"""linux_provider.py - Linux capabilities for SecuDrive (stdlib-only core).

Everything behind the ``PlatformProvider`` contract needed to run the *same*
core on Linux: local/removable volume enumeration via ``/proc/mounts`` (no
psutil dependency), XDG content directories, login autostart via a
``~/.config/autostart`` .desktop entry, root detection, a per-sample process
CPU meter (``/proc/self/stat``), an optional real-time file-watch backend
(pyinotify) and an optional USB hotplug listener (pyudev).

Optional dependencies degrade gracefully:
    * no ``pyinotify`` -> real-time watch reports unavailable (polling only)
    * no ``pyudev``    -> USB detection falls back to volume polling, which the
      watcher already implements against the same contract.

Hidden-file convention on Linux is dotfiles (``.hidden`` / leading-dot names),
not attribute bits - so ``file_attributes_supported()`` stays ``False`` and
``recovery.reveal_hidden`` simply has nothing to do here.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from .base import PlatformProvider

# ---------------------------------------------------------------------------
# Optional backends (kept import-safe so this module loads everywhere).
# ---------------------------------------------------------------------------
try:
    import pyinotify

    _HAVE_PYINOTIFY = True
    _ProcessEvent = pyinotify.ProcessEvent
except ImportError:  # pragma: no cover - environment dependent
    pyinotify = None
    _HAVE_PYINOTIFY = False
    _ProcessEvent = object

try:
    import pyudev

    _HAVE_PYUDEV = True
except ImportError:  # pragma: no cover - environment dependent
    pyudev = None
    _HAVE_PYUDEV = False


#: Match the action codes used by ``realtime_monitor`` (kept local to avoid an
#: import cycle; values are the historical win32 FILE_ACTION_* meanings).
FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5

#: Pseudo filesystems that are never user storage (mount(8) list, trimmed).
_PSEUDO_FS = frozenset({
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs",
    "debugfs", "tracefs", "pstore", "mqueue", "hugetlbfs", "configfs",
    "binfmt_misc", "autofs", "rpc_pipefs", "fusectl", "efivarfs", "selinuxfs",
})

#: Independent remover of the trailing partition counter (handles nvme names).
_RE_PART = re.compile(r"^(.*?)(?:p?\d+)$")

#: Auto-mount roots that imply "removable media" for the watcher semantics.
_REMOVABLE_ROOTS = ("/media/", "/run/media/", "/mnt/")

_RT_MASK = (
    0x00000100  # IN_CREATE
    | 0x00000200  # IN_DELETE
    | 0x00000002  # IN_MODIFY
    | 0x00000008  # IN_CLOSE_WRITE
    | 0x00000004  # IN_ATTRIB
    | 0x00000040  # IN_MOVED_FROM
    | 0x00000080  # IN_MOVED_TO
)
_IN_CREATE = 0x00000100
_IN_DELETE = 0x00000200
_IN_MODIFY = 0x00000002
_IN_CLOSE_WRITE = 0x00000008
_IN_MOVED_FROM = 0x00000040
_IN_MOVED_TO = 0x00000080


class LinuxUSBListener(threading.Thread):
    """pyudev block-subsystem pump; fires ``callback()`` on add/remove.

    Guards: if pyudev is missing or the netlink monitor cannot start, the
    thread exits quickly and the watcher falls back to polling.
    """

    def __init__(self, callback: Callable[[], None],
                 stop_event: Optional[threading.Event] = None) -> None:
        super().__init__(daemon=True, name="LinuxUSBListener")
        self.callback = callback
        self.stop_event = stop_event or threading.Event()
        self._registered = False
        self._fd: Optional[int] = None

    def is_available(self) -> bool:
        return self._registered

    def _stop_requested(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    def run(self) -> None:
        import select as _select
        if not _HAVE_PYUDEV:
            return
        try:
            ctx = pyudev.Context()
            mon = pyudev.Monitor.from_netlink(ctx)
            mon.filter_by(subsystem="block")
            mon.start()
            self._fd = mon.fileno()
            self._registered = True
        except Exception:
            self._registered = False
            return
        while not self._stop_requested():
            try:
                ready, _, _ = _select.select([self._fd], [], [], 0.5)
                if not ready:
                    continue
                while True:
                    dev = mon.poll(timeout=0)
                    if dev is None:
                        break
                    if getattr(dev, "action", "") in ("add", "remove"):
                        self.callback()
                        break  # give the main loop some cycles between bursts
            except OSError:
                break
            except Exception:
                continue


class _RTEventHandler(_ProcessEvent):  # noqa: F821  (guarded import)
    """Bridge pyinotify events into the RealtimeMonitor callback contract."""

    def __init__(self, session: "LinuxWatchSession") -> None:
        self.session = session

    def _post(self, event, action: int) -> None:
        root = self.session.root
        abs_path = getattr(event, "pathname", "") or ""
        if not abs_path:
            return
        try:
            stripped = abs_path.rstrip(os.sep)
            if not stripped or stripped == root.rstrip(os.sep):
                return  # the watched root itself, not a child
            rel = abs_path[len(root):].lstrip(os.sep)
        except Exception:
            rel = os.path.relpath(abs_path, root)
        if not rel:
            return
        self.session.monitor._on_watch_event(action, rel, root)

    def process_default(self, event) -> None:
        try:
            if event.mask & _IN_CREATE:
                self._post(event, FILE_ACTION_ADDED)
            elif event.mask & _IN_DELETE:
                self._post(event, FILE_ACTION_REMOVED)
            elif event.mask & _IN_MOVED_FROM:
                self._post(event, FILE_ACTION_RENAMED_OLD_NAME)
            elif event.mask & _IN_MOVED_TO:
                self._post(event, FILE_ACTION_RENAMED_NEW_NAME)
            elif event.mask & _IN_CLOSE_WRITE:
                self._post(event, FILE_ACTION_MODIFIED)
            elif event.mask & _IN_MODIFY:
                self._post(event, FILE_ACTION_MODIFIED)
        except Exception:
            # never let a userland parse error kill the pyinotify loop
            return


class LinuxWatchSession:
    """One pyinotify watch over a drive root (daemon notifier thread).

    Mirrors ``WindowsWatchSession``'s lifecycle so ``RealtimeMonitor`` treats
    both identically: ``start()`` / ``stop()`` / ``is_alive()`` plus the
    monitor ``_session_ready`` / ``_session_failed`` / ``_session_ended``
    callbacks.
    """

    def __init__(self, monitor, root: str) -> None:
        self.monitor = monitor
        drive = str(root).rstrip("\\").rstrip("/") or "/"
        self.root = drive + "/"
        self.error: Optional[str] = None
        self._wm: Optional["pyinotify.WatchManager"] = None
        self._notifier = None
        self._alive = False
        self._ready_fired = False

    def start(self) -> "LinuxWatchSession":
        if self._alive:
            return self
        try:
            self._wm = pyinotify.WatchManager()
            self._wm.add_watch(self.root, _RT_MASK, rec=True, auto_add=True)
            handler = _RTEventHandler(self)
            self._notifier = pyinotify.ThreadedNotifier(
                self._wm, default_proc=handler)
            self._notifier.start()
            self._alive = True
            self.error = None
            self._ready_fired = True
            self.monitor._session_ready(self)
        except Exception as exc:
            self.error = str(exc)
            self._alive = False
            self.monitor._session_failed(self, self.error)
        return self

    def stop(self) -> None:
        if not self._alive:
            return
        try:
            self._notifier.stop()
        except Exception:
            pass
        self._alive = False
        self.monitor._session_ended(self)

    def is_alive(self) -> bool:
        return self._alive


class LinuxProvider(PlatformProvider):
    """Linux provider: /proc/mounts volumes, XDG dirs, dotfile convention."""

    def __init__(self) -> None:
        super().__init__()
        # Raw per-sample CPU state (clock ticks + wall clock), mirroring the
        # Windows provider's delta approach.
        self._cpu_last_ticks = 0.0
        self._cpu_last_wall = time.monotonic()

    def system(self) -> str:
        return "Linux"

    # ------------------------------------------------------------ mounts
    def _mount_entries(self) -> List[tuple]:
        """[(device, mountpoint, fstype)] from /proc/mounts (or /etc/mtab)."""
        paths = ["/proc/mounts", "/etc/mtab"]
        for source in paths:
            try:
                entries: List[tuple] = []
                with open(source, "r", encoding="utf-8",
                          errors="replace") as fh:
                    for line in fh.read().splitlines():
                        parts = line.split()
                        if len(parts) >= 3:
                            entries.append((parts[0], parts[1], parts[2]))
                if entries:
                    return entries
            except OSError:
                continue
        return []

    def _block_mounts(self, removable: bool):
        """Mounted block devices, optionally restricted to auto-mount roots."""
        root_device = self._system_device()
        root_disk = _RE_PART.sub(r"\1", root_device) if root_device else ""
        result: List[tuple] = []
        for dev, mnt, fstype in self._mount_entries():
            if fstype in _PSEUDO_FS:
                continue
            if not dev.startswith("/dev/"):
                continue
            low = mnt.rstrip("/")
            if removable and not low.startswith(_REMOVABLE_ROOTS):
                continue
            result.append((dev, mnt, fstype, root_disk))
        return result

    def _system_device(self) -> str:
        for dev, mnt, _fstype in self._mount_entries():
            if mnt == "/":
                return dev
        return ""

    def _is_root_disk(self, dev: str, root_disk: str) -> bool:
        if not root_disk:
            return False
        return (_RE_PART.sub(r"\1", dev) == root_disk)

    # ---------------------------------------------------- drive discovery (1)
    def all_letters(self) -> List[str]:
        """Mount identifiers (POSIX): every current mount point, sorted."""
        return sorted({mnt for _dev, mnt, _fstype in self._mount_entries()})

    def logical_drive_strings(self) -> List[str]:
        return self.all_letters()

    def fixed_drive_paths(self) -> List[str]:
        """Local block volumes (incl. /); pseudo and auto-mount removed."""
        return sorted(mnt for dev, mnt, _ft, rdisk in self._block_mounts(False)
                      if not mnt.rstrip("/").startswith(_REMOVABLE_ROOTS))

    def removable_drive_paths(self) -> List[str]:
        """Auto-mount roots under /media, /run/media and /mnt (removable)."""
        return sorted(mnt for _dev, mnt, _ft, _r in self._block_mounts(True))

    def list_removable_drives(self) -> List[str]:
        """Mount identifiers considered removable today."""
        return self.removable_drive_paths()

    def list_external_drives(self) -> List[str]:
        """External storage mount identifiers: non-system block volumes
        (Fixed external disks AND removable media), boot disk excluded.  This
        is what the watcher + Drive Doctor call "external media"."""
        return [mnt for dev, mnt, _ft, rdisk in self._block_mounts(False)
                if not self._is_root_disk(dev, rdisk)]

    def system_drive_letter(self) -> str:
        """POSIX: the root mountpoint ``/`` (no drive letters exist here).
        ``volume_root`` expands it into ``/`` so base scan-target helpers work
        unchanged."""
        return "/"

    def external_drive_paths(self) -> List[str]:
        return [mnt for mnt in self.list_external_drives()
                if os.path.isdir(mnt)]

    def drive_kind(self, path: str) -> str:
        """Mirror the Windows labels: ``External SSD/HDD (Fixed)``,
        ``USB Flash (Removable)`` or ``Unknown``."""
        norm = str(path).rstrip("\\/") or "/"
        if norm in {m.rstrip("/") for m in self.removable_drive_paths()}:
            return "USB Flash (Removable)"
        if norm in {m.rstrip("/") for m in self.fixed_drive_paths()}:
            return "External SSD/HDD (Fixed)"
        return "Unknown"

    def drive_display(self, path: str) -> str:
        return f"{path} - {self.drive_kind(path)}"

    def is_valid_drive_root(self, text: str) -> bool:
        if not text or not str(text).strip():
            return False
        cleaned = str(text).strip().strip('"')
        if not os.path.isdir(cleaned):
            return False
        if cleaned.rstrip("/") in {m.rstrip("/")
                                   for m in self.logical_drive_strings()}:
            return True
        return os.path.ismount(cleaned)

    def drive_volume_label(self, path: str) -> Optional[str]:
        """Best-effort: volume label via blkid needs root; fall back to the
        label-ish mountpoint basename on auto-mounts ('' otherwise)."""
        norm = str(path).rstrip("\\/")
        low = norm.rstrip("/")
        if not low or low == "/":
            return ""
        if low.startswith(_REMOVABLE_ROOTS):
            return os.path.basename(low)
        return ""

    # --------------------------------------------------------------- privilege
    def is_admin(self) -> bool:
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid and geteuid() == 0)

    # --------------------------------------------------- file attributes (2)
    # HIDDEN/SYSTEM attribute bits are a Windows concept; Linux uses dotfiles.
    # ``file_attributes_supported`` therefore stays False (base default) and
    # ``reveal_hidden`` is a no-op here.

    # ------------------------------------------ registry autostarts (3)
    # No registry on Linux - ``sanitize_registry_autostarts`` inherits the
    # base no-op report.

    # ------------------------------------------------------ hotplug (4)
    def usb_listener_available(self) -> bool:
        return _HAVE_PYUDEV

    def usb_backend_name(self) -> str:
        return ("udev-device-notification" if _HAVE_PYUDEV
                else "polling-removable-volumes")

    def create_usb_listener(self, callback: Callable[[], None],
                            stop_event=None) -> Optional[LinuxUSBListener]:
        if not _HAVE_PYUDEV:
            return None
        return LinuxUSBListener(callback=callback, stop_event=stop_event)

    # ------------------------------------------ security-center (5)
    # Base defaults say "not implemented"; the status report already covers
    # non-Windows platforms.  No override needed.

    # ------------------------------------------- real-time watch (6)
    def rt_watch_available(self) -> bool:
        return _HAVE_PYINOTIFY

    def create_watch_session(self, monitor, root: str) -> "LinuxWatchSession":
        if not _HAVE_PYINOTIFY:
            raise NotImplementedError(
                "pyinotify is required for real-time file watching on Linux")
        return LinuxWatchSession(monitor, root)

    def sample_cpu_percent(self) -> float:
        """Raw (unsmoothed) self-process CPU% since the previous call, 0.0 on
        error.  Reads utime+stime (clock ticks) from ``/proc/self/stat`` so the
        throttle meter behaves like the Windows GetProcessTimes path."""
        try:
            stat_path = "/proc/self/stat"
            with open(stat_path, "r", encoding="ascii", errors="replace") as fh:
                raw = fh.read()
            end = raw.rfind(")")
            if end < 0:
                raise OSError("malformed stat")
            fields = raw[end + 1:].split()
            # fields[0] == field 3 (state); utime is field 14, stime field 15.
            utime = float(fields[11]) if len(fields) >= 14 else 0.0
            stime = float(fields[12]) if len(fields) >= 15 else 0.0
            ticks = utime + stime
            hz = float(os.sysconf("SC_CLK_TCK")) if hasattr(os, "sysconf") else 100.0
            if not hz:
                hz = 100.0
            now_wall = time.monotonic()
            delta_wall = max(now_wall - self._cpu_last_wall, 0.001)
            delta_ticks = ticks - self._cpu_last_ticks
            self._cpu_last_ticks = ticks
            self._cpu_last_wall = now_wall
            return (delta_ticks / hz / delta_wall) * 100.0
        except Exception:
            return 0.0

    # ------------------------------------------------------- autostart (7)
    @property
    def _autostart_dir(self) -> Path:
        return Path(os.environ.get("XDG_CONFIG_HOME")
                    or os.path.join(Path("~").expanduser(), ".config")
                    , "autostart")

    def _autostart_file(self) -> Path:
        return self._autostart_dir / "secudrive.desktop"

    def autostart_enabled(self) -> bool:
        f = self._autostart_file()
        if not f.is_file():
            return False
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        for line in text.splitlines():
            low = line.strip().lower()
            if low.startswith("hidden=true") or low.startswith("x-hidden=true"):
                return False
            if low.startswith("exec="):
                return True
        return False

    def set_autostart(self, enabled: bool) -> bool:
        f = self._autostart_file()
        if enabled:
            try:
                self._autostart_dir.mkdir(parents=True, exist_ok=True)
                f.write_text(
                    "[Desktop Entry]\n"
                    "Type=Application\n"
                    "Name=SecuDrive\n"
                    "Comment=External drive protection\n"
                    f"Exec={Path(sys.executable).resolve()} -m secudrive.gui\n"
                    "Terminal=false\n"
                    "X-GNOME-Autostart-enabled=true\n",
                    encoding="utf-8")
                return True
            except OSError:
                return False
        try:
            f.unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    # ---------------------------------------- platform-independent helpers
    def user_content_paths(self) -> List[str]:
        """XDG user dirs (fall back to the base Desktop/Documents... probe)."""
        home = Path("~").expanduser()
        xdg = home / ".config" / "user-dirs.dirs"
        mapping = {"DESKTOP": "Desktop", "DOCUMENTS": "Documents",
                   "DOWNLOAD": "Downloads", "PICTURES": "Pictures"}
        found: List[Path] = []
        if xdg.is_file():
            try:
                contrib = {}
                for line in xdg.read_text(encoding="utf-8",
                                          errors="replace").splitlines():
                    line = line.strip()
                    if not line.startswith("XDG_") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key[len("XDG_"):-len("_DIR")]
                    val = val.strip().strip('"')
                    if val:
                        val = os.path.expandvars(val)
                        contrib[key] = Path(val).expanduser()
                order = ["DESKTOP", "DOCUMENTS", "DOWNLOAD", "PICTURES"]
                for key in order:
                    path = contrib.get(key)
                    if path and path.is_dir():
                        found.append(path)
            except OSError:
                found = []
        if not found:
            for name in mapping.values():
                p = home / name
                if p.is_dir():
                    found.append(p)
            if not found:
                found = [home]
        seen = set()
        out = []
        for p in found:
            s = str(p).rstrip("/")
            if s not in seen:
                seen.add(s)
                out.append(str(p))
        return out