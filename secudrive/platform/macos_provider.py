"""macos_provider.py - macOS capabilities for SecuDrive (stdlib-first core).

Everything behind the ``PlatformProvider`` contract needed to run the *same*
core on macOS: local/removable volume enumeration via ``/Volumes`` + ``/``
(classic stdlib mounts; ``diskutil`` used only as a best-effort refinement for
removable-vs-fixed labels), login autostart via a LaunchAgent plist
(``~/Library/LaunchAgents/com.secudrive.plist``), root detection, a per-sample
process CPU meter (``resource.getrusage``), a real-time file-watch backend via
FSEvents (guarded optional dependency ``watchdog``) and file-attribute flags
via ``chflags`` (``UF_HIDDEN`` for "hidden", ``UF_IMMUTABLE`` for "protected").

Optional dependencies degrade gracefully:
    * no ``watchdog`` -> real-time watch reports unavailable (polling only)
    * diskutil absent/fails -> volumes classify as fixed; labels fall back to
      the mountpoint basename (identical behaviour to a box without the tools)

USB hotplug has no udev/netlink equivalent here, so ``usb_listener_available``
is ``False`` and the watcher uses its built-in volume polling - the same
polling path it already uses everywhere else.
"""
from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .base import PlatformProvider

# ---------------------------------------------------------------------------
# Optional backends (kept import-safe so this module loads everywhere).
# ---------------------------------------------------------------------------
try:
    import watchdog.events
    import watchdog.observers

    _HAVE_WATCHDOG = True
    _FileSystemEventHandler = watchdog.events.FileSystemEventHandler
except ImportError:  # pragma: no cover - environment dependent
    _HAVE_WATCHDOG = False
    _FileSystemEventHandler = object

#: Match the action codes used by ``realtime_monitor`` (kept local to avoid an
#: import cycle; values are the historical win32 FILE_ACTION_* meanings).
FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5

#: macOS file flags exposed through ``os.stat().st_flags`` / ``os.chflags()``.
#: ``stat.UF_HIDDEN`` etc. are Darwin-only, so fall back to the documented
#: numeric values (sys/stat.h) on other platforms.
try:
    from stat import SF_ARCHIVED, UF_HIDDEN, UF_IMMUTABLE  # noqa: F401
except ImportError:  # pragma: no cover - non-Darwin stat module
    UF_HIDDEN = 0x00008000      # hidden in the Finder (owner-settable)
    UF_IMMUTABLE = 0x00000002   # user immutable = read-only / "protected"
    SF_ARCHIVED = 0x00010000    # archived marker (informational)

#: Property-list keys (older PascalCase vs newer macOS camelCase) that mark a
#: volume as physically removable media (USB flash, SD, ejectable disks).
_REMOVABLE_KEYS = (
    "RemovableMedia", "RemovableMediaOrExternal", "Ejectable",
    "removableMedia", "removableMediaOrExternal", "ejectable",
)
_LABEL_KEYS = ("VolumeName", "VolumeNameOrNull", "FilesystemName")


class _MacFSEventHandler(_FileSystemEventHandler):  # noqa: F821
    """Bridge watchdog (FSEvents) events into the RealtimeMonitor contract."""

    def __init__(self, session: "MacOSWatchSession") -> None:
        super().__init__()
        self.session = session

    def _post(self, abs_path: str, action: int) -> None:
        root = self.session.root
        if not abs_path:
            return
        try:
            stripped = abs_path.rstrip(os.sep)
            if not stripped or stripped == root.rstrip(os.sep):
                return  # the watched root itself, not a child
            rel = abs_path[len(root):].lstrip(os.sep)
        except Exception:
            return
        if not rel:
            return
        self.session.monitor._on_watch_event(action, rel, root)

    def on_any_event(self, event) -> None:
        try:
            kind = getattr(event, "event_type", "")
            src = getattr(event, "src_path", "") or ""
            if kind == "created":
                self._post(src, FILE_ACTION_ADDED)
            elif kind == "deleted":
                self._post(src, FILE_ACTION_REMOVED)
            elif kind == "modified":
                self._post(src, FILE_ACTION_MODIFIED)
            elif kind == "moved":
                self._post(src, FILE_ACTION_RENAMED_OLD_NAME)
                self._post(getattr(event, "dest_path", "") or "",
                           FILE_ACTION_RENAMED_NEW_NAME)
        except Exception:
            # never let a userland parse error kill the watchdog loop
            return


class MacOSWatchSession:
    """One FSEvents watch over a drive root (daemon observer thread).

    Mirrors ``WindowsWatchSession``'s lifecycle so ``RealtimeMonitor`` treats
    all providers identically: ``start()`` / ``stop()`` / ``is_alive()`` plus
    the monitor ``_session_ready`` / ``_session_failed`` / ``_session_ended``
    callbacks.
    """

    def __init__(self, monitor, root: str) -> None:
        self.monitor = monitor
        drive = str(root).rstrip("\\").rstrip("/") or "/"
        self.root = drive + "/"
        self.error: Optional[str] = None
        self._observer = None
        self._alive = False
        self._ready_fired = False

    def start(self) -> "MacOSWatchSession":
        if self._alive:
            return self
        if not _HAVE_WATCHDOG:
            self.error = "watchdog is not installed (FSEvents backend missing)"
            self.monitor._session_failed(self, self.error)
            return self
        try:
            handler = _MacFSEventHandler(self)
            self._observer = watchdog.observers.Observer()
            self._observer.schedule(handler, self.root, recursive=True)
            self._observer.start()
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
            self._observer.stop()
            self._observer.join(timeout=3.0)
        except Exception:
            pass
        self._alive = False
        self.monitor._session_ended(self)

    def is_alive(self) -> bool:
        return self._alive


class MacOSProvider(PlatformProvider):
    """macOS provider: /Volumes + ``/`` volumes, LaunchAgent plist, chflags."""

    #: Attribute constants keep the Windows bit values so the shared recovery
    #: code interprets them identically cross-platform.
    FILE_ATTRIBUTE_READONLY = 0x00000001
    FILE_ATTRIBUTE_HIDDEN = 0x00000002
    FILE_ATTRIBUTE_SYSTEM = 0x00000004
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

    _LAUNCH_AGENT_LABEL = "com.secudrive"

    def __init__(self) -> None:
        super().__init__()
        # Raw per-sample CPU state (seconds + wall clock), mirroring the
        # Linux provider's delta approach.
        self._cpu_last_used = 0.0
        self._cpu_last_wall = time.monotonic()
        # Drive-classification cache, keyed by the current mount-point set.
        self._drv_mounts: Optional[tuple] = None
        self._drv_table: Dict[str, dict] = {}

    def system(self) -> str:
        return "macOS"

    # ------------------------------------------------------------ volumes
    def _all_mounts(self) -> List[str]:
        """Mount points the process can scan: ``/`` plus real mounts in
        ``/Volumes`` (stale non-mount dirs are never included)."""
        mounts: List[str] = ["/"]
        try:
            entries = os.listdir("/Volumes")
        except OSError:
            return mounts
        for name in sorted(entries):
            if name.startswith("."):
                continue
            path = os.path.join("/Volumes", name)
            if os.path.ismount(path):
                mounts.append(path)
        return mounts

    def _diskutil(self, *args: str) -> Optional[dict]:
        """Best-effort ``diskutil … -plist`` -> dict (None on any failure)."""
        try:
            proc = subprocess.run(
                ["diskutil", *args], capture_output=True,
                timeout=15, check=False)
            if proc.returncode != 0:
                return None
            data = plistlib.loads(proc.stdout)
        except Exception:
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _plist_is_removable(plist: dict) -> bool:
        return any(bool(plist.get(key)) for key in _REMOVABLE_KEYS)

    @staticmethod
    def _plist_label(plist: dict) -> str:
        for key in _LABEL_KEYS:
            val = plist.get(key)
            if isinstance(val, str) and val:
                return val
        return ""

    def _drive_table(self) -> Dict[str, dict]:
        """mountpoint -> {"kind": "fixed"|"removable", "label": str}.

        Cached and rebuilt whenever the mount-point set changes, so a USB
        plug/unplug is reflected on the next call without hammering diskutil.
        """
        mounts = tuple(self._all_mounts())
        if mounts == self._drv_mounts:
            return self._drv_table
        table: Dict[str, dict] = {}
        for mp in mounts:
            row = {"kind": "fixed", "label": ""}
            plist = self._diskutil("info", mp, "-plist")
            if plist:
                if self._plist_is_removable(plist):
                    row["kind"] = "removable"
                row["label"] = self._plist_label(plist)
            table[mp] = row
        self._drv_mounts = mounts
        self._drv_table = table
        return table

    # ---------------------------------------------------- drive discovery (1)
    def all_letters(self) -> List[str]:
        """Mount identifiers (POSIX): every current mount point, sorted."""
        return sorted(self._drive_table())

    def logical_drive_strings(self) -> List[str]:
        return self.all_letters()

    def fixed_drive_paths(self) -> List[str]:
        return sorted(mp for mp, row in self._drive_table().items()
                      if row["kind"] == "fixed")

    def removable_drive_paths(self) -> List[str]:
        return sorted(mp for mp, row in self._drive_table().items()
                      if row["kind"] == "removable")

    def list_removable_drives(self) -> List[str]:
        """Mount identifiers considered removable today."""
        return self.removable_drive_paths()

    def list_external_drives(self) -> List[str]:
        """External storage mount identifiers: every non-/ volume (Fixed AND
        removable), boot volume excluded.  This is what the watcher + Drive
        Doctor call "external media"."""
        return [mp for mp in self._drive_table()
                if mp.rstrip("/") != "/"]

    def system_drive_letter(self) -> str:
        """POSIX: the root mountpoint ``/`` (no drive letters exist here).
        ``volume_root`` expands it into ``/`` so base scan-target helpers work
        unchanged."""
        return "/"

    def external_drive_paths(self) -> List[str]:
        return [mp for mp in self.list_external_drives()
                if os.path.isdir(mp)]

    def drive_kind(self, path: str) -> str:
        """Mirror the Windows labels: ``External SSD/HDD (Fixed)``,
        ``USB Flash (Removable)`` or ``Unknown``."""
        norm = str(path).rstrip("\\/") or "/"
        row = self._drive_table().get(norm)
        if row is None:
            return "Unknown"
        return ("USB Flash (Removable)" if row["kind"] == "removable"
                else "External SSD/HDD (Fixed)")

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
        """Best-effort: diskutil VolumeName, else the mountpoint basename."""
        norm = str(path).rstrip("\\/") or "/"
        row = self._drive_table().get(norm)
        if row is not None and row["label"]:
            return row["label"]
        return "" if norm == "/" else os.path.basename(norm)

    # --------------------------------------------------------------- privilege
    def is_admin(self) -> bool:
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid and geteuid() == 0)

    # --------------------------------------------------- file attributes (2)
    # macOS has real flag semantics: Finder-hidden via UF_HIDDEN, "protected"
    # (read-only / immutable) via UF_IMMUTABLE.  ``os.chflags`` is Darwin-only,
    # so this degrades to the base OSError contract elsewhere.
    def file_attributes_supported(self) -> bool:
        return hasattr(os, "chflags")

    #: our bit -> macOS chflag pair (SYSTEM has no sane chflag analogue).
    _ATTR_FLAG_PAIRS = (
        (FILE_ATTRIBUTE_HIDDEN, UF_HIDDEN),
        (FILE_ATTRIBUTE_READONLY, UF_IMMUTABLE),
        (FILE_ATTRIBUTE_ARCHIVE, SF_ARCHIVED),
    )

    def get_file_attrs(self, path: str) -> int:
        if not hasattr(os, "chflags"):
            raise OSError("file flags are not supported on this platform")
        st_flags = os.stat(path).st_flags
        attrs = 0
        for our_bit, mac_flag in self._ATTR_FLAG_PAIRS:
            if st_flags & mac_flag:
                attrs |= our_bit
        return attrs

    def set_file_attrs(self, path: str, attrs: int) -> None:
        if not hasattr(os, "chflags"):
            raise OSError("file flags are not supported on this platform")
        cur = os.stat(path).st_flags
        new = cur
        for our_bit, mac_flag in self._ATTR_FLAG_PAIRS:
            if attrs & our_bit:
                new |= mac_flag
            else:
                new &= ~mac_flag
        os.chflags(path, new)

    # ------------------------------------------ registry autostarts (3)
    # No registry on macOS - ``sanitize_registry_autostarts`` inherits the
    # base no-op report.

    # ------------------------------------------------------ hotplug (4)
    def usb_listener_available(self) -> bool:
        """No udev/netlink on macOS; the watcher polls /Volumes instead."""
        return False

    def usb_backend_name(self) -> str:
        return "polling-removable-volumes"

    # ------------------------------------------ security-center (5)
    # Base defaults say "not implemented"; the status report already covers
    # non-Windows platforms.  No override needed.

    # ------------------------------------------- real-time watch (6)
    def rt_watch_available(self) -> bool:
        return _HAVE_WATCHDOG

    def create_watch_session(self, monitor, root: str) -> "MacOSWatchSession":
        if not _HAVE_WATCHDOG:
            raise NotImplementedError(
                "watchdog (FSEvents) is required for real-time file watching "
                "on macOS")
        return MacOSWatchSession(monitor, root)

    def sample_cpu_percent(self) -> float:
        """Raw (unsmoothed) self-process CPU% since the previous call, 0.0 on
        error.  Reads utime+stime from ``resource.getrusage`` so the throttle
        meter behaves like the Windows/Linux paths."""
        try:
            import resource
            ru = resource.getrusage(resource.RUSAGE_SELF)
            used = ru.ru_utime + ru.ru_stime
            now_wall = time.monotonic()
            delta_wall = max(now_wall - self._cpu_last_wall, 0.001)
            delta_used = used - self._cpu_last_used
            self._cpu_last_used = used
            self._cpu_last_wall = now_wall
            return (delta_used / delta_wall) * 100.0
        except Exception:
            return 0.0

    # ------------------------------------------------------- autostart (7)
    @property
    def _launch_agents_dir(self) -> Path:
        return Path("~/Library/LaunchAgents").expanduser()

    def _autostart_file(self) -> Path:
        return self._launch_agents_dir / "com.secudrive.plist"

    @staticmethod
    def _agent_plist(executable: str) -> dict:
        return {
            "Label": MacOSProvider._LAUNCH_AGENT_LABEL,
            "ProgramArguments": [executable, "-m", "secudrive.gui"],
            "RunAtLoad": True,
        }

    def autostart_enabled(self) -> bool:
        f = self._autostart_file()
        if not f.is_file():
            return False
        try:
            with f.open("rb") as fh:
                data = plistlib.load(fh)
        except Exception:
            return False
        return data.get("Label") == self._LAUNCH_AGENT_LABEL

    def set_autostart(self, enabled: bool) -> bool:
        f = self._autostart_file()
        if enabled:
            try:
                self._launch_agents_dir.mkdir(parents=True, exist_ok=True)
                plist = self._agent_plist(
                    Path(sys.executable).resolve().as_posix())
                f.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML))
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
        """macOS keeps its user dirs English-named on disk (localised names
        are only the Finder's display layer), so probe the standard set
        directly - plus Music/Movies, which the base probe omits."""
        home = Path("~").expanduser()
        found: List[Path] = []
        for sub in ("Desktop", "Documents", "Downloads", "Pictures",
                    "Movies", "Music"):
            p = home / sub
            if p.is_dir():
                found.append(p)
        if not found:
            found = [home]
        return [str(p) for p in found]