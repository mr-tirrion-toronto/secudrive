"""windows_provider.py - Windows implementation of PlatformProvider.

Bodies are the pre-refactor module functions moved verbatim from
systemutils / recovery / immunizer / win_usb / wsc_register /
realtime_monitor - only the calling indirection changed.

Growth is incremental: each refactor step lands its methods here, drives the
mobile module through the provider, then runs the regression gate.
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
import time
import uuid as _uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .base import PlatformProvider
from .. import crashguard
from ..logging_utils import get_logger

logger = get_logger("platform-windows")

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3

# -- drive discovery (moved from secudrive/systemutils.py)
_GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
_GetVolumeInformationW = ctypes.windll.kernel32.GetVolumeInformationW


def _drive_type(letter: str) -> int:
    try:
        return _GetDriveTypeW(f"{letter}:\\")
    except Exception:
        return 0


# -- file attributes (moved from secudrive/recovery.py)
_GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
_SetFileAttributesW = ctypes.windll.kernel32.SetFileAttributesW

FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_ARCHIVE = 0x00000020
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


# -- registry autostart pruning (moved from secudrive/immunizer.py)
_AUTOSTART_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
]

# -- USB attach listener (moved from secudrive/win_usb.py)
try:
    import win32api
    import win32con
    import win32gui
    import pywintypes

    _HAVE_PYWIN32 = True
except ImportError:  # pragma: no cover - environment dependent
    win32api = win32con = win32gui = pywintypes = None
    _HAVE_PYWIN32 = False

# Windows messages / broadcast constants
WM_DEVICECHANGE = 0x0219
DBT_DEVICEARRIVAL = 0x8000          # system detected a new device
DBT_DEVICEREMOVECOMPLETE = 0x8004   # device gracefully removed
GUID_DEVINTERFACE_USB_DEVICE = "{A5DCBF10-6530-11D2-901F-00C04FB951ED}"
GUID_DEVINTERFACE_VOLUME = "{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}"

# -- real-time watch (moved from secudrive/realtime_monitor.py)
FILE_LIST_DIRECTORY = 0x0001
ERROR_NOTIFY_ENUM_DIR = 1023


class WindowsWatchSession:
    """One ``ReadDirectoryChangesW`` async loop over a single drive root.

    Moved from ``secudrive/realtime_monitor.py``; ``monitor`` must expose the
    ``RealtimeMonitor`` callback contract (``_on_watch_event`` / ``_on_rt_event``
    / ``_session_ready`` / ``_session_failed`` / ``_session_ended`` and the
    ``buffer_bytes`` attribute).
    """

    def __init__(self, monitor, root: str) -> None:
        self.monitor = monitor
        drive = str(root).rstrip("\\").rstrip("/")
        self.root = drive + os.sep
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._handle = None
        self._overflow_count = 0
        self.error: Optional[str] = None

    def start(self) -> "WindowsWatchSession":
        self._stop.clear()
        name = f"RTWatch-{self.root[0]}:{os.getpid()}"[-12:]
        self._thread = threading.Thread(
            target=self._thread_body, name=name, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=4)
        self._thread = None

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # --- thread body ---------------------------------------------------------
    def _thread_body(self) -> None:
        try:
            self._loop()
        except Exception:
            crashguard.report_exception(
                f"rt-watch:{self.root}", sys.exc_info()[1], sys.exc_info()[2])
        finally:
            self._discard_handle(cancel=True)
            self.monitor._session_ended(self)

    def _open(self) -> bool:
        import win32con, win32file
        try:
            self._handle = win32file.CreateFile(
                self.root, FILE_LIST_DIRECTORY,
                (win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE
                 | win32con.FILE_SHARE_DELETE),
                None, win32con.OPEN_EXISTING,
                (win32con.FILE_FLAG_BACKUP_SEMANTICS
                 | win32con.FILE_FLAG_OVERLAPPED), None)
            self._overflow_count = 0
            self.error = None
            return True
        except Exception as exc:
            self.error = str(exc)
            return False

    def _loop(self) -> None:
        import win32con, win32event, win32file, pywintypes

        filters = (win32con.FILE_NOTIFY_CHANGE_FILE_NAME
                   | win32con.FILE_NOTIFY_CHANGE_DIR_NAME
                   | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE
                   | win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES)
        buf = win32file.AllocateReadBuffer(self.monitor.buffer_bytes)
        evt = win32event.CreateEvent(None, 0, 0, None)  # auto-reset
        ov = pywintypes.OVERLAPPED()
        ov.hEvent = evt
        while not self._stop.is_set():
            if self._handle is None:
                if not self._open():
                    self.monitor._session_failed(self, self.error)
                    self._stop.wait(2.0)
                    continue
                self.monitor._session_ready(self)
            armed = False
            while not self._stop.is_set() and self._handle is not None:
                if not armed:
                    try:
                        win32file.ReadDirectoryChangesW(
                            self._handle, buf, True, filters, ov)
                        armed = True
                    except Exception as exc:
                        ov = None
                        if getattr(exc, "winerror", None) == ERROR_NOTIFY_ENUM_DIR:
                            self._overflow_count += 1
                            self.monitor._on_rt_event(
                                f"RT buffer overflow #{self._overflow_count}"
                                f" on {self.root} (re-opening)", "event")
                            self._discard_handle()
                            break
                        self.monitor._session_failed(self, str(exc))
                        self._discard_handle()
                        break
                try:
                    rc = win32event.WaitForSingleObject(evt, 250)
                except Exception:
                    self._discard_handle()
                    break
                if rc == win32event.WAIT_OBJECT_0:
                    armed = False
                    try:
                        nbytes = win32file.GetOverlappedResult(
                            self._handle, ov, True)
                    except Exception:
                        self._discard_handle()
                        break
                    if not nbytes:
                        self._discard_handle()
                        break
                    try:
                        for action, rel in win32file.FILE_NOTIFY_INFORMATION(
                                buf, nbytes):
                            self.monitor._on_watch_event(
                                int(action), str(rel), self.root)
                    except Exception:
                        crashguard.report_exception(
                            "rt-parse", sys.exc_info()[1], sys.exc_info()[2])
        # Thread owns the handle for its whole lifetime: it always cancels
        # pending IO and closes ITS OWN handle so stop() never touches a
        # handle from another thread (that would hang on a pending op).
        if self._handle is not None:
            self._discard_handle(cancel=True)
        try:
            win32event.CloseHandle(evt)
        except Exception:
            pass

    def _discard_handle(self, cancel: bool = False) -> None:
        """Must be called from the watch thread only."""
        if self._handle is None:
            return
        try:
            if cancel:
                try:
                    win32file.CancelIo(self._handle)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            self._handle.Close()
        except Exception:
            pass
        self._handle = None


class USBAttachListener(threading.Thread):
    """Message-window pump that fires ``callback()`` on device attach/remove.

    Guards: if pywin32 is unavailable or registration fails, the thread exits
    quickly and the caller should fall back to polling.
    """

    def __init__(self, callback: Callable[[], None],
                 stop_event: Optional[threading.Event] = None) -> None:
        super().__init__(daemon=True, name="USBAttachListener")
        self.callback = callback
        self.stop_event = stop_event or threading.Event()
        self._registered = False
        self.hwnd: Optional[int] = None

    def is_available(self) -> bool:
        return self._registered

    def run(self) -> None:
        if not _HAVE_PYWIN32:
            logger.info("pywin32 not installed - USB listener unavailable (poll fallback)")
            return
        try:
            self.hwnd = self._create_message_window()
            self._register_notifications(self.hwnd)
        except Exception as exc:
            logger.warning("cannot start USB device notification: %s", exc)
            return

        logger.info("USB device notification listener active (hwnd=0x%x)", self.hwnd)
        while not self.stop_event.is_set():
            # PumpWaitingMessages() dispatches any queued WM_DEVICECHANGE without
            # blocking; the daemon sleeps the rest of the slice.
            win32gui.PumpWaitingMessages()
            time.sleep(0.05)
        try:
            win32gui.DestroyWindow(self.hwnd)
        except Exception:
            pass

    # ------------------------------------------------------------------ internals
    def _wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int):
        if msg == WM_DEVICECHANGE and wparam in (DBT_DEVICEARRIVAL,
                                                 DBT_DEVICEREMOVECOMPLETE):
            try:
                self.callback()
            except Exception:
                pass
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def _create_message_window(self) -> int:
        hinst = win32api.GetModuleHandle(None)
        wc = win32gui.WNDCLASS()
        wc.hInstance = hinst
        wc.lpfnWndProc = self._wnd_proc
        wc.lpszClassName = "SecuDriveUSBListener"
        cls = win32gui.RegisterClass(wc)
        return win32gui.CreateWindow(
            cls, "SecuDriveUSB", 0, 0, 0, 0, 0, 0, 0, hinst, None)

    def _register_notifications(self, hwnd: int) -> None:
        import win32gui_struct

        for guid in (GUID_DEVINTERFACE_USB_DEVICE, GUID_DEVINTERFACE_VOLUME):
            packed = win32gui_struct.PackDEV_BROADCAST_DEVICEINTERFACE(guid)
            win32gui.RegisterDeviceNotification(
                hwnd, packed, win32con.DEVICE_NOTIFY_WINDOW_HANDLE)
        self._registered = True


def pywin32_available() -> bool:
    return _HAVE_PYWIN32


# -- Windows Security Center registration (moved from secudrive/wsc_register.py)
#: Stable provider GUID for SecuDrive (same key every run -> idempotent).
PROVIDER_GUID = str(_uuid.uuid5(_uuid.NAMESPACE_DNS, "secudrive.wsc"))

_PROVIDER_KEY = r"SOFTWARE\Microsoft\Security Center\Provider"
_UPDATE_KEY = r"SOFTWARE\Microsoft\Security Center\Provider\Updates"
_SERVICE_NAME = "SecurityHealthService"

#: ProductState encodes provider state the way the Security Center expects
#: (documented convention used by AV vendors): 0x10000 -> "tracking enabled"
#: marker, 0x1000 -> "signatures available".  0x11000 reads as "registered,
#: up to date" in the UI.
_STATE_ON = 0x11000
_STATE_OFF = 0x10000


def _sysdrive() -> str:
    return (os.environ.get("SystemDrive") or "C:")


def _edition_notes() -> List[str]:
    notes: List[str] = []
    try:
        import winreg
    except ImportError:
        return notes
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            edition = winreg.QueryValueEx(k, "EditionID")[0]
            name = winreg.QueryValueEx(k, "ProductName")[0]
            build = winreg.QueryValueEx(k, "CurrentBuild")[0]
        notes.append(f"Windows edition: {name} ({edition}, build {build})")
        if edition and any(s in edition for s in ("Core", "Home")):
            notes.append(
                "Home SKUs show Security Center status but provider "
                "registration is best verified on Pro/Enterprise machines.")
    except OSError:
        pass
    return notes


def _write_provider_keys(exe_path: str, signature_version: str,
                         enabled: bool) -> None:
    import winreg

    state = _STATE_ON if enabled else _STATE_OFF
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                            f"{_PROVIDER_KEY}\\{PROVIDER_GUID}",
                            0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "ProductName", 0, winreg.REG_SZ,
                          "SecuDrive")
        winreg.SetValueEx(k, "ProductState", 0, winreg.REG_DWORD,
                          state)
        winreg.SetValueEx(k, "SignatureVersion", 0, winreg.REG_SZ,
                          signature_version or "1.0.0.0")
        winreg.SetValueEx(k, "PathToSignedProductExe", 0,
                          winreg.REG_EXPAND_SZ, exe_path or "")
        winreg.SetValueEx(k, "PathToUpdatedProductState", 0,
                          winreg.REG_EXPAND_SZ,
                          os.path.join(_sysdrive() + "\\", "ProgramData",
                                       "SecuDrive", "wsc_state.dll"))
        logger.info("WSC provider key written: %s\\%s", _PROVIDER_KEY,
                    PROVIDER_GUID)

    # User-level signature stamp (non-admin friendly, keeps "up to date" true).
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,
                                f"{_UPDATE_KEY}\\{PROVIDER_GUID}",
                                0, winreg.KEY_WRITE) as u:
            winreg.SetValueEx(u, "SignatureVersion", 0, winreg.REG_SZ,
                              signature_version or "1.0.0.0")
    except OSError as exc:
        logger.warning("could not write WSC user stamp: %s", exc)


def _remove_provider_keys() -> None:
    import winreg

    for hive, root in ((winreg.HKEY_LOCAL_MACHINE, _PROVIDER_KEY),
                       (winreg.HKEY_CURRENT_USER, _UPDATE_KEY)):
        full = f"{root}\\{PROVIDER_GUID}"
        try:
            winreg.DeleteKey(hive, full)
            logger.info("WSC provider key removed: %s", full)
        except OSError:
            pass


class WindowsProvider(PlatformProvider):
    """Windows NT provider: ctypes drive discovery, registry, WSC, pywin32."""

    #: Attribute constants (real Windows values; base defaults are 0).
    FILE_ATTRIBUTE_READONLY = FILE_ATTRIBUTE_READONLY
    FILE_ATTRIBUTE_HIDDEN = FILE_ATTRIBUTE_HIDDEN
    FILE_ATTRIBUTE_SYSTEM = FILE_ATTRIBUTE_SYSTEM
    FILE_ATTRIBUTE_ARCHIVE = FILE_ATTRIBUTE_ARCHIVE
    INVALID_FILE_ATTRIBUTES = INVALID_FILE_ATTRIBUTES

    def system(self) -> str:
        return "Windows"

    def __init__(self) -> None:
        super().__init__()
        # Process-CPU delta state for ``sample_cpu_percent`` (see realtime
        # throttle meter); mirrors the old ``_CPUMeter`` rolling estimate.
        self._cpu_last_k = 0.0
        self._cpu_last_u = 0.0
        self._cpu_last_wall = time.monotonic()

    # ---------------------------------------------------- drive discovery
    def all_letters(self) -> List[str]:
        return [chr(code) for code in range(ord("A"), ord("Z") + 1)]

    def logical_drive_strings(self) -> List[str]:
        r"""Roots of every mounted drive (C:\, D:\, F:\...) visible to the
        process.  Union of GetLogicalDriveStringsW and a letter probe: some
        elevated/locked sessions report an incomplete API list while plain
        ``os.path.isdir`` still sees the volume - we want the *union* so a real
        external disk can never silently fail validation."""
        roots: List[str] = []
        try:
            buf = ctypes.create_unicode_buffer(260)
            if ctypes.windll.kernel32.GetLogicalDriveStringsW(260, buf):
                roots = [s for s in buf.value.split("\x00") if s]
        except Exception:
            roots = []
        roots.extend(f"{l}:\\" for l in self.all_letters()
                     if os.path.isdir(f"{l}:\\") and f"{l}:\\" not in roots)
        return roots

    def fixed_drive_paths(self) -> List[str]:
        return [f"{l}:\\" for l in self.all_letters() if _drive_type(l) == DRIVE_FIXED]

    def removable_drive_paths(self) -> List[str]:
        return [f"{l}:\\" for l in self.all_letters() if _drive_type(l) == DRIVE_REMOVABLE]

    def list_removable_drives(self) -> List[str]:
        """Drive letters that are removable today (immunizer/watcher view)."""
        return [let for let in self.all_letters() if _drive_type(let) == DRIVE_REMOVABLE]

    def list_external_drives(self) -> List[str]:
        """External storage letters: Fixed AND removable, boot volume excluded.
        Matches the pre-refactor immunizer semantics (letters, no isdir gate -
        the watcher re-checks mount presence before acting)."""
        boot = self.system_drive_letter()
        return [let for let in self.all_letters()
                if let != boot and _drive_type(let) in (DRIVE_FIXED, DRIVE_REMOVABLE)]

    def system_drive_letter(self) -> str:
        """Return the letter (e.g. ``C``) hosting the Windows directory."""
        buf = ctypes.create_unicode_buffer(260)
        if _GetVolumeInformationW and getattr(
                ctypes.windll.kernel32, "GetWindowsDirectoryW", None):
            if ctypes.windll.kernel32.GetWindowsDirectoryW(buf, 260):
                return buf.value[0].upper()
        return (os.environ.get("SystemDrive", "C:") or "C:")[0].upper()

    def external_drive_paths(self) -> List[str]:
        """All non-system external storage: Fixed NTFS/exFAT SSDs/HDDs AND
        removable flash drives.  The system/boot volume is never included.

        An external SSD mounted as a *fixed* volume used to be invisible to the
        removable-only detector; this is the browse list the GUI / watcher /
        auto-scan service all consume.
        """
        boot = self.system_drive_letter()
        return [
            f"{l}:\\" for l in self.all_letters()
            if l != boot and os.path.isdir(f"{l}:\\")
            and _drive_type(l) in (DRIVE_FIXED, DRIVE_REMOVABLE)
        ]

    def drive_kind(self, path: str) -> str:
        """User-facing drive classification: ``External SSD/HDD (Fixed)``,
        ``USB Flash (Removable)``, or ``Unknown``."""
        prev = _drive_type(Path(path).drive[0] if Path(path).drive else "")
        return {DRIVE_FIXED: "External SSD/HDD (Fixed)",
                DRIVE_REMOVABLE: "USB Flash (Removable)"}.get(prev, "Unknown")

    def drive_display(self, path: str) -> str:
        """Dropdown label: ``F:\\ - External SSD/HDD (Fixed)`` etc."""
        return f"{path} - {self.drive_kind(path)}"

    def is_valid_drive_root(self, text: str) -> bool:
        """True only if ``text`` names a really-mounted drive root.  The exact
        check every GUI action button must pass - never a silent default."""
        if not text or not str(text).strip():
            return False
        cleaned = str(text).strip().strip('"')
        if len(cleaned) < 2 or cleaned[1] != ":":
            return False
        root = f"{cleaned[0].upper()}:\\"
        return root in self.logical_drive_strings() or os.path.isdir(root)

    def drive_volume_label(self, path: str) -> Optional[str]:
        """Best-effort volume label for a drive path ('' if none / no media)."""
        root = f"{Path(path).drive}\\"
        try:
            name_buf = ctypes.create_unicode_buffer(260)
            _GetVolumeInformationW(root, name_buf, 260, None, None, None, None, 0)
            return name_buf.value
        except Exception:
            return ""

    def is_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    # ---------------------------------------------------- file attributes
    def file_attributes_supported(self) -> bool:
        return True

    def get_file_attrs(self, path: str) -> int:
        value = _GetFileAttributesW(path)
        if value == INVALID_FILE_ATTRIBUTES:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def set_file_attrs(self, path: str, attrs: int) -> None:
        if not _SetFileAttributesW(path, attrs):
            raise ctypes.WinError(ctypes.get_last_error())

    # ---------------------------------------------------- registry autostarts
    def sanitize_registry_autostarts(self, drive_letter: str,
                                     backup_file: Optional[Path] = None,
                                     dry_run: bool = False) -> dict:
        """Delete autostart values whose command points inside the cleaned drive.

        Every affected key/value is first serialised to JSON (in ``backup_file``)
        so nothing is ever destroyed irrecoverably.  Positional skips: this only
        prunes *drive-scoped* autostarts, never removes user's own entries.
        """
        try:
            import winreg
        except ImportError as exc:  # pragma: no cover
            return {"action": "registry_sanitize", "dry_run": dry_run,
                    "error": f"winreg unavailable: {exc}"}

        drive_prefix = f"{drive_letter}:".upper()
        removed, kept = [], []
        for hive_name, subkey in _AUTOSTART_KEYS:
            hive = getattr(winreg, "HKEY_CURRENT_USER" if hive_name == "HKCU"
                           else "HKEY_LOCAL_MACHINE")
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _type = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        if isinstance(value, str) and value.upper().startswith(drive_prefix):
                            entry = {"hive": hive_name, "key": subkey, "name": name,
                                     "value": value}
                            if dry_run:
                                kept.append(entry)
                            else:
                                try:
                                    winreg.DeleteValue(key, name)
                                    removed.append(entry)
                                except OSError as exc:
                                    entry["error"] = str(exc)
                                    kept.append(entry)
                            index -= 1          # delete shifts remaining indices
                        index += 1
            except OSError as exc:
                logger.debug("no access to %s\\%s: %s", hive_name, subkey, exc)

        if not dry_run and removed and backup_file:
            try:
                backup_file.parent.mkdir(parents=True, exist_ok=True)
                with open(backup_file, "w", encoding="utf-8") as fh:
                    json.dump({"drive": drive_prefix, "removed": removed}, fh, indent=2)
            except OSError as exc:
                return {"action": "registry_sanitize", "dry_run": dry_run,
                        "removed": removed, "kept": kept, "error": f"backup failed: {exc}"}

        return {"action": "registry_sanitize", "dry_run": dry_run,
                "removed": removed, "kept": kept}

    # --------------------------------------------------------------- hotplug
    def usb_listener_available(self) -> bool:
        return pywin32_available()

    def usb_backend_name(self) -> str:
        return ("device-notification" if pywin32_available()
                else "polling-removable-volumes")

    def create_usb_listener(self, callback: Callable[[], None],
                            stop_event=None) -> Optional[USBAttachListener]:
        """Return a device-notification listener, or None for polling."""
        if not _HAVE_PYWIN32:
            return None
        return USBAttachListener(callback=callback, stop_event=stop_event)

    # ---------------------------------------------- real-time watch (6)
    def rt_watch_available(self) -> bool:
        try:
            import win32file, win32con, win32event, pywintypes  # noqa: F401
            return os.name == "nt"
        except ImportError:
            return False

    def create_watch_session(self, monitor, root: str) -> WindowsWatchSession:
        """Return one ``ReadDirectoryChangesW`` watch loop over ``root``."""
        return WindowsWatchSession(monitor, root)

    def sample_cpu_percent(self) -> float:
        """Raw (unsmoothed) process CPU% since the previous call, 0.0 on error.

        Delta state lives on the provider, which is what the old ``_CPUMeter``
        kept on itself; the caller owns smoothing/EMA of the returned value.
        """
        try:
            import ctypes.wintypes
            kernel = ctypes.windll.kernel32
            ft_create, ft_exit = (ctypes.wintypes.FILETIME(),
                                  ctypes.wintypes.FILETIME())
            ft_k, ft_u = (ctypes.wintypes.FILETIME(), ctypes.wintypes.FILETIME())
            h = kernel.GetCurrentProcess()
            kernel.GetProcessTimes(
                h, ctypes.byref(ft_create), ctypes.byref(ft_exit),
                ctypes.byref(ft_k), ctypes.byref(ft_u))

            def _ft_to_s(ft: ctypes.wintypes.FILETIME) -> float:
                return ((ft.dwHighDateTime * 0x100000000 + ft.dwLowDateTime)
                        / 10_000_000)

            now_wall = time.monotonic()
            delta_wall = max(now_wall - self._cpu_last_wall, 0.001)
            total = _ft_to_s(ft_k) + _ft_to_s(ft_u)
            delta_cpu = total - self._cpu_last_k - self._cpu_last_u
            self._cpu_last_k, self._cpu_last_u = _ft_to_s(ft_k), _ft_to_s(ft_u)
            self._cpu_last_wall = now_wall
            return (delta_cpu / delta_wall) * 100.0
        except Exception:
            return 0.0

    # ------------------------------------------------------- autostart (7)
    def autostart_enabled(self) -> bool:
        """True when the current user's Run key holds a SecuDrive entry."""
        try:
            import winreg
            with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_READ) as key:
                winreg.QueryValueEx(key, "SecuDrive")
                return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def set_autostart(self, enabled: bool) -> bool:
        """Register/unregister SecuDrive in the current user's Run key."""
        try:
            import winreg
            run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            cmd = f'"{sys.executable}"'
            if enabled:
                with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, run_key, 0,
                                        winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "SecuDrive", 0, winreg.REG_SZ, cmd)
            else:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0,
                                    winreg.KEY_WRITE) as key:
                    try:
                        winreg.DeleteValue(key, "SecuDrive")
                    except FileNotFoundError:
                        pass
            logger.info("autostart %s: %s",
                        "enabled" if enabled else "disabled", cmd)
            return True
        except Exception as exc:
            logger.warning("autostart toggle failed: %s", exc)
            return False

    # ------------------------------------------------ security-center (WSC)
    def security_center_status(self) -> dict:
        """Best-effort status of the local Security Center stack (never raises)."""
        out: dict = {"windows": True, "admin": self.is_admin(),
                     "service": "unknown", "provider_keys": "unknown",
                     "notes": []}
        out["notes"] = _edition_notes()
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Security Center") as _:
                out["provider_keys"] = "ok"
        except OSError:
            out["provider_keys"] = "missing-or-restricted"
        try:
            import subprocess
            r = subprocess.run(
                ["sc", "query", _SERVICE_NAME], capture_output=True, text=True,
                timeout=10)
            state = "stopped"
            for line in (r.stdout or "").splitlines():
                low = line.lower()
                if "running" in low:
                    state = "running"
            out["service"] = state
        except Exception:
            out["service"] = "unknown"
        return out

    def register_security_center(self, exe_path: str = "",
                                 signature_version: str = "1.0.0.0",
                                 enabled: bool = True) -> dict:
        """Register SecuDrive as a Security Center antivirus provider.

        Returns a dict with ``ok``, ``message`` and ``status``.  Idempotent -
        safe to call on every install/first-run.
        """
        result: dict = {"ok": False, "registered": False, "message": "",
                        "status": self.security_center_status()}
        if not self.is_admin():
            result["message"] = (
                "Administrator privileges are required to register Security "
                "Center providers (HKLM write).")
            return result
        try:
            _write_provider_keys(exe_path or sys.executable or "SecuDrive.exe",
                                 signature_version, enabled)
        except OSError as exc:
            logger.exception("WSC registration failed")
            result["message"] = f"WSC registration failed: {exc}"
            return result
        result["ok"] = True
        result["registered"] = True
        result["message"] = (
            "SecuDrive registered with Windows Security Center.  Note: an "
            "unsigned binary may still be ignored by Windows Security - see "
            "installer/SIGNING-NOTES.md.")
        logger.info("WSC provider registered (exe=%s, version=%s)",
                    exe_path, signature_version)
        return result

    def unregister_security_center(self) -> dict:
        """Reverses ``register_security_center`` (also needs admin for HKLM)."""
        result: dict = {"ok": False, "message": "",
                        "status": self.security_center_status()}
        if not self.is_admin():
            result["message"] = ("Administrator privileges are required to "
                                 "remove Security Center provider keys.")
            return result
        _remove_provider_keys()
        result["ok"] = True
        result["message"] = "SecuDrive removed from Windows Security Center."
        return result

    def wmi_visible(self, provider_guid: Optional[str] = None) -> bool:
        """Best-effort read-back via root\\SecurityCenter2 (requires pywin32).

        Returns True when an ``AntivirusProduct`` instance reports our provider
        name/guid.  False when the WMI class is absent or the provider is not
        listed (common while the Security Health service catches up).
        """
        guid = (provider_guid or PROVIDER_GUID).upper()
        try:
            import win32com.client  # type: ignore
        except ImportError:
            return False
        try:
            wmi = win32com.client.GetObject("winmgmts://./root/SecurityCenter2")
            for item in wmi.InstancesOf("AntivirusProduct"):
                raw = ""
                for attr in ("instanceGuid", "productState"):
                    try:
                        raw = raw + str(item.GetObjectText())
                        break
                    except Exception:
                        continue
                text = str(item.GetObjectText()) if hasattr(item,
                                                            "GetObjectText") else ""
                if guid.lower() in text.lower() or "secudrive" in text.lower():
                    return True
        except Exception as exc:  # noqa: BLE001 - read-back is best-effort
            logger.debug("SecurityCenter2 read-back unavailable: %s", exc)
        return False