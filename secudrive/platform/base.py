"""base.py - PlatformProvider contract (cross-platform abstraction).

Every OS-dependent capability SecuDrive needs lives behind this one
interface, so the core modules (scanner, recovery, immunizer, watcher,
wsc_register, realtime_monitor) never touch win32 / registry code directly
and the *same* codebase runs on Windows, Linux, and macOS.

Concrete per-OS providers live next to this file:

    windows_provider.py -> WindowsProvider
    linux_provider.py   -> LinuxProvider   (written in the cross-platform phase)
    macos_provider.py   -> MacOSProvider   (written in the cross-platform phase)

Method name = capability.  The Windows provider bodies are the pre-refactor
module functions moved verbatim; platform-independent helpers (quick/full/
auto scan target selection) live here once, on the base class.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, List, Optional, Tuple


class PlatformProvider:
    """One object per running OS; instantiate via ``get_provider()``.

    Platform-specific methods raise ``NotImplementedError`` on the base class
    so the package stays importable everywhere until each provider lands.
    """

    # ------------------------------------------------------------------ meta
    def system(self) -> str:
        """OS the provider serves: ``Windows``, ``Linux``, ``Darwin``..."""
        return "unknown"

    # ---------------------------------------------------- drive discovery (1)
    def all_letters(self) -> List[str]:
        """Drive letters (Windows) / mount identifiers (POSIX)."""
        raise NotImplementedError("drive-letter enumeration is not implemented "
                                  "for this platform")

    def logical_drive_strings(self) -> List[str]:
        """Roots of every mounted drive the process can see."""
        raise NotImplementedError("logical drive enumeration is not implemented "
                                  "for this platform")

    def fixed_drive_paths(self) -> List[str]:
        """Roots of fixed local volumes."""
        raise NotImplementedError("fixed-drive enumeration is not implemented "
                                  "for this platform")

    def removable_drive_paths(self) -> List[str]:
        """Roots of removable volumes (flash / external media)."""
        raise NotImplementedError("removable-drive enumeration is not implemented "
                                  "for this platform")

    def list_removable_drives(self) -> List[str]:
        """Drive letters/identifiers that are removable today (dual of
        ``removable_drive_paths``; used by the immunizer/watcher)."""
        raise NotImplementedError("removable-drive enumeration is not implemented "
                                  "for this platform")

    def list_external_drives(self) -> List[str]:
        """External storage letters/identifiers (boot volume excluded)."""
        raise NotImplementedError("external-drive enumeration is not implemented "
                                  "for this platform")

    def system_drive_letter(self) -> str:
        """Letter hosting the OS (e.g. ``C``); '' when none."""
        raise NotImplementedError("system-drive detection is not implemented "
                                  "for this platform")

    def external_drive_paths(self) -> List[str]:
        """Non-system external storage (Fixed SSDs/HDDs AND removable)."""
        raise NotImplementedError("external-drive enumeration is not implemented "
                                  "for this platform")

    def drive_kind(self, path: str) -> str:
        """User-facing classification label for ``path``."""
        raise NotImplementedError("drive classification is not implemented "
                                  "for this platform")

    def drive_display(self, path: str) -> str:
        """Dropdown label for ``path`` (kind appended where supported)."""
        raise NotImplementedError("drive display formatting is not implemented "
                                  "for this platform")

    def is_valid_drive_root(self, text: str) -> bool:
        """True only when ``text`` names a really-mounted drive root."""
        raise NotImplementedError("drive-root validation is not implemented "
                                  "for this platform")

    def drive_volume_label(self, path: str) -> Optional[str]:
        """Best-effort volume label for ``path`` ('' if none / no media)."""
        raise NotImplementedError("volume-label lookup is not implemented "
                                  "for this platform")

    # --------------------------------------------------------------- privilege
    def is_admin(self) -> bool:
        """True when the process runs with administrator/root rights."""
        raise NotImplementedError("privilege detection is not implemented "
                                  "for this platform")

    # --------------------------------------------------- file attributes (2)
    def file_attributes_supported(self) -> bool:
        """True when HIDDEN/SYSTEM attribute bits are meaningful here."""
        return False

    # Windows attribute bits (0 on platforms without attribute semantics).
    FILE_ATTRIBUTE_READONLY = 0
    FILE_ATTRIBUTE_HIDDEN = 0
    FILE_ATTRIBUTE_SYSTEM = 0
    FILE_ATTRIBUTE_ARCHIVE = 0
    INVALID_FILE_ATTRIBUTES = None

    def get_file_attrs(self, path: str) -> int:
        """Return the raw attribute bitmask; raises OSError when unavailable."""
        raise OSError("file attributes are not supported on this platform")

    def set_file_attrs(self, path: str, attrs: int) -> None:
        """Set the raw attribute bitmask; raises OSError when unavailable."""
        raise OSError("file attributes are not supported on this platform")

    # ------------------------------------------ registry autostarts (3)
    def sanitize_registry_autostarts(self, drive_letter: str,
                                     backup_file: Optional[Path] = None,
                                     dry_run: bool = False) -> dict:
        """Prune autostart values pointing inside the cleaned drive."""
        return {"action": "registry_sanitize", "dry_run": dry_run,
                "removed": [], "kept": [],
                "error": "registry autostart sanitizing is not implemented "
                         "for this platform"}

    # ------------------------------------------------------ hotplug (4)
    def usb_listener_available(self) -> bool:
        """True when a low-latency USB notification backend is available."""
        return False

    def usb_backend_name(self) -> str:
        """User-facing backend label: ``device-notification`` vs polling.
        Called only when a low-latency listener is in use."""
        return "device-notification"

    def create_usb_listener(self, callback: Callable[[], None],
                            stop_event=None):
        """Return a started-capable listener object, or None for polling.
        The listener exposes ``start()``, ``stop()``, ``is_alive()`` and
        ``is_available()`` (see watcher.py)."""
        return None

    # ------------------------------------------ security-center (5)
    def register_security_center(self, exe_path: str = "",
                                 signature_version: str = "1.0.0.0",
                                 enabled: bool = True) -> dict:
        """Register the product with the OS security center (best-effort)."""
        return {"ok": False, "registered": False,
                "message": "Security Center registration is not implemented "
                           "for this platform"}

    def unregister_security_center(self) -> dict:
        """Reverse ``register_security_center`` (best-effort)."""
        return {"ok": False,
                "message": "Security Center registration is not implemented "
                           "for this platform"}

    def security_center_status(self) -> dict:
        """Best-effort status of the OS security-center stack (never raises)."""
        return {"windows": False, "admin": self.is_admin(),
                "service": "unknown", "provider_keys": "unknown",
                "notes": ["Security Center is Windows-only."]}

    def wmi_visible(self, provider_guid: Optional[str] = None) -> bool:
        """Best-effort read-back of security-center registration."""
        return False

    # ------------------------------------------- real-time watch (6)
    def rt_watch_available(self) -> bool:
        """True when a low-latency file-watch backend is available."""
        return False

    def create_watch_session(self, monitor, root: str):
        """Return a watch session object for ``root`` (see realtime_monitor)."""
        raise NotImplementedError("low-latency file watching is not implemented "
                                  "for this platform")

    def sample_cpu_percent(self) -> float:
        """Current process CPU% (0.0 when the estimate is unavailable)."""
        return 0.0

    # ------------------------------------------------------- autostart (7)
    def autostart_enabled(self) -> bool:
        """True when SecuDrive is registered to run at login."""
        return False

    def set_autostart(self, enabled: bool) -> bool:
        """Register/unregister SecuDrive at login; True on success."""
        return False

    # ---------------------------------------- platform-independent helpers
    def volume_root(self, ident: str) -> str:
        """Canonical root path for a volume identifier.

        Windows identifiers are single letters (``D`` -> ``D:\\``); POSIX
        identifiers are already mount points (``/media/u/USB`` -> kept, with a
        trailing separator).  Consumers use this instead of ``f"{letter}:\\\\"``
        so the same watcher/immunizer code runs on every platform.
        """
        if ident and len(ident) == 1 and ident.isalpha():
            return f"{ident}:\\"
        root = str(ident).rstrip("\\/")
        return root + os.sep if root else os.sep

    def user_content_paths(self) -> List[str]:
        """Desktop / Documents / Downloads / Pictures that actually exist."""
        home = Path("~").expanduser()
        candidates: List[Path] = []
        for sub in ("Desktop", "Documents", "Downloads", "Pictures"):
            p = home / sub
            if p.is_dir():
                candidates.append(p)
        if not candidates:
            candidates.append(home)
        return [str(p) for p in candidates]

    def quick_scan_targets(self) -> List[str]:
        """Quick Scan = real user data first.  A target nested inside an
        already-selected one is dropped (it would duplicate the walk), but
        sibling content directories on the same volume (Desktop, Documents,
        Downloads, Pictures...) are ALL kept - that is the point of a quick
        user-data scan."""
        targets: List[str] = []
        for path in self.user_content_paths():
            norm = os.path.normpath(path)
            if any(self._path_is_within(norm, os.path.normpath(kept))
                   for kept in targets):
                continue
            targets.append(path)
        return targets

    @staticmethod
    def _path_is_within(candidate: str, parent: str) -> bool:
        """True when ``candidate`` equals ``parent`` or lies under it
        (path-only containment so same-volume siblings are never dropped)."""
        try:
            return os.path.commonpath([candidate, parent]) == parent
        except ValueError:
            return False

    def full_scan_targets(self) -> List[str]:
        """Full Scan = every fixed local volume (skips empty/exotic mounts)."""
        return [p for p in self.fixed_drive_paths() if os.path.isdir(p)]

    def auto_scan_targets(self) -> List[str]:
        """Launch-time silent scan set: system volume root + external volumes.

        The boot volume is bounded by "quick" semantics upstream (max_depth +
        the scanner's exclude-dirs); external drives are walked fully.
        """
        targets: List[str] = []
        boot = self.system_drive_letter()
        if boot:
            boot_root = self.volume_root(boot)
            if os.path.isdir(boot_root):
                targets.append(boot_root)
        if not targets:
            targets = list(self.user_content_paths())
        targets.extend(p for p in self.external_drive_paths()
                       if p not in targets)
        return targets


class FallbackProvider(PlatformProvider):
    """Unsupported-platform stand-in (importable anywhere).

    Keeps every module importable on platforms without a dedicated provider
    yet; capability calls raise ``NotImplementedError``.
    """

    def __init__(self, system_name: str = "unknown") -> None:
        self._system_name = system_name

    def system(self) -> str:
        return self._system_name