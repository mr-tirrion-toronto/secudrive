"""immunizer.py - External Drive Immunizer.

* ``DriveWatcher`` - polls removable drive availability and fires a callback
  on new mounts so the recovery engine can deep-clean a freshly plugged drive
  without user interaction.
* ``immunize()``     - legacy vaccination: create an ``autorun.inf`` *directory*
  at the drive root (a file with that exact name can then never be dropped,
  because a directory and a file cannot coexist with the same name).
* ``sanitize_registry_autostarts()`` - prune autostart values that point into a
  cleaned drive letter.  Registry state is JSON-exported to the backup store
  before any value is deleted (zero data loss applied to the registry too).

Drive discovery and the registry pruning are delegated to
``secudrive.platform`` so the same module runs on Windows, Linux, and macOS.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .logging_utils import get_logger
from .platform import get_provider

logger = get_logger("immunizer")

provider = get_provider()


# ------------------------------------------------------------------- drives
def _drive_exists(ident: str) -> bool:
    """True when the identifier names a currently-mounted volume root."""
    return os.path.isdir(provider.volume_root(ident))


def list_removable_drives() -> List[str]:
    """Return drive identifiers (letters on Windows, e.g. ['E', 'F']; mount
    points on POSIX) that are removable today."""
    return provider.list_removable_drives()


def list_external_drives() -> List[str]:
    """External storage identifiers: Fixed (NTFS/exFAT SSDs/HDDs) AND removable,
    excluding the system/boot volume.  This is what the watcher + Drive
    Doctor consider \"external media\".
    """
    return provider.list_external_drives()


def external_drive_details() -> List[dict]:
    """Typed external drive list: ``[{"letter": "F", "path": "F:\\",
    "kind": "External SSD/HDD (Fixed)"}, ...]`` (Fixed + Removable,
    system volume excluded).  On POSIX ``letter`` holds the mount point.
    What the GUI/autopilot bind to."""
    from .systemutils import drive_kind
    return [{"letter": ident, "path": provider.volume_root(ident),
             "kind": drive_kind(provider.volume_root(ident))}
            for ident in list_external_drives()
            if os.path.isdir(provider.volume_root(ident))]


class DriveWatcher:
    """Background poller that reports newly inserted external drives.

    Watches Fixed + Removable volumes (external SSD/HDD included), excluding
    the system/boot volume - see ``list_external_drives``.  Raising the
    ``on_remove`` callback keeps the GUI list honest when a drive is yanked.
    """

    def __init__(self, interval: float = 2.0,
                 callback: Optional[Callable[[str], None]] = None,
                 on_remove: Optional[Callable[[str], None]] = None) -> None:
        self.interval = interval
        self.callback = callback or (lambda letter: None)
        self.on_remove = on_remove or (lambda letter: None)
        self._known: set[str] = set(self._snapshot())
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "DriveWatcher":
        self._thread = threading.Thread(target=self._run, name="DriveWatcher", daemon=True)
        self._thread.start()
        logger.info("drive watcher started (interval=%ss)", self.interval)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 1.0)

    def refresh(self) -> List[str]:
        """Immediately re-list external drives (device-change fast path)."""
        now = set(self._snapshot())
        self._diff(now)
        return sorted(now)

    def _snapshot(self) -> List[str]:
        return [provider.volume_root(ident)
                for ident in list_external_drives()
                if _drive_exists(ident)]

    def _run(self) -> None:
        while not self._stop.is_set():
            self._diff(set(self._snapshot()))
            self._stop.wait(self.interval)

    def _diff(self, now: set) -> None:
        joined = now - self._known
        for letter in sorted(joined):
            if _drive_exists(letter):
                path = f"{letter}:\\"
                logger.info("external drive detected: %s", path)
                try:
                    self.callback(path)
                except Exception as exc:                       # never kill the watcher
                    logger.error("drive callback failed for %s: %s", path, exc)
        removed = self._known - now
        for letter in sorted(removed):
            path = f"{letter}:\\"
            logger.info("external drive removed: %s", path)
            try:
                self.on_remove(path)
            except Exception as exc:
                logger.error("drive remove callback failed for %s: %s", path, exc)
        self._known = now

    def wait_forever(self) -> None:
        """Block the calling thread until Ctrl+C (drives keep getting cleaned)."""
        try:
            while not self._stop.is_set():
                time.sleep(1.0)
        except KeyboardInterrupt:
            self.stop()


def immunize(drive_root: Path, vaccinate_autorun: bool = True) -> Dict:
    """Vaccinate a drive against autorun.inf / fake-shortcut persistence."""
    drive_root = Path(drive_root)
    report = {"action": "immunize", "target": str(drive_root), "steps": []}

    if vaccinate_autorun:
        vaccine = drive_root / "autorun.inf"
        if vaccine.is_file():
            report["steps"].append({
                "step": "autorun_inf_file_present",
                "detail": "an actual autorun.inf exists - not overwritable by vaccine; "
                          "run 'clean' to retire it",
            })
        elif vaccine.is_dir():
            report["steps"].append({
                "step": "autorun_inf_vaccine_ok",
                "detail": "vaccinating 'autorun.inf' directory already present",
            })
        else:
            try:
                vaccine.mkdir(exist_ok=False)
                report["steps"].append({
                    "step": "autorun_inf_vaccine_created",
                    "detail": "directory vaccine created; a same-name file can no longer be "
                              "silently dropped on this volume",
                })
            except OSError as exc:
                report["steps"].append({"step": "error", "detail": str(exc)})
    return report


# ------------------------------------------------------------------- registry
def sanitize_registry_autostarts(drive_letter: str, backup_file: Optional[Path] = None,
                                 dry_run: bool = False) -> Dict:
    """Delete autostart values whose command points inside the cleaned drive.

    Delegated to the platform provider.  The Windows provider serialises every
    affected key/value to JSON (in ``backup_file``) before deletion so nothing
    is ever destroyed irrecoverably.  Positional skips: this only prunes
    *drive-scoped* autostarts, never removes user's own entries.
    """
    return provider.sanitize_registry_autostarts(
        drive_letter, backup_file=backup_file, dry_run=dry_run)