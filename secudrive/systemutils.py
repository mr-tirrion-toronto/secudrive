"""systemutils.py - cross-platform drive / privilege / home-dir discovery.

Single source of truth for "which paths do we scan / clean / watch?" shared
by the GUI, the watcher service, and the CLI.

All platform-specific behaviour is delegated to ``secudrive.platform`` so
the same codebase runs unchanged on Windows, Linux, and macOS.
"""
from __future__ import annotations

from typing import List, Optional

from .logging_utils import get_logger
from .platform import get_provider

logger = get_logger("systemutils")

provider = get_provider()

DRIVE_FIXED = 3
DRIVE_REMOVABLE = 2


def all_letters() -> List[str]:
    return provider.all_letters()


def logical_drive_strings() -> List[str]:
    return provider.logical_drive_strings()


def fixed_drive_paths() -> List[str]:
    return provider.fixed_drive_paths()


def removable_drive_paths() -> List[str]:
    return provider.removable_drive_paths()


def system_drive_letter() -> str:
    return provider.system_drive_letter()


def external_drive_paths() -> List[str]:
    return provider.external_drive_paths()


def drive_kind(path: str) -> str:
    return provider.drive_kind(path)


def drive_display(path: str) -> str:
    return provider.drive_display(path)


def is_valid_drive_root(text: str) -> bool:
    return provider.is_valid_drive_root(text)


def drive_volume_label(path: str) -> Optional[str]:
    return provider.drive_volume_label(path)


def is_admin() -> bool:
    return provider.is_admin()


# ------------------------------------------------------------------ helpers
def user_content_paths() -> List[str]:
    return provider.user_content_paths()


def quick_scan_targets() -> List[str]:
    return provider.quick_scan_targets()


def full_scan_targets() -> List[str]:
    return provider.full_scan_targets()


def auto_scan_targets() -> List[str]:
    return provider.auto_scan_targets()