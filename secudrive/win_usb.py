"""win_usb.py - low-latency USB/external-media attach detection (Windows).

This module is a thin compatibility shim: the implementation lives in
``secudrive.platform.windows_provider`` so the platform refactor can keep
one source of truth.  Importing it returns the provider's listener /
availability helpers unchanged.

Preferred backend: RegisterDeviceNotification via a message-only window
(pywin32).  Falls back cleanly to ``False`` availability so the watcher can
degrade to polling when pywin32 is absent (POSIX, or slim builds).

Drive-letter resolution is deliberately deferred: Windows reports a *device
path* (e.g. \\?\\usb#vid_...) on arrival, not a drive letter.  Mapping device
paths to letters requires DeviceIoControl / WMI round-trips, so this listener
only wakes the background watcher, which then re-lists removable volumes (a
few milliseconds later the fresh letter is visible).  This keeps the backend
correct without pywin32 GUI plumbing complexity.
"""
from __future__ import annotations

from .platform.windows_provider import (  # noqa: F401
    DBT_DEVICEARRIVAL,
    DBT_DEVICEREMOVECOMPLETE,
    GUID_DEVINTERFACE_USB_DEVICE,
    GUID_DEVINTERFACE_VOLUME,
    USBAttachListener,
    WM_DEVICECHANGE,
    pywin32_available,
)

__all__ = [
    "DBT_DEVICEARRIVAL",
    "DBT_DEVICEREMOVECOMPLETE",
    "GUID_DEVINTERFACE_USB_DEVICE",
    "GUID_DEVINTERFACE_VOLUME",
    "USBAttachListener",
    "WM_DEVICECHANGE",
    "pywin32_available",
]