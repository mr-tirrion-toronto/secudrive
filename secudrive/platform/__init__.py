"""secudrive.platform - per-OS capability providers.

``get_provider()`` auto-selects the provider for the running OS so the core
modules can stay platform-agnostic:

    Windows -> WindowsProvider
    Linux   -> LinuxProvider
    Darwin  -> MacOSProvider
"""
from __future__ import annotations

import platform as _platform

from .base import FallbackProvider, PlatformProvider

_provider = None


def get_provider() -> PlatformProvider:
    """Return (and cache) the provider for the running OS."""
    global _provider
    if _provider is None:
        system = _platform.system()
        if system == "Windows":
            from .windows_provider import WindowsProvider
            _provider = WindowsProvider()
        elif system == "Linux":
            from .linux_provider import LinuxProvider
            _provider = LinuxProvider()
        elif system == "Darwin":
            from .macos_provider import MacOSProvider
            _provider = MacOSProvider()
        # Unsupported platforms get an importable stand-in so every module
        # loads everywhere; capability calls raise NotImplementedError.
        else:
            _provider = FallbackProvider(system_name=system)
    return _provider