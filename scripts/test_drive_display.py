#!/usr/bin/env python3
"""test_drive_display.py - regression test for provider.drive_display().

Guards the latent Windows bug fixed during the platform refactor
(windows_provider.drive_display formerly called the bare module function
``drive_kind(...)`` -> NameError on every call; nothing exercised that code
path because real-time drive-dashboard rows are shown from cached lists).

Checks, for every provider implementation:
  * drive_display() never raises for any *string* input
  * output always matches ``f"{path} - {kind}"`` with a legal kind label
  * kind round-trips through drive_kind(path)
  * real mounted drives (active provider) produce valid labels
  * FallbackProvider raises NotImplementedError explicitly (documented
    unsupported-platform contract, not a crash)
"""
import sys
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "platform").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive.platform.base import FallbackProvider  # noqa: E402
from secudrive.platform import get_provider  # noqa: E402
from secudrive.platform.linux_provider import LinuxProvider  # noqa: E402
from secudrive.platform.macos_provider import MacOSProvider  # noqa: E402
from secudrive.platform.windows_provider import WindowsProvider  # noqa: E402

KINDS = {"External SSD/HDD (Fixed)", "USB Flash (Removable)", "Unknown"}

PATH_BATTERY = [
    "C:\\", "c:\\", "C:", "D:", "D:\\", "",
    "foobar", "C:\\Users", "C:\\Users\\Public",
    " /mnt/usb ", '"D:\\"', "/", "/home", "/media/user/USB",
    "path with spaces\\x.txt", "Проект:\\файл",
]


def run_provider(provider, label: str) -> int:
    for p in PATH_BATTERY:
        display = provider.drive_display(p)
        kind = provider.drive_kind(p)
        assert display == f"{p} - {kind}", (label, repr(p), display, kind)
        assert kind in KINDS, (label, repr(p), kind)
    print(f"{label}: drive_display ok across {len(PATH_BATTERY)} inputs")
    return 0


def run_active(provider) -> int:
    """Real mounted drives must produce valid labels on the active provider."""
    seen = 0
    for root in (provider.external_drive_paths()
                 + provider.removable_drive_paths()
                 + provider.quick_scan_targets()):
        display = provider.drive_display(root)
        assert " - " in display, (root, display)
        assert display.rsplit(" - ", 1)[1] in KINDS, (root, display)
        seen += 1
    print(f"active({provider.system()}): drive_display ok on {seen} real roots")
    return 0


def main() -> int:
    run_provider(WindowsProvider(), "windows")
    run_provider(LinuxProvider(), "linux")
    run_provider(MacOSProvider(), "macos")

    active = get_provider()
    run_active(active)

    # FallbackProvider: the contract says NotImplementedError, loudly - never a
    # partial render or a NameError-style crash.
    fb = FallbackProvider("test")
    try:
        fb.drive_display("C:\\")
    except NotImplementedError:
        pass
    else:
        raise AssertionError("FallbackProvider.drive_display must raise "
                             "NotImplementedError")
    print("fallback: drive_display raises NotImplementedError (expected)")

    print("\ndrive_display regression: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # keep the traceback meaningful on failure
        print(f"\ndrive_display regression: FAIL ({exc})", file=sys.stderr)
        raise