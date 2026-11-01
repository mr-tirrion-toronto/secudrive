"""macos_smoke.py - macOS-side regression gate for the platform layer.

Run on a Mac (or any box where ``secudrive/macos_provider.py`` is meant to
work):

    python scripts/macos_smoke.py

What it verifies:
    1. Every core module imports (forces provider auto-selection).
    2. On Darwin, ``get_provider()`` returns ``MacOSProvider`` and ``system()``
       is "macOS".
    3. Drive discovery contract: fixed/removable/external enumeration, boot
       exclusion, ``drive_kind`` / ``drive_display`` / ``drive_volume_label`` /
       ``is_valid_drive_root``, plus ``volume_root`` letter/mount mapping.
    4. Base-delegated no-ops behave (registry sanitize, Security Center, USB
       listener fallback, file attributes - incl. a live ``chflags`` round-trip
       using the owner-settable UF_HIDDEN flag).
    5. Real-time watch: when watchdog (FSEvents) is installed, start a watch on
       a temp dir, create a file, expect an ADDED event, then a clean stop.
    6. CPU meter returns a sane percentage over a short busy loop.
    7. Autostart round-trip against a temporary HOME (LaunchAgents plist).
    8. Watcher + immunizer wiring (polling backend; ``external_drive_details``
       structure; ``immunize`` on a temp drive).

Exit code 0 = PASS on the checks that apply to this host.  Optional-backend
checks that cannot run (no watchdog / not on Darwin) are reported as SKIP, not
FAIL.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

failures: list = []
skips: list = []
ok_count = 0


def check(name: str, cond, detail: str = "") -> None:
    global ok_count
    if cond:
        ok_count += 1
        print(f"  PASS  {name}")
    else:
        failures.append(name)
        print(f"  FAIL  {name}  {detail}")


def skip(name: str, why: str) -> None:
    skips.append(name)
    print(f"  SKIP  {name}  ({why})")


# --------------------------------------------------------------------------
# 1 + 2. imports and provider selection
print("[1] module imports + provider selection")
from secudrive import (  # noqa: E402  (import smoke, order matters for parity)
    cli, gui, immunizer, realtime_monitor, recovery, scanner, systemutils,
    watcher, wsc_register,
)
from secudrive.cli import build_parser  # noqa: E402
from secudrive.platform import get_provider  # noqa: E402
from secudrive.platform.macos_provider import MacOSProvider  # noqa: E402

check("all core modules import", True)
build_parser()

is_macos = os.name == "posix" and sys.platform == "darwin"
provider = get_provider()
if is_macos:
    from secudrive.platform.macos_provider import _HAVE_WATCHDOG  # noqa: E402
    check("get_provider -> MacOSProvider", isinstance(provider, MacOSProvider))
    check("provider.system() == macOS", provider.system() == "macOS")
else:
    from secudrive.platform import macos_provider as mp
    _HAVE_WATCHDOG = mp._HAVE_WATCHDOG
    provider = mp.MacOSProvider()  # Windows sim exercises the same code paths


# --------------------------------------------------------------------------
# 3. drive discovery contract
print("[2] drive discovery")
mac_provider = provider if is_macos else mp.MacOSProvider()

root_d = mac_provider.volume_root("D")
check("volume_root('D') == 'D:\\\\'", root_d == "D:\\")
root_v = mac_provider.volume_root("/Volumes/USB")
check("volume_root('/Volumes/USB') ends with sep",
      root_v.startswith("/Volumes/USB") and root_v.endswith(os.sep))

letters = mac_provider.all_letters()
check("all_letters() returns list", isinstance(letters, list))
logical = mac_provider.logical_drive_strings()
check("logical_drive_strings() returns list", isinstance(logical, list))

if is_macos:
    fixed = mac_provider.fixed_drive_paths()
    check("fixed_drive_paths contains '/'", "/" in fixed)
    check("system_drive_letter() == '/'", mac_provider.system_drive_letter() == "/")
    check("external excludes boot volume",
          not any(m.rstrip("/") in ("", "/")
                  for m in mac_provider.external_drive_paths()))
    check("is_valid_drive_root('C:\\') False (no such mount on macOS)",
          mac_provider.is_valid_drive_root("C:\\") is False)
else:
    skip("real mount assertions", "not on macOS")

kind = mac_provider.drive_kind("/")
check("drive_kind('/') is a known label",
      kind in ("External SSD/HDD (Fixed)", "USB Flash (Removable)", "Unknown"))
check("drive_display ends with kind", mac_provider.drive_display("/").endswith(kind))
label = mac_provider.drive_volume_label("/")
check("drive_volume_label('/') is str/None/''",
      label is None or isinstance(label, str))
check("is_valid_drive_root('/') True", mac_provider.is_valid_drive_root("/"))

# --------------------------------------------------------------------------
# 4. base-delegated no-ops / macOS-specific capabilities
print("[3] base-delegated capability no-ops")
reg = mac_provider.sanitize_registry_autostarts("X", dry_run=True)
check("registry sanitize is a no-op report", reg.get("action") == "registry_sanitize")
wsc = mac_provider.register_security_center()
check("WSC register ok=False", wsc.get("ok") is False)
st = mac_provider.security_center_status()
check("WSC status windows=False", st.get("windows") is False)
check("usb_listener backend bool",
      isinstance(mac_provider.usb_listener_available(), bool))
check("usb backend label is polling (no udev on macOS)",
      mac_provider.usb_backend_name() == "polling-removable-volumes")

if mac_provider.file_attributes_supported():
    check("file_attributes_supported() True on macOS", True)
    tmp_attr = tempfile.NamedTemporaryFile(prefix="secudrive-attr-", delete=False)
    tmp_attr.close()
    try:
        check("get_file_attrs(tmp) initially 0",
              mac_provider.get_file_attrs(tmp_attr.name) == 0)
        mac_provider.set_file_attrs(tmp_attr.name,
                                    mac_provider.FILE_ATTRIBUTE_HIDDEN)
        check("set_file_attrs(HIDDEN) sticks",
              bool(mac_provider.get_file_attrs(tmp_attr.name)
                   & mac_provider.FILE_ATTRIBUTE_HIDDEN))
        mac_provider.set_file_attrs(tmp_attr.name, 0)
        check("set_file_attrs(0) clears", mac_provider.get_file_attrs(
            tmp_attr.name) == 0)
    except OSError as exc:
        check("chflags round-trip (needs an owner-settable flag)", False, repr(exc))
    finally:
        os.unlink(tmp_attr.name)
else:
    check("file_attributes_supported() False elsewhere", True)
    try:
        mac_provider.get_file_attrs("/tmp")
        check("get_file_attrs raises OSError", False)
    except OSError:
        check("get_file_attrs raises OSError", True)
    except Exception as exc:
        check("get_file_attrs raises OSError (only)", False, repr(exc))
    skip("chflags round-trip", "not on macOS")

# --------------------------------------------------------------------------
# 5. real-time watch (optional backend)
print("[4] real-time watch")
if not is_macos:
    check("rt_watch_available() is bool", isinstance(mac_provider.rt_watch_available(), bool))
    skip("watchdog live watch", "not on macOS")


class _StubMonitor:
    buffer_bytes = 65536
    events: list = []

    def _on_watch_event(self, action, rel, root):
        self.events.append((action, rel, root))

    def _on_rt_event(self, msg, kind):
        pass

    def _session_ready(self, sess):
        self.ready = getattr(self, "ready", 0) + 1

    def _session_failed(self, sess, err):
        self.failed = err

    def _session_ended(self, sess):
        self.ended = getattr(self, "ended", 0) + 1


if mac_provider.rt_watch_available() and is_macos:
    tmpdir = tempfile.mkdtemp(prefix="secudrive-rt-")
    try:
        mon = _StubMonitor()
        session = mac_provider.create_watch_session(mon, tmpdir)
        session.start()
        time.sleep(1.0)
        probe = os.path.join(tmpdir, "probe.bin")
        with open(probe, "wb") as fh:
            fh.write(b"x" * 16)
        deadline = time.time() + 6.0
        while time.time() < deadline and not mon.events:
            time.sleep(0.1)
        check("watchdog event captured", bool(mon.events), repr(mon.events[:3]))
        session.stop()
        check("session ended callback fired",
              isinstance(getattr(mon, "ended", 0), int) and mon.ended >= 1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
elif is_macos and not mac_provider.rt_watch_available():
    skip("watchdog live watch", "watchdog not installed")

# --------------------------------------------------------------------------
# 6. CPU meter
print("[5] CPU meter")
start = time.monotonic()
busy = 0.0
while time.monotonic() - start < 0.3:
    busy += 1.0
p1 = mac_provider.sample_cpu_percent()
time.sleep(0.25)
p2 = mac_provider.sample_cpu_percent()
check("sample_cpu_percent() >= 0", p1 >= 0.0 and p2 >= 0.0,
      f"samples {p1:.2f} {p2:.2f}")

# --------------------------------------------------------------------------
# 7. autostart round-trip (redirected HOME -> LaunchAgents)
print("[6] autostart")
hold_home = os.environ.get("HOME")
try:
    tmp_home = tempfile.mkdtemp(prefix="secudrive-home-")
    os.environ["HOME"] = tmp_home
    check("autostart_enabled() False initially",
          mac_provider.autostart_enabled() is False)
    check("set_autostart(True)", mac_provider.set_autostart(True) is True)
    check("autostart_enabled() True after enable",
          mac_provider.autostart_enabled() is True)
    check("set_autostart(False)", mac_provider.set_autostart(False) is True)
    check("autostart_enabled() False after disable",
          mac_provider.autostart_enabled() is False)
    f = mac_provider._autostart_file()
    check("launch agent plist gone after disable", not f.exists())
finally:
    if hold_home is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = hold_home
    shutil.rmtree(tmp_home, ignore_errors=True)

# --------------------------------------------------------------------------
# 8. watcher + immunizer wiring
print("[7] watcher + immunizer wiring")
from secudrive.watcher import BackgroundWatcher
from secudrive.immunizer import external_drive_details, immunize

details = external_drive_details()
check("external_drive_details() list of dicts",
      isinstance(details, list) and all(isinstance(d, dict) for d in details))
if details:
    d0 = details[0]
    check("detail has letter/path/kind", {"letter", "path", "kind"} <= set(d0))
    check("detail path is a real dir", os.path.isdir(d0["path"]))

tmpdrv = tempfile.mkdtemp(prefix="secudrive-drv-")
try:
    report = immunize(tmpdrv)
    check("immunize() reports steps", "steps" in report)
finally:
    shutil.rmtree(tmpdrv, ignore_errors=True)

watcher = BackgroundWatcher(interval=0.2)
watcher.start()
time.sleep(0.4)
alive = watcher.is_running()
watcher.stop()
check("BackgroundWatcher start/stop", alive is True and not watcher.is_running())

# --------------------------------------------------------------------------
print()
if failures:
    print(f"MACOS SMOKE: FAIL ({len(failures)} failures, {ok_count} passed,"
          f" {len(skips)} skipped)")
    for name in failures:
        print("   -", name)
    sys.exit(1)
print(f"MACOS SMOKE: PASS ({ok_count} passed, {len(skips)} skipped)")
sys.exit(0)