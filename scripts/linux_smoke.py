"""linux_smoke.py - Linux-side regression gate for the platform layer.

Run on a Linux box (or any box where ``secudrive/linux_provider.py`` is meant
to work):

    python scripts/linux_smoke.py

What it verifies:
    1. Every core module imports (forces provider auto-selection).
    2. On Linux, ``get_provider()`` returns ``LinuxProvider`` and ``system()``
       is "Linux".
    3. Drive discovery contract: fixed/removable/external enumeration, boot
       exclusion, ``drive_kind`` / ``drive_display`` / ``drive_volume_label`` /
       ``is_valid_drive_root``, plus ``volume_root`` letter/mount mapping.
    4. Base-delegated no-ops behave (registry sanitize, Security Center,
       file attributes, USB listener fallback).
    5. Real-time watch: when pyinotify is installed, start a watch on a temp
       dir, create a file, expect a MODIFIED/ADDED event, then a clean stop.
    6. CPU meter returns a sane percentage over a short busy loop.
    7. Autostart round-trip against a temporary XDG_CONFIG_HOME.
    8. Watcher + immunizer wiring (polling backend; ``external_drive_details``
       structure; ``immunize`` on a temp drive).

Exit code 0 = PASS on the checks that apply to this host.  Optional-backend
checks that cannot run (no pyinotify / pyudev) are reported as SKIP, not
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
from secudrive.platform.linux_provider import LinuxProvider  # noqa: E402

check("all core modules import", True)
build_parser()

is_linux = os.name == "posix" and sys.platform.startswith("linux")
provider = get_provider()
if is_linux:
    from secudrive.platform.linux_provider import _HAVE_PYINOTIFY, _HAVE_PYUDEV
    check("get_provider -> LinuxProvider", isinstance(provider, LinuxProvider))
    check("provider.system() == Linux", provider.system() == "Linux")
else:
    from secudrive.platform import linux_provider as lp
    provider = lp.LinuxProvider()


# --------------------------------------------------------------------------
# 3. drive discovery contract
print("[2] drive discovery")
lp_provider = provider if is_linux else lp.LinuxProvider()

# volume_root letter/mount mapping
root_d = lp_provider.volume_root("D")
check("volume_root('D') == 'D:\\\\'", root_d == "D:\\")
if not is_linux:
    skip("volume_root mount passthrough", "not on Linux")

letters = lp_provider.all_letters()
check("all_letters() returns list", isinstance(letters, list))
logical = lp_provider.logical_drive_strings()
check("logical_drive_strings() returns list", isinstance(logical, list))

if is_linux:
    fixed = lp_provider.fixed_drive_paths()
    check("fixed_drive_paths contains '/'", "/" in fixed)
    check("external excludes boot device",
          lp_provider.system_drive_letter() == "/"
          and not any(m == "/" for m in lp_provider.external_drive_paths()))
    rem = lp_provider.removable_drive_paths()
    for m in rem:
        check(f"removable under auto-mount root: {m}",
              m.rstrip("/").startswith(("/media", "/run/media", "/mnt")))
else:
    skip("real mount assertions", "not on Linux")

kind = lp_provider.drive_kind("/")
check("drive_kind('/') is a known label",
      kind in ("External SSD/HDD (Fixed)", "USB Flash (Removable)", "Unknown"))
check("drive_display ends with kind", lp_provider.drive_display("/").endswith(kind))
label = lp_provider.drive_volume_label("/")
check("drive_volume_label('/') is str/None/''",
      label is None or isinstance(label, str))
check("is_valid_drive_root('/') True", lp_provider.is_valid_drive_root("/"))
if is_linux:
    check("is_valid_drive_root('C:\\') False (no such mount on Linux)",
          lp_provider.is_valid_drive_root("C:\\") is False)

# --------------------------------------------------------------------------
# 4. base-delegated no-ops
print("[3] base-delegated capability no-ops")
check("file_attributes_supported() is False", lp_provider.file_attributes_supported() is False)
try:
    lp_provider.get_file_attrs("/tmp")
    check("get_file_attrs raises OSError", False)
except OSError:
    check("get_file_attrs raises OSError", True)
except Exception as exc:
    check("get_file_attrs raises OSError (only)", False, repr(exc))
reg = lp_provider.sanitize_registry_autostarts("X", dry_run=True)
check("registry sanitize is a no-op report", reg.get("action") == "registry_sanitize")
wsc = lp_provider.register_security_center()
check("WSC register ok=False", wsc.get("ok") is False)
st = lp_provider.security_center_status()
check("WSC status windows=False", st.get("windows") is False)
check("usb_listener backend low-latency or polling",
      isinstance(lp_provider.usb_listener_available(), bool))

# --------------------------------------------------------------------------
# 5. real-time watch (optional backend)
print("[4] real-time watch")
if not is_linux:
    check("rt_watch_available() is bool", isinstance(lp_provider.rt_watch_available(), bool))
    skip("pyinotify live watch", "not on Linux")


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


if lp_provider.rt_watch_available():
    tmpdir = tempfile.mkdtemp(prefix="secudrive-rt-")
    try:
        mon = _StubMonitor()
        session = lp_provider.create_watch_session(mon, tmpdir)
        session.start()
        time.sleep(0.4)
        probe = os.path.join(tmpdir, "probe.bin")
        with open(probe, "wb") as fh:
            fh.write(b"x" * 16)
        deadline = time.time() + 5.0
        while time.time() < deadline and not mon.events:
            time.sleep(0.1)
        check("pyinotify event captured", bool(mon.events), repr(mon.events[:3]))
        session.stop()
        check("session ended callback fired",
              isinstance(getattr(mon, "ended", 0), int) and mon.ended >= 1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
else:
    skip("pyinotify live watch", "pyinotify not installed")

# --------------------------------------------------------------------------
# 6. CPU meter
print("[5] CPU meter")
start = time.monotonic()
busy = 0.0
while time.monotonic() - start < 0.3:
    busy += 1.0
p1 = lp_provider.sample_cpu_percent()
time.sleep(0.25)
p2 = lp_provider.sample_cpu_percent()
check("sample_cpu_percent() >= 0", p1 >= 0.0 and p2 >= 0.0,
      f"samples {p1:.2f} {p2:.2f}")

# --------------------------------------------------------------------------
# 7. autostart round-trip (redirected XDG dirs)
print("[6] autostart")
hold_xdg = os.environ.get("XDG_CONFIG_HOME")
try:
    tmp_cfg = tempfile.mkdtemp(prefix="secudrive-xdg-")
    os.environ["XDG_CONFIG_HOME"] = tmp_cfg
    check("autostart_enabled() False initially",
          lp_provider.autostart_enabled() is False)
    check("set_autostart(True)", lp_provider.set_autostart(True) is True)
    check("autostart_enabled() True after enable",
          lp_provider.autostart_enabled() is True)
    check("set_autostart(False)", lp_provider.set_autostart(False) is True)
    check("autostart_enabled() False after disable",
          lp_provider.autostart_enabled() is False)
    f = lp_provider._autostart_file()
    check("desktop file gone after disable", not f.exists())
finally:
    if hold_xdg is None:
        os.environ.pop("XDG_CONFIG_HOME", None)
    else:
        os.environ["XDG_CONFIG_HOME"] = hold_xdg
    shutil.rmtree(tmp_cfg, ignore_errors=True)

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
    print(f"LINUX SMOKE: FAIL ({len(failures)} failures, {ok_count} passed,"
          f" {len(skips)} skipped)")
    for name in failures:
        print("   -", name)
    sys.exit(1)
print(f"LINUX SMOKE: PASS ({ok_count} passed, {len(skips)} skipped)")
sys.exit(0)