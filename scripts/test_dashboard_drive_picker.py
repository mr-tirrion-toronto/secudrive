#!/usr/bin/env python3
"""test_dashboard_drive_picker.py - P3 regression: the Dashboard must again
offer the per-drive picker, exactly like ScannerPage, and honor it on scan.

Earlier fix restored the dropdown into DashboardPage's action row, but left the
populate/current helpers defined ONLY on ScannerPage.  So:

  * constructing the Dashboard crashed with
      AttributeError: 'DashboardPage' object has no attribute
      '_populate_drive_combo'
    (the combo widget + _populate_drive_combo() call were added to
    DashboardPage.__init__ with no matching method on that class);
  * and even had it built, every Quick/Full scan launched from the Dashboard
    silently scanned ALL drives, ignoring the (empty) pick.

This test locks in the restored contract:

  1. DashboardPage OWNS its combo (self.drive_combo) and populates it via a
     Dashboard-owned _populate_drive_combo():
       * row 0 is the "All drives" sentinel carrying NO item data;
       * one row per external drive carrying the drive PATH as item data and a
         tooltip (path + volume label), mirroring ScannerPage's picker.
  2. _current_drive_combo() returns None on the sentinel and the picked path
     otherwise.
  3. Re-population preserves the currently picked drive.
  4. _start_scan honors the pick: a picked drive sends EXACTLY [picked] for
     both Quick and Full; "All drives" falls back to the quick/full target
     lists.

Runs headless (offscreen) against a throwaway temp base.  The drive helpers
(external_drive_paths / drive_display / drive_volume_label / quick_scan_targets
/ full_scan_targets) are stubbed with deterministic fakes so the result is the
same on any machine; ScannerPage.start_scan is replaced with a capture-only
stub so no scan ever really starts.
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from PyQt6.QtWidgets import QApplication  # noqa: E402

CHECKS: list = []


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def main() -> int:
    import secudrive.systemutils as su_mod
    from secudrive.gui import (MainWindow, RuntimeContext, apply_dark_theme)
    from secudrive.gui import ScannerPage as SP

    FAKES = [str(Path("D:/")), str(Path("E:/"))]
    real_ext = su_mod.external_drive_paths
    real_disp = su_mod.drive_display
    real_label = su_mod.drive_volume_label
    real_quick = su_mod.quick_scan_targets
    real_full = su_mod.full_scan_targets
    su_mod.external_drive_paths = lambda: list(FAKES)
    su_mod.drive_display = lambda p: f"Volume-{Path(p).name}: ({p})"
    su_mod.drive_volume_label = lambda p: f"LBL-{Path(p).name}"
    su_mod.quick_scan_targets = lambda: [str(Path("Q:/ans"))]
    su_mod.full_scan_targets = lambda: [str(Path("F:/tot"))]
    try:
        app = QApplication.instance() or QApplication([])
        base = Path(tempfile.mkdtemp(prefix="secudrive-dashpicker-"))
        ctx = RuntimeContext(base)
        for k, v in (("auto_scan_on_startup", False), ("auto_sigs_on_startup", False),
                     ("auto_action_policy", "off"), ("rt_enabled", False),
                     ("usb_auto_clean", False)):
            ctx.cfg.set(k, v)
        ctx.cfg.save()
        apply_dark_theme(app)
        win = MainWindow(ctx, base)
        page = win.dashboard

        # ---- 1. Dashboard owns its own picker, populated identically
        combo = page.drive_combo
        check("dashboard owns drive_combo", combo is not None)
        check("row 0 sentinel 'All drives' carries no data",
              combo.itemText(0) == "All drives" and combo.itemData(0) is None,
              repr(combo.itemText(0)))
        check("one row per external drive",
              combo.count() == 1 + len(FAKES), str(combo.count()))
        check("each drive row carries its path as item data",
              all(str(combo.itemData(i)).upper().replace("\\", "/") in
                  ("D:/", "E:/") for i in range(1, combo.count())),
              str([combo.itemData(i) for i in range(1, combo.count())]))
        check("each drive row carries a path+volume tooltip",
              all(combo.itemData(i) for i in range(1, combo.count())))

        # ---- 2. current-value plumbing
        check("_current_drive_combo() is None on the sentinel",
              page._current_drive_combo() is None, repr(page._current_drive_combo()))
        combo.setCurrentIndex(1)
        check("_current_drive_combo() returns the picked path",
              page._current_drive_combo() == FAKES[0], repr(page._current_drive_combo()))

        # ---- 3. re-population preserves the pick
        page._populate_drive_combo()
        check("re-populate keeps the picked drive",
              page._current_drive_combo() == FAKES[0], repr(page._current_drive_combo()))

        # ---- 4. _start_scan honors the pick vs the fallback lists
        captured: list = []
        real_start = SP.start_scan

        def fake_start(self, targets, options, label):
            captured.append(([str(t) for t in targets], label))

        SP.start_scan = fake_start
        try:
            combo.setCurrentIndex(1)
            page._start_scan("quick")
            check("Quick Scan with a pick sends exactly [picked]",
                  captured and captured[-1][0] == [FAKES[0]],
                  str(captured[-1] if captured else None))
            page._start_scan("full")
            check("Full Scan with a pick sends exactly [picked]",
                  captured and captured[-1][0] == [FAKES[0]],
                  str(captured[-1] if captured else None))

            combo.setCurrentIndex(0)  # sentinel -> all drives
            page._start_scan("quick")
            check("Quick Scan on 'All drives' uses the quick fallback",
                  captured and captured[-1][0] == [str(Path("Q:/ans"))],
                  str(captured[-1] if captured else None))
            page._start_scan("full")
            check("Full Scan on 'All drives' uses the full fallback",
                  captured and captured[-1][0] == [str(Path("F:/tot"))],
                  str(captured[-1] if captured else None))
        finally:
            SP.start_scan = real_start
        win.close()
    finally:
        su_mod.external_drive_paths = real_ext
        su_mod.drive_display = real_disp
        su_mod.drive_volume_label = real_label
        su_mod.quick_scan_targets = real_quick
        su_mod.full_scan_targets = real_full

    print(f"\nDashboard drive picker: {CHECKS.count(True)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
