#!/usr/bin/env python3
"""test_ux_features.py - automated coverage of the GUI UX deliverable:
Findings Results viewer, persistent Notification Center, and the live
per-item Quarantine status states.

Runs headless (QT_QPA_PLATFORM=offscreen) against a throwaway temp base so it
never touches the user's real database, backups or quarantine store.  Signs
are: findings rows persisted under a scan_id, notification history that
survives app "restart" (a second MainWindow over the same RuntimeContext),
and the real Restore/Disinfect/Delete engine path with per-item status
transitions wired through ItemActionWorker.

Covered checklist:
  1. auto/background scan findings are viewable from the Dashboard "Last scan"
     card AND the activity-feed entry (both after navigation).
  2. Notification history survives an app restart (second window instance
     over the same db/config base).
  3. Restore of multiple items in one batch shows independent per-item live
     progress and per-item final statuses (no single global spinner).
  4. Every toast is also logged in-app (bell badge reflects unread count from
     the persistent store).
  5. Two consecutive real full ScanWorker cycles run back-to-back without the
     "wrapped C/C++ object of type ScanWorker has been deleted" crash.
"""
import json
import os
import sys
import tempfile
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from PyQt6.QtWidgets import QApplication  # noqa: E402

from secudrive.logging_utils import setup_logging  # noqa: E402

setup_logging(level=50)

_FINDING = {
    "path": r"C:\evil\payload.exe", "category": "signature",
    "name": "EICAR-Test", "confidence": 0.97,
    "evidence": "matched EICAR signature", "size": 68, "sha256": "x" * 64,
}


def _spin(q, cond, timeout_ms=20000):
    """Run the Qt event loop until cond() is truthy or timeout.

    The watchdog timer is stopped once the spin ends so a leftover timer (a
    previous window that was close()d but not destroyed) can never fire a
    stray exit() into a later exec() call.
    """
    from PyQt6.QtCore import QTimer

    class _Loop(QTimer):
        def __init__(self):
            super().__init__()
            self.elapsed = 0
            self.timeout.connect(self._check)
            self.start(50)

        def _check(self):
            self.elapsed += 50
            if cond():
                QApplication.instance().exit(0)
            elif self.elapsed >= timeout_ms:
                QApplication.instance().exit(2)
    # tied to q so the wrapper + event connection outlive exec()
    q._spin_timer = _Loop()
    q._spin_timer.setParent(q)
    try:
        return QApplication.instance().exec()
    finally:
        q._spin_timer.stop()
        q._spin_timer.deleteLater()
        q._spin_timer = None


def _build_win():
    from secudrive.gui import RuntimeContext, MainWindow, apply_dark_theme
    base = tempfile.mkdtemp(prefix="uxbt_")
    ctx = RuntimeContext(base)
    # keep windows inert: no auto-scan / auto-update timers firing during tests
    ctx.cfg.set("auto_scan_on_startup", False)
    ctx.cfg.set("auto_sigs_on_startup", False)
    ctx.cfg.set("auto_action_policy", "off")
    ctx.cfg.set("rt_enabled", False)
    ctx.cfg.set("usb_auto_clean", False)
    ctx.cfg.save()
    apply_dark_theme(QApplication.instance())
    win = MainWindow(ctx, base)
    return ctx, win


def _synthetic_auto_scan(win, scan_id):
    """Persist a findings row + scan summary the way autopilot would, then
    fire the exact GUI handlers autopilot calls on completion."""
    db = win.ctx.db
    db.record_findings(scan_id, [dict(_FINDING, path=r"C:\evil\auto1.exe")])
    stats = {
        "scan": {"scan_id": scan_id, "files": 3, "dirs": 1,
                 "errors": [], "findings": 1, "targets": [r"C:\evil"],
                 "persisted": 1},
        "errors": [], "disinfected": 0, "quarantined": 0,
        "attribs_fixed": 0, "duration_s": 0.4,
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    win._on_auto_finished(stats)
    return stats


def main() -> int:
    ctx = QApplication.instance() or QApplication([])

    # ---------------------------------------------------------------- (1) feed
    ctx_base, win = _build_win()
    scan_id = "autoUX" + uuid.uuid4().hex[:8]
    _synthetic_auto_scan(win, scan_id)

    # Dashboard "Last scan" card reflects the finished auto-scan.
    win.dashboard.refresh()
    lbl = win.dashboard.last_scan_meta.text()
    assert "1 finding(s)" in lbl, f"dashboard card missing findings: {lbl!r}"
    assert win.dashboard._last_scan_meta[0] == scan_id, "card scan_id wrong"
    assert win.dashboard.btn_view_results.isEnabled(), "View Results disabled"
    print("1a. Dashboard 'Last scan' card shows auto-scan findings -> PASS")

    # Navigation: open from the Dashboard card.
    win.dashboard._open_last_scan()
    viewer = win._active_viewer
    assert viewer is not None and len(viewer._findings) == 1, "viewer empty"
    assert viewer._findings[0]["name"] == "EICAR-Test"
    viewer.close()
    print("1b. Dashboard card opens Findings Results viewer -> PASS")

    # Feed entry carries the scan payload; click-route opens the same viewer.
    feed = win.dashboard.activity
    assert feed.listw.count() >= 1, "feed has no scan event"
    top = feed.listw.item(0)
    assert top.toolTip() == "Click to view details", "feed entry not clickable"
    payload = top.data(0x0100)   # Qt.UserRole
    assert isinstance(payload, dict) and payload.get("scan_id") == scan_id
    win._open_feed_findings(payload)
    assert win._active_viewer is not None, "feed route did not open viewer"
    win._active_viewer.close()
    print(f"1c. Activity-feed scan entry opens Findings viewer "
          f"({feed.listw.count()} events) -> PASS")

    # -------------------------------------------------------------- (2) restart
    # A second window over the SAME RuntimeContext simulates app restart:
    # notification history must still be there (persisted in secudrive.db).
    win.notifications.push("scan", "Pre-restart scan", "keep me",
                           {"scan_id": scan_id})
    saved = win.notifications.list(limit=5)
    assert any(n.get("title") == "Pre-restart scan" for n in saved), "no save"

    from secudrive.gui import MainWindow as MW2
    from secudrive.gui import apply_dark_theme as _theme
    _theme(ctx)
    win2 = MW2(win.ctx, None)
    after = win2.notifications.list(limit=5)
    assert any(n.get("title") == "Pre-restart scan" for n in after), \
        "notification lost across restart"
    payload_kept = next(n for n in after if n.get("title") == "Pre-restart scan")
    assert payload_kept.get("payload", {}).get("scan_id") == scan_id, \
        "payload not preserved"
    # unread count is surfaced by the bell badge
    win2.bell.refresh()
    badge = win2.bell.text()
    assert "🔔" in badge and win2.notifications.unread_count() > 0, badge
    print(f"2. Notification history survives app restart "
          f"(bell badge {badge!r}) -> PASS")
    win2.close()
    win.close()

    # ---------------------------------------------------- (3) per-item restore
    ctx3, win3 = _build_win()
    win3.ctx.ensure_engine()
    engine = win3.ctx.engine
    work_dir = Path(win3.ctx.cfg.base_dir) if hasattr(win3.ctx.cfg, "base_dir") \
        else Path(ctx3.cfg.base_dir)
    uid_to_file = {}
    for idx in range(3):
        p = work_dir / f"restore{idx}.exe"
        p.write_bytes(b"PROG" + b"\x00" * 64 + b"PAYLOADX" * 4)
        rec = engine.quarantine_file(p, f"EICAR-{idx}")
        assert rec.get("status") == "quarantined", rec
        uid_to_file[rec["uid"]] = p
    q = win3.quarantine
    q.refresh()
    assert q.table.rowCount() == 3, f"expected 3 rows, got {q.table.rowCount()}"

    # multi-select all three
    sel = q.table.selectionModel()
    for r in range(q.table.rowCount()):
        sel.select(q.table.model().index(r, 0),
                   sel.SelectionFlag.Select | sel.SelectionFlag.Rows)
    uids = q._selected_rows()
    assert len(uids) == 3 and all(len(u) == 32 for u in uids), \
        "uid truncation regression (must be full 32-hex uids)"
    assert set(uids) == set(uid_to_file), "uid mapping lost"

    # collect status transitions per item as the batch streams
    seen = {}
    orig = q._on_item_status
    def watch(uid, info):
        seen.setdefault(uid, set()).add(info.get("state"))
        orig(uid, info)
    q._on_item_status = watch

    q._run_verb("restore", "Restore")
    assert q._busy, "busy map not populated"
    rc = _spin(q, cond=lambda: (not q._busy and q._worker is None))
    assert rc == 0, f"restore batch did not finish (rc={rc})"
    # every item independently went running -> done
    assert all(s == {"running", "done"} for s in seen.values()), seen
    # db statuses settled to restored, files are back on disk
    for um, p in uid_to_file.items():
        row = win3.ctx.db.get_quarantine(um)
        assert row["status"] == "restored", (um, row["status"])
        assert p.exists(), f"restored file missing: {p}"
    assert "succeeded" in q.status_label.text(), q.status_label.text()
    print(f"3. Restore x3 concurrent with per-item statuses "
          f"({len(seen)} items running→done) -> PASS")

    # session filter: drop finished rows from the list (re-select them first;
    # the batch's refresh() cleared the old selection)
    sel3 = q.table.selectionModel()
    for r in range(q.table.rowCount()):
        sel3.select(q.table.model().index(r, 0),
                    sel3.SelectionFlag.Select | sel3.SelectionFlag.Rows)
    q._remove_selected_finished()
    assert q.table.rowCount() == 0, "finished rows not removable"
    q._clear_finished_rows()
    assert q.table.rowCount() == 0, \
        "clear-finished wrongly un-hid rows (must keep terminal rows hidden)"
    print("3b. 'Remove finished from list' drops restored rows; "
          "'Clear finished rows' keeps terminal rows hidden "
          "(view-only, rows stay in the DB) -> PASS")

    # --------------------------------------------------- (4) toast -> in-app
    win3._notify("Toast check", "this must also land in-app", kind="scan",
                 payload={"scan_id": scan_id})
    rows = win3.notifications.list(limit=3)
    assert any(n.get("title") == "Toast check" for n in rows), "toast not logged"
    print(f"4. Toast always also persisted in-app "
          f"({win3.notifications.unread_count()} unread) -> PASS")

    # 4b. Clicking a notification marks it read AND navigates to the right
    #     view (payload is JSON-decoded exactly once by the DB layer; the bell
    #     must NOT re-parse it or navigation silently dies).
    nid = next(n["id"] for n in rows if n.get("title") == "Toast check")
    win3.bell._handle(nid)
    assert win3._active_viewer is not None, \
        "notification click did not open the scan's Findings viewer"
    win3._active_viewer.close()
    clicked = win3.notifications.get(nid)
    assert clicked is not None and clicked.get("read") == 1, \
        "notification click did not mark the entry read"
    print("4b. Notification click marks read + navigates to target view -> PASS")

    win3.close()

    # --------------------------------------------- (5) consecutive real scans
    # Regression for "wrapped C/C++ object of type ScanWorker has been deleted":
    # finishing a scan used to deleteLater() the QThread while scanner_page.worker
    # still referenced it, so the NEXT start_scan() crashed inside
    # self.worker.isRunning(). Two full scan cycles must run back-to-back.
    ctx5, win5 = _build_win()
    work5 = Path(win5.ctx.cfg.base_dir)
    for i in range(4):
        (work5 / f"data{i}.dat").write_bytes(b"x" * (32 + i))
    from secudrive.scanner import ScanOptions
    opts = ScanOptions()
    opts.max_depth = 2

    win5.scanner_page.start_scan([str(work5)], opts, label="crash-reg-1")
    rc = _spin(win5, cond=lambda: win5.scanner_page.worker is None)
    assert rc == 0, "first scan did not finish"
    assert win5.scanner_page.worker is None, "worker ref not released"

    win5.scanner_page.start_scan([str(work5)], opts, label="crash-reg-2")
    # wait for full release: worker ref nulled AND the native QThread finished
    # signal drained from _workers (queued after the wrapper finished_sig)
    rc = _spin(win5, cond=lambda: not win5._workers)
    assert rc == 0, f"second scan crashed/failed (rc={rc})"
    assert win5.scanner_page.worker is None
    assert not win5._workers, "tracked workers not released"

    win5.scanner_page._stop()   # no-op path must be safe after completion
    win5.close()
    print("5. Consecutive real scans recycle ScanWorker without "
          "deleted-C++ crash -> PASS")

    # ------------------------------------- (6) hotplug race: scan-in-progress
    # A second scan request fired while one is running (the hotplug path) must
    # (a) NEVER touch or replace the in-flight worker -> it is QUEUED, and
    # (b) auto-start once the current scan's QThread has truly finished and
    #     its wrapper was dropped.  Also: a scan request right after a finish
    #     must not raise RuntimeError from a freshly-deleted C++ object.
    ctx6, win6 = _build_win()
    work6 = Path(win6.ctx.cfg.base_dir)
    for i in range(3):
        (work6 / f"plug{i}.dat").write_bytes(b"x" * (32 + i))
    from secudrive.scanner import ScanOptions
    opts6 = ScanOptions()
    opts6.max_depth = 2

    q6 = win6.scanner_page
    # (a) kick scan #1, then fire the "new drive plugged" scan request WHILE
    #     scan #1 is still running.
    q6.start_scan([str(work6)], opts6, label="hotplug-1")
    first = q6.worker
    assert first is not None and first.isRunning(), "scan #1 should be running"
    q6.start_scan([str(work6)], opts6, label="hotplug-2")   # hotplug while busy
    # in-flight worker must be untouched; the new request is queued, not run
    assert q6.worker is first, "queue-on-conflict replaced the in-flight worker!"
    assert first.isRunning(), "in-flight worker was interrupted"
    assert len(q6._pending_scans) == 1, q6._pending_scans
    q6._stop()                       # guarded read: must not raise on live worker
    rc = _spin(win6, cond=lambda: q6.worker is None)
    assert rc == 0, f"hotplug scans did not drain (rc={rc})"
    assert not q6._pending_scans, "queued scan not consumed"
    assert not win6._workers, "tracked workers not fully released"
    # (b) immediate rescan right after a completed+dropped scan (the original
    #     deleted-C++ repro: finished -> deleteLater -> start_scan() read).
    q6.start_scan([str(work6)], opts6, label="hotplug-3")
    rc = _spin(win6, cond=lambda: q6.worker is None)
    assert rc == 0, f"post-finish rescan crashed/failed (rc={rc})"
    assert not win6._workers
    q6._stop()
    win6.close()
    print("6. Hotplug while scanning: queue-on-conflict + post-finish rescan "
          "race  -> PASS")

    print("\n---------------------------------------------")
    print("UX FEATURES CHECKLIST: PASS (all 5 scenarios)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # keep traceback meaningful on failure
        print(f"\nUX FEATURES CHECKLIST: FAIL ({exc})", file=sys.stderr)
        raise