#!/usr/bin/env python3
"""test_notification_center.py - P4 regression: per-item notification removal +
clear-all work, and NO bell action (view / remove / clear-all) can ever flip the
quarantine row of a disinfected item back to 'Quarantined' - every bell action
re-reads the LIVE database.
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

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

CHECKS: list = []


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def main() -> int:
    from secudrive.notifications import KIND_QUARANTINE, NotificationStore
    from secudrive.database import Database
    import tempfile as _t
    from pathlib import Path as _P

    base = _P(_t.mkdtemp(prefix="secudrive-notif-"))
    db = Database(base / "secudrive.db")
    store = NotificationStore(db)

    print("1. store-level remove / clear-all")
    store.push(KIND_QUARANTINE, "One", "a", {"uid": "x1"})
    store.push("info", "Two", "b", {"uid": "x2"})
    store.push("info", "Three", "c", {"uid": "x3"})
    check("seeded 3 notifications", len(store.list(10)) == 3, str(len(store.list(10))))
    nid = store.list(10)[0]["id"]
    store.remove(nid)
    check("remove() drops exactly one row", len(store.list(10)) == 2)
    check("removed nid absent",
          all(n["id"] != nid for n in store.list(10)))
    store.push("info", "Four", "d", {})
    store.clear_all()
    check("clear_all() empties the store", len(store.list(10)) == 0)
    check("unread_count after clear == 0", store.unread_count() == 0)

    print("2. bell actions never revert a disinfected item's status")
    QMessageBox.information = staticmethod(lambda *a, **k: None)  # headless
    app = QApplication.instance() or QApplication([])
    from secudrive.gui import (RuntimeContext, MainWindow, apply_dark_theme,
                               _disinfect_quarantined)
    ctx = RuntimeContext(base)
    for k, v in (("auto_scan_on_startup", False), ("auto_sigs_on_startup", False),
                 ("auto_action_policy", "off"), ("rt_enabled", False),
                 ("usb_auto_clean", False)):
        ctx.cfg.set(k, v)
    ctx.cfg.save()
    apply_dark_theme(app)
    win = MainWindow(ctx, base)
    engine = ctx.ensure_engine()
    f = _P(ctx.cfg.base_dir) / "v.jpg"
    f.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100 + b"\xff\xd9"
                  + b"\x00" * 4000)
    q = engine.quarantine_file(f, "TrailingPayload")
    uid = q["uid"]
    rec = _disinfect_quarantined(engine, uid)     # the 'Disinfect' button path
    check("item disinfected (stripped)",
          rec.get("status") in ("stripped", "disinfected"), str(rec.get("status")))
    check("row status now Restored",
          ctx.db.get_quarantine(uid)["status"] == "restored")

    page = win.quarantine
    page.refresh()
    win.notifications.push(KIND_QUARANTINE, "Disinfected", "v.jpg", {"uid": uid})
    win.notifications.push("info", "Chaff", "", {})
    nid2 = [n["id"] for n in win.notifications.list(10)
            if n["kind"] == KIND_QUARANTINE][0]

    def status_text() -> str:
        from PyQt6.QtCore import Qt
        for r in range(page.table.rowCount()):
            cell = page.table.item(r, 0)
            if cell and cell.data(Qt.ItemDataRole.UserRole) == uid:
                return page.table.item(r, 3).text()
        return "<absent>"

    before = status_text()
    win.bell._handle(nid2)                        # VIEW the notification
    after_view = status_text()
    check("viewing does not revert status",
          after_view == "Restored", f"before={before!r} after_view={after_view!r}")
    check("item row still present on quarantine page",
          ctx.db.list_quarantine() != [])

    nid3 = [n["id"] for n in win.notifications.list(10)
            if n["kind"] == KIND_QUARANTINE][0]
    win.bell._remove_one(nid3)                    # REMOVE the notification
    after_remove = ctx.db.get_quarantine(uid)["status"]
    check("removing the notification leaves status Restored",
          after_remove == "restored", str(after_remove))
    win.bell._clear_all()                          # CLEAR ALL
    after_clear = ctx.db.get_quarantine(uid)["status"]
    check("clear-all leaves status Restored",
          after_clear == "restored", str(after_clear))
    check("no notifications remain after clear-all",
          win.notifications.unread_count() == 0 and len(win.notifications.list(10)) == 0)

    win.close()
    print(f"\nNotification center: {sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())