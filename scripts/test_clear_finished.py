#!/usr/bin/env python3
"""test_clear_finished.py - P3 regression: 'Clear finished rows' must hide ONLY
rows whose LIVE DB status is terminal (restored/deleted/disinfected/purged).
Quarantined / failed rows must NEVER be hidden, and nothing may be deleted from
secudrive.db or the backups - the action is view-only for the session.
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
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402

CHECKS: list = []
_WARNED: list = []


def _nop_info(parent, title: str, text: str = "") -> None:
    _WARNED.append(text or title)


QMessageBox.information = staticmethod(_nop_info)  # noqa: SLF001


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def _visible_rows(page) -> list:
    return [str(page.table.item(r, 0).data(Qt.ItemDataRole.UserRole) or "")
            for r in range(page.table.rowCount())]


def main() -> int:
    app = QApplication.instance() or QApplication([])

    from secudrive.gui import RuntimeContext, MainWindow, apply_dark_theme

    base = tempfile.mkdtemp(prefix="secudrive-clearfin-")
    ctx = RuntimeContext(base)
    ctx.cfg.set("auto_scan_on_startup", False)
    ctx.cfg.set("auto_sigs_on_startup", False)
    ctx.cfg.set("auto_action_policy", "off")
    ctx.cfg.set("rt_enabled", False)
    ctx.cfg.set("usb_auto_clean", False)
    ctx.cfg.save()
    apply_dark_theme(app)
    win = MainWindow(ctx, base)
    engine = ctx.ensure_engine()
    page = win.quarantine

    # ---- seed: restored + purged + deleted + quarantined + failed ----------
    rows = {}
    for name, title in [("a.exe", "restored"), ("b.exe", "purged"),
                        ("c.exe", "deleted"), ("d.exe", "quarantined"),
                        ("e.exe", "failed")]:
        f = Path(ctx.cfg.base_dir) / name
        f.write_bytes(b"MZ" + b"\x00" * 40)
        q = engine.quarantine_file(f, f"SIG-{name}")
        uid = q["uid"]
        if title == "restored":
            engine.restore_item(uid)
        elif title == "purged":
            engine.purge_item(uid)
        elif title == "deleted":
            ctx.db.set_quarantine_status(uid, "deleted")
        elif title == "failed":
            ctx.db.set_quarantine_status(uid, "failed")
        rows[name] = uid

    all_uids = set(rows.values())
    db_total = len(ctx.db.list_quarantine())
    check("seeded 5 rows in DB", db_total == 5, str(db_total))

    # ---- Clear finished rows: only terminal-status rows vanish from view ----
    print("Clear finished rows (view-only, terminal statuses only)")
    page.refresh()
    check("all 5 rows shown before clear",
          page.table.rowCount() == 5, str(page.table.rowCount()))
    page._clear_finished_rows()
    shown = _visible_rows(page)
    hidden_terminal = {rows["a.exe"], rows["b.exe"], rows["c.exe"]}
    kept = {rows["d.exe"], rows["e.exe"]}
    check("restored/purged/deleted hidden", hidden_terminal.isdisjoint(shown))
    check("quarantined + failed KEPT visible", kept.issubset(shown),
          str(sorted(shown)))
    check("non-terminal rows still in DB",
          all(any(x["uid"] == u for x in ctx.db.list_quarantine()) for u in kept))
    check("terminal rows still in DB (nothing deleted)",
          {x["uid"] for x in ctx.db.list_quarantine()} == all_uids)

    # ---- reset the session filter, then remove-selected --------
    page._finished_filter.clear()
    page.refresh()
    check("reset filter -> 5 rows again", page.table.rowCount() == 5)

    # select the RESTORED row and 'Remove finished from list'
    def _select(uid: str) -> None:
        for r in range(page.table.rowCount()):
            if page.table.item(r, 0).data(Qt.ItemDataRole.UserRole) == uid:
                rect = page.table.visualItemRect(page.table.item(r, 0))
                QTest.mouseClick(page.table.viewport(),
                                 Qt.MouseButton.LeftButton,
                                 Qt.KeyboardModifier.NoModifier,
                                 rect.center() if not rect.isNull() else None)
                return

    _select(rows["a.exe"])
    page._remove_selected_finished()
    shown = _visible_rows(page)
    check("selected restored row removed", rows["a.exe"] not in shown)
    check("quarantined still visible after remove-selected",
          rows["d.exe"] in shown)

    # ---- selecting a QUARANTINED row must NOT hide it ----------------------
    check("no earlier warn yet", not _WARNED)
    _select(rows["d.exe"])
    page._remove_selected_finished()
    shown = _visible_rows(page)
    check("quarantined row kept after remove-selected", rows["d.exe"] in shown)
    check("non-finished warning shown", any("not finished" in w for w in _WARNED),
          str(_WARNED[:1]))

    # ---- destructive semantics: encrypted backups survive every clear ------
    kept_rows = [r for r in ctx.db.list_quarantine()
                 if r["status"] not in ("purged",)]
    live_backups = [Path(r["backup_path"]).exists() for r in kept_rows]
    check("kept items' encrypted backups still on disk", all(live_backups))

    win.close()
    print(f"\nClear-finished regression: {sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())