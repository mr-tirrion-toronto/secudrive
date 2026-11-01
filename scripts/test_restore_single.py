#!/usr/bin/env python3
"""test_restore_single.py - faithful single-item Quarantine Restore repro.

Simulates EXACTLY what a user does: mouse-click a quarantined row in the
Quarantine table, then click the real "Restore Clean File" button.  Runs the
event loop until the worker drains, then reports DB status + on-disk file.

Debug contract: starts logging with DEBUG so every tagged RESTORE| line in the
click -> _run_verb -> ItemActionWorker -> item_status -> finished_sig ->
_actions_done -> refresh chain is printed to stderr/stdout.  Grep for RESTORE|.
"""
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton  # noqa: E402
from PyQt6.QtCore import QTimer, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402

from secudrive.logging_utils import setup_logging  # noqa: E402

setup_logging(level=10)  # DEBUG

_LOG_MSG: list = []

# never let headless _warn()/_confirm_purge() block on a modal box
def _nop_info(parent, title: str, text: str = "") -> None:
    _LOG_MSG.append(text or title)


QMessageBox.information = staticmethod(_nop_info)  # noqa: SLF001


def _spin(q, cond, timeout_ms=15000):
    from PyQt6.QtCore import QTimer as _T

    class _Loop(_T):
        def __init__(self):
            super().__init__()
            self.elapsed = 0
            self.timeout.connect(self._check)
            self.start(50)

        def _check(self):
            self.elapsed += 50
            if cond() or self.elapsed >= timeout_ms:
                QApplication.instance().exit(0 if cond() else 2)

    loop = _Loop()
    loop.parent = q  # noqa: B010
    rc = QApplication.instance().exec()
    loop.stop()
    loop.setParent(None)
    loop.deleteLater()
    return rc


def main() -> int:
    app = QApplication.instance() or QApplication([])

    from secudrive.gui import RuntimeContext, MainWindow, apply_dark_theme

    base = tempfile.mkdtemp(prefix="secudrive-restore1-")
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
    victim = Path(ctx.cfg.base_dir) / "restore-single.exe"
    victim.write_bytes(b"PROG" + b"\x00" * 64 + b"PAYLOADX" * 4)

    rec = engine.quarantine_file(victim, "EICAR-SINGLE")
    assert rec.get("status") == "quarantined", rec
    uid = rec["uid"]
    print(f"[repro] quarantined uid={uid} original={victim}")
    print(f"[repro] original exists now? {victim.exists()}")

    q = win.quarantine
    q.refresh()
    print(f"[repro] quarantine table rows={q.table.rowCount()}")

    # ---- user action 1: real mouse click on row 0 to select it ----
    rect = q.table.visualItemRect(q.table.item(0, 0))
    print(f"[repro] row0 visual rect={rect}")
    QTest.mouseClick(q.table.viewport(), Qt.MouseButton.LeftButton,
                     Qt.KeyboardModifier.NoModifier,
                     rect.center() if not rect.isNull() else None)
    app.processEvents()
    selected = q._selected_rows()
    print(f"[repro] after mouse click selected={selected}")
    assert len(selected) == 1 and selected[0] == uid, \
        f"mouse-click selection broken: {selected}"

    # ---- user action 2: click the REAL Restore Clean File button ----
    btn = next(b for b in q.findChildren(QPushButton)
               if b.text() == "Restore Clean File")
    print("[repro] clicking Restore Clean File button...")
    btn.click()
    print(f"[repro] after click: _worker={q._worker} _busy={dict(q._busy)}")

    print("[repro] pumping event loop until worker drains...")
    rc = _spin(q, cond=lambda: (q._worker is None and not q._busy))
    print(f"[repro] spin rc={rc} worker={q._worker} busy={dict(q._busy)}")
    app.processEvents()

    row = ctx.db.get_quarantine(uid)
    print(f"[repro] DB row status={row['status']}")
    print(f"[repro] restored file back on disk? {victim.exists()}")
    print(f"[repro] status label: {q.status_label.text()!r}")
    print(f"[repro] _state={q._state}")
    print(f"[repro] _warn dialogs shown: {_LOG_MSG}")

    ok = (row["status"] == "restored" and victim.exists())
    print(f"RESULT: {'PASS - single restore complete' if ok else 'FAIL'}")
    if not ok:
        win.close()
        return 1

    # ---- corrupt-backup scenario: restore must surface a red FAILED ---------
    print("\n[repro] corrupted backup: Restore Clean File must show Failed + reason")
    victim2 = Path(ctx.cfg.base_dir) / "restore-corrupt.exe"
    victim2.write_bytes(b"PROG" + b"\x00" * 64 + b"PAYLOADX" * 4)
    rec2 = engine.quarantine_file(victim2, "EICAR-CORRUPT")
    uid2 = rec2["uid"]
    blob2 = Path(rec2["backup"])
    blob2.write_bytes(b"\x00" * 64)
    print(f"[repro] uid2={uid2} blob smashed at {blob2}")

    q.refresh()
    idx2 = next(i for i in range(q.table.rowCount())
                if (q.table.item(i, 0).data(
                        Qt.ItemDataRole.UserRole)) == uid2)
    rect2 = q.table.visualItemRect(q.table.item(idx2, 0))
    QTest.mouseClick(q.table.viewport(), Qt.MouseButton.LeftButton,
                     Qt.KeyboardModifier.NoModifier,
                     rect2.center() if not rect2.isNull() else None)
    app.processEvents()
    assert q._selected_rows() == [uid2], q._selected_rows()
    seen_states: list = []
    _orig_on_item_status = q._on_item_status

    def _spy(uid, info):
        if uid == uid2:
            _orig_on_item_status(uid, info)
            seen_states.append({"raw": dict(info),
                                "stored": dict(q._state.get(uid2, {}))})
        else:
            _orig_on_item_status(uid, info)

    q._on_item_status = _spy
    btn2 = next(b for b in q.findChildren(QPushButton)
                if b.text() == "Restore Clean File")
    btn2.click()
    rc2 = _spin(q, cond=lambda: (q._worker is None and not q._busy))
    app.processEvents()

    # transient red "Failed" is painted WHILE the batch runs (_on_item_status
    # state=error with the reason); after _actions_done the page re-renders the
    # LIVE DB truth (row stays 'quarantined' - never flipped to a green state).
    error_state = next((s for s in seen_states
                        if s.get("stored", {}).get("status") == "error"), None)
    dialog = "\n".join(_LOG_MSG)
    db2 = ctx.db.get_quarantine(uid2)["status"]
    print(f"[repro] corrupt: seen_states={seen_states}")
    print(f"[repro] corrupt: dialogs={_LOG_MSG}")
    print(f"[repro] corrupt: DB row status={db2!r} file_on_disk={victim2.exists()}")
    ok2 = (rc2 == 0
           and error_state is not None
           and "corrupt" in str(error_state.get("stored", {}).get("err", "")).lower()
           and "corrupt" in dialog.lower()
           and db2 == "quarantined"          # never silently green
           and not victim2.exists())
    print(f"RESULT: {'PASS - corrupt restore fails loudly, row not green' if ok2 else 'FAIL'}")
    win.close()
    return 0 if (ok and ok2) else 1


if __name__ == "__main__":
    sys.exit(main())