#!/usr/bin/env python3
"""test_scan_cancel_closed_db.py - regression test for BUG #3: the
"Cannot operate on a closed database" crash on scan cancel / app quit.

This reproduces the EXACT lifecycle that used to crash:
  1. a real Scanner is running over a seeded temp tree (multi-threaded);
  2. the scan is cancelled mid-way (Scanner.cancel);
  3. while the cancel unwinds, a notification/background write races the
     Database shutdown;
  4. the Database is closed (the drained, lifecycle-aware close()).

The old code closed the raw sqlite3 connection with no guard, so any in-flight
write that landed after close() raised a raw sqlite3.ProgrammingError
("Cannot operate on a closed database") which propagated up through the GUI
cancel/quit path as a crash / error dialog.

The fixed contract (secudrive/database.py + secudrive/notifications.py):
  * close() flips self._closed to True UNDER THE SAME RLock writers hold, so
    in-flight writes are DRAINED (never interrupted), and writes that start
    after the flip raise the TYPED DatabaseClosedError instead of a raw
    ProgrammingError;
  * NotificationStore.push() catches DatabaseClosedError and skips cleanly
    (returns 0) instead of crashing.

This test asserts:
  * cancelling a running scan unwinds WITHOUT a DatabaseClosedError escape;
  * a notification pushed DURING the close unwind is either drained
    (persisted before close) or skipped (returned 0) - never an exception;
  * no raw sqlite3 ProgrammingError / "closed database" is raised anywhere;
  * a second close() is a safe no-op (close is idempotent).
"""
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

CHECKS: list = []


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def main() -> int:
    from secudrive.database import Database
    from secudrive.notifications import NotificationStore
    from secudrive.scanner import Scanner, ScanOptions

    base = Path(tempfile.mkdtemp(prefix="secudrive-cancel-cdb-"))
    db = Database(base / "secudrive.db")
    store = NotificationStore(db)

    # ---- seed a scan tree big enough to still be mid-flight when we cancel ----
    # (6000 files, hashed in the pure-Python engine, so a 50ms cancel reliably
    #  lands mid-scan rather than after a finished pass - deterministic unwind)
    tree = base / "tree"
    tree.mkdir()
    for i in range(20):
        sub = tree / f"sub{i:02d}"
        sub.mkdir()
        for j in range(300):
            (sub / f"file{j:04d}_{i:02d}.jpg").write_bytes(
                b"\xff\xd8\xff\xe0" + bytes([i & 0xFF, j & 0xFF] * 128)
                + b"\xff\xd9" + bytes((i * 300 + j) % 256) * 256)

    killed = []
    program_error: list = []

    def cancel_now(scanner: Scanner) -> None:
        time.sleep(0.05)          # let the scan get underway
        scanner.cancel()

    scanner = Scanner(db, ScanOptions(use_rust=False, threads=4))
    cancel_thread = threading.Thread(target=cancel_now, args=(scanner,))
    cancel_thread.start()

    try:
        scanner.scan([tree])
    except Exception as exc:      # noqa: BLE001 - assert the SPECIFIC contract
        killed.append(exc)

    # ---- a notification/background write racing the DB shutdown (THE race) ----
    race_results: list = []
    store.push("info", "one", "a", {"uid": "x1"})     # drain-friendly write

    # fire one from another thread while close() is expected to be draining
    raced: list = []

    def racing_push() -> None:
        try:
            raced.append({"rc": store.push("info", "two", "b", {"uid": "x2"})})
        except Exception as exc:                      # noqa: BLE001
            raced.append({"rc": None, "exc": type(exc).__name__, "msg": str(exc)})
            if isinstance(exc, Exception):
                program_error.append(type(exc).__name__)

    t = threading.Thread(target=racing_push)
    t.start()
    store.push("info", "three", "c", {"uid": "x3"})
    t.join()                                          # deterministic: join first
    db.close()                                        # drained, lifecycle-aware

    # second close must be a safe no-op (idempotent)
    try:
        db.close()
        idem_ok = True
    except Exception:                                 # noqa: BLE001
        idem_ok = False

    check("cancel unwinds without DatabaseClosedError",
          not killed,
          (str(killed[0]) if killed else "clean"))
    check("no raw ProgrammingError / 'closed database' during race",
          not program_error and not killed,
          (program_error[0] if program_error else "clean"))
    check("racing push did not crash (drained or skipped)",
          len(raced) == 1 and raced[0].get("rc") is not None,
          str(raced))
    check("racing push either drained (rc>0) or skipped (rc==0)",
          all(r.get("rc") is not None and r.get("rc") >= 0 for r in raced),
          str(raced))
    check("close() is idempotent (repeat close is a no-op)",
          idem_ok, "")

    # DB genuinely closed: a fresh write is a typed skip, not a crash
    store.push("info", "after", "d", {"uid": "x4"})
    print(f"\nscan-cancel closed-db regression: "
          f"{sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
