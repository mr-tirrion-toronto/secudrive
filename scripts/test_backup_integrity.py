#!/usr/bin/env python3
"""test_backup_integrity.py - P2 regression: encrypted backups must be written
ATOMICALLY (temp -> structural verify -> rename, so a torn write can never
produce an 'implausible frame size' blob), and a corrupted backup must be
reported distinctly (unrecoverable + audit) with no garbage restore artifacts.
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

CHECKS: list = []


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def main() -> int:
    from secudrive.crypto import (backup_file, generate_key, IntegrityError,
                                  restore_backup_file)
    from secudrive.crypto import _verify_blob_headers
    from secudrive.database import Database
    from secudrive.recovery import RecoveryEngine
    from secudrive.safefile import compute_hashes

    base = Path(tempfile.mkdtemp(prefix="secudrive-integrity-"))
    bdir = base / "backups"; bdir.mkdir()
    qdir = base / "quarantine"; qdir.mkdir()
    key = generate_key()
    db = Database(base / "secudrive.db")

    # ---- 1. happy path: atomic single .bak.aes, round-trip exact bytes -----
    print("1. backup_file atomic write + round-trip")
    src = base / "victim.jpg"
    blob_bytes = os.urandom(512 * 1024)
    src.write_bytes(blob_bytes)
    meta = backup_file(src, bdir, key)
    store = Path(meta["store_path"])
    check("exactly one .bak.aes (no .tmp leftover)",
          store.exists() and not list(bdir.glob("*.tmp")))
    out = base / "restored.jpg"
    n = restore_backup_file(store, out, key, expected_sha=meta["sha256"],
                            expected_size=meta["size"])
    check("restore round-trip exact bytes", out.read_bytes() == blob_bytes
          and n == len(blob_bytes), f"{n} bytes")

    # ---- 2. header-walk self-check rejects truncated and garbage frames -----
    print("2. _verify_blob_headers rejects torn/garbage blobs")
    good = store.read_bytes()
    truncated = good[: len(good) - 7]      # cut part of the last frame
    Path(base / "torn.bak").write_bytes(truncated)
    with open(base / "torn.bak", "rb") as fh:
        try:
            _verify_blob_headers(fh)
            check("truncated blob rejected", False)
        except IntegrityError:
            check("truncated blob rejected", True)
    Path(base / "garbage.bak").write_bytes(b"\xff\xff\x00\x00" + os.urandom(40))
    with open(base / "garbage.bak", "rb") as fh:
        try:
            _verify_blob_headers(fh)
            check("garbage blob rejected", False)
        except IntegrityError:
            check("garbage blob rejected", True)

    # ---- 3. corrupted backup during restore: unrecoverable + audit, no junk --
    print("3. restore_item on corrupted backup reports unrecoverable")
    src2 = base / "doc.pdf"
    src2.write_bytes(b"%PDF-1.4 " + os.urandom(2000))
    q = RecoveryEngine(db, bdir, qdir, key=key)
    qq = q.quarantine_file(src2, threat="Test")
    uid = qq["uid"]
    bpath = Path(qq["backup"])
    assert bpath.exists()
    bpath.write_bytes(b"\x00" * 40)       # smash the real blob
    rec = q.restore_item(uid)
    check("status == error", rec.get("status") == "error")
    check("unrecoverable flag set",
          rec.get("unrecoverable") is True,
          str(rec.get("reason"))[:120])
    check("reason says backup corrupted",
          str(rec.get("reason", "")).startswith("backup corrupted"))
    check("no .restore-<uid> garbage next to original",
          not list(base.glob(f".*.restore-{uid[:8]}")))
    check("no restored file left behind", not src2.exists())
    audit = db._query("SELECT event FROM audit_log WHERE event='restore_corrupt'")
    check("audit row logged", len(audit) >= 1)

    # ---- 4. good backup still restores after corruption path ---------------
    print("4. restore still succeeds for intact backups")
    src3 = base / "ok.txt"
    src3.write_bytes(b"hello integrity")
    q2 = RecoveryEngine(db, bdir, qdir, key=key)
    qq3 = q2.quarantine_file(src3, threat="Test")
    src3.unlink(missing_ok=True)
    rec3 = q2.restore_item(qq3["uid"])
    check("intact backup restored",
          rec3.get("status") == "restored" and src3.exists()
          and src3.read_bytes() == b"hello integrity")

    print(f"\nBackup integrity: {sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())