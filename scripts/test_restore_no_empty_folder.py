#!/usr/bin/env python3
"""test_restore_no_empty_folder.py - regression test for BUG #2.

The quirk being pinned down: a restore used to create ``original.parent``
BEFORE decrypting/verifying the encrypted backup, so a failed decrypt left an
EMPTY FOLDER behind where the file should have appeared ("restore produced an
empty folder").  The fix decrypts to a quarantine-dir staging file first and
only materialises the parent once the plaintext has been verified - and rolls
the empty folder back if the restore still fails afterwards.

Guards:
  * MISSING backup  -> error rec, no empty folder created
  * CORRUPT backup  -> error rec (verify/decrypt failed), no empty folder
  * GOOD backup     -> file restored with EXACT bytes, parent present
  * displace path   -> existing occupant moved to quarantine, staging cleaned
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive.database import Database  # noqa: E402
from secudrive.recovery import RecoveryEngine  # noqa: E402

CHECKS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""))


def make_engine(tmp: Path) -> tuple[Database, RecoveryEngine, Path, Path]:
    db = Database(tmp / "secudrive.db")
    backups = tmp / "backups"
    quarantine = tmp / "quarantine"
    engine = RecoveryEngine(db, backups, quarantine,
                            key_path=tmp / ".key")
    return db, engine, backups, quarantine


def restore_via(engine: RecoveryEngine, store: Path, sha: str, size: int,
                original: Path, uid: str) -> dict:
    """Create a minimal quarantine row then run restore_item."""
    db = engine.db
    db.add_quarantine(uid=uid, original_path=str(original),
                      store_path=str(original.with_suffix(".q")),
                      backup_path=str(store), size=size, sha256=sha,
                      threat_name="suspicious")
    return engine.restore_item(uid)


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-restorempty-"))
    try:
        db, engine, backups, quarantine = make_engine(sandbox)

        # The quarantine source: a real encrypted backup of known bytes.
        src = sandbox / "data.bin"
        src.write_bytes(b"hello, quarantine world! " * 4)
        shutil.copy2(src, backups / "source-extra.bin")
        meta = engine._ensure_key() or None
        from secudrive.crypto import backup_file
        bkp = backup_file(src, backups, engine.key)
        good_store = Path(bkp["store_path"])
        sha, size = bkp["sha256"], int(bkp["size"])

        target_parent = sandbox / "out" / "deep" / "nested"
        original = target_parent / "restored.bin"

        # -- 1. MISSING backup: error + NO empty folder ---------------------
        rec_m = restore_via(engine, backups / "nope.bak.aes", sha, size, original,
                            "a" * 32)
        check("missing backup -> error rec",
              rec_m.get("status") == "error"
              and "backup missing" in str(rec_m.get("reason")),
              str(rec_m.get("reason")))
        check("missing backup creates NO folder on the way",
              not target_parent.exists(), str(target_parent))

        # -- 2. CORRUPT backup: error + NO empty folder ---------------------
        corrupt = backups / "corrupt.bak.aes"
        corrupt.write_bytes(good_store.read_bytes()[:-40] + b"\x00" * 40)
        rec_c = restore_via(engine, corrupt, sha, size, original, "b" * 32)
        check("corrupt backup -> error rec",
              rec_c.get("status") == "error", str(rec_c.get("status")))
        check("corrupt backup leaves NO empty folder",
              not target_parent.exists(), str(target_parent))
        check("staging file cleaned up after corrupt-deny",
              not (backups / ".restore-staging-bbbbbbbbbbbb").exists())

        # -- 3. GOOD backup: file restored with exact bytes + parent present -
        rec_ok = restore_via(engine, good_store, sha, size, original, "c" * 32)
        check("good restore -> status restored",
              rec_ok.get("status") == "restored", str(rec_ok.get("status")))
        check("parent present", target_parent.is_dir())
        check("file present", original.is_file())
        check("bytes byte-exact",
              original.read_bytes() == src.read_bytes())
        row = db.get_quarantine("c" * 32)
        check("DB status=restored",
              row and row.get("status") == "restored", str(row and row.get("status")))

        # -- 4. occupant at the original path -> displaced, no staging leak ---
        occ = sandbox / "occupied-parent" / "won.bin"
        occ.parent.mkdir(parents=True)
        occ.write_bytes(b"someone else lives here")
        b2 = backup_file(src, backups, engine.key)
        rec_d = restore_via(engine, Path(b2["store_path"]), b2["sha256"],
                            int(b2["size"]), occ, "d" * 32)
        check("displace path -> status restored",
              rec_d.get("status") == "restored", str(rec_d.get("status")))
        check("old occupant moved to quarantine store",
              bool(rec_d.get("displaced")))
        check("displaced row exists",
              db.get_quarantine(rec_d.get("displaced")) is not None)
        check("file at original path restored",
              occ.read_bytes() == src.read_bytes())
        check("no staging leftovers for the displaced uid",
              not any(p.name.startswith(".restore-staging-")
                      for p in backups.iterdir()))

        total = sum(1 for c in CHECKS if c)
        failed = len(CHECKS) - total
        print(f"\nRestore empty-folder guard: {total}/{len(CHECKS)} checks passed")
        return 0 if not failed else 1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - harness must not die silently
        print(f"\nRestore empty-folder guard: FAIL ({exc})", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)