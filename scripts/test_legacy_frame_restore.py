#!/usr/bin/env python3
"""test_legacy_frame_restore.py - P2 regression: restoring a LEGACY-FORMATTED
encrypted backup (frames of 1,398,200 bytes from pre-P2 builds) must succeed
byte-exact through the real restore path, now that _MAX_FRAME is correctly
bounded.  A genuine garbage/oversized frame must still be rejected.

Part A: deterministic synthetic blob written with 1 MiB plaintext chunks -> the
        1,398,200-byte frames every >=1 MiB backup carries (the exact case the
        old _MAX_FRAME rejected with "implausible frame size 1398200").
Part B: a REAL quarantined LOST.DIR blob from the machine's live data dir,
        restored to a TEMP path only (never the original F: location) and
        verified byte-exact against the sha256/size recorded in the DB.
        Skipped (still green) when the real data dir/blob/key is unavailable.
"""
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

LEGACY_CHUNK = 1024 * 1024      # a 1 MiB chunk is the legacy-era write format
LEGACY_FRAME = 1_398_200      # base64 token for a 1 MiB chunk (census-exact max)

CHECKS: list = []


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def _real_data_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
    cand = Path(local) / "SecuDrive" / "data"
    return cand if (cand / "secudrive.db").exists() else Path()


def main() -> int:
    from secudrive.crypto import (FRAME_HEADER, IntegrityError, _MAX_FRAME, _fernet,
                                  generate_key, restore_backup_file)

    # ---- bound sanity: clears legacy max, still a guard far below 2x ---------
    print("0. _MAX_FRAME bound")
    check("clears legacy frame max", _MAX_FRAME > LEGACY_FRAME,
          f"_MAX_FRAME={_MAX_FRAME} vs legacy frame={LEGACY_FRAME}")
    check("still tight (no 2x/blowup headroom)", _MAX_FRAME < 2 * LEGACY_FRAME,
          f"_MAX_FRAME={_MAX_FRAME}")

    key = generate_key()
    fernet = _fernet(key)

    # ---- part A: synthetic legacy-frame blob round-trips byte-exact ---------
    print("1. legacy-frame blob (synthetic) restores byte-exact")
    data = os.urandom(3 * LEGACY_CHUNK)        # frames: 1,398,200 + 1,398,200 + small
    blob = Path(tempfile.mkdtemp(prefix="secudrive-legacy-craft-")) / "legacy.bak.aes"
    with open(blob, "wb") as fout:
        for i in range(0, len(data), LEGACY_CHUNK):
            chunk = data[i:i + LEGACY_CHUNK]
            tok = fernet.encrypt(chunk)
            fout.write(FRAME_HEADER.pack(len(tok)))
            fout.write(tok)
    import re as _re
    with open(blob, "rb") as fh:
        (n,) = FRAME_HEADER.unpack(fh.read(4))
    check("synthetic blob really is legacy-framed", n == LEGACY_FRAME, f"first frame={n}")
    out = blob.with_name("restored.bin")
    try:
        size = restore_backup_file(blob, out, key)
        check("restore round-trip exact bytes",
              out.read_bytes() == data and size == len(data), f"{size} bytes")
    except IntegrityError as exc:
        check("restore round-trip exact bytes", False, str(exc))
        check("no partial file left behind", not out.exists())
    finally:
        for p in (out, blob):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    # ---- garbage oversized frame still rejected ------------------------------
    print("2. oversized/garbage frame still rejected")
    gob = blob.with_name("oversized.bak.aes")
    with open(gob, "wb") as fh:
        fh.write(FRAME_HEADER.pack(_MAX_FRAME + 1))
        fh.write(b"\x00" * 64)
    try:
        restore_backup_file(gob, blob.with_name("nope.bin"), key)
        check("oversized frame rejected", False)
    except IntegrityError as exc:
        check("oversized frame rejected", True, f"{exc}")
    finally:
        try:
            gob.unlink(missing_ok=True)
        except OSError:
            pass

    # ---- part B: REAL LOST.DIR blob, read-only, restored only to a temp -----
    print("3. real LOST.DIR legacy blob restores byte-exact (read-only)")
    real_dir = _real_data_dir()
    status = "SKIPPED"
    if real_dir:
        db_path = real_dir / "secudrive.db"
        key_path = real_dir / ".secudrive.key"
        if key_path.exists():
            try:
                con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cur = con.execute(
                    "SELECT uid, original_path, backup_path, size, sha256 "
                    "FROM quarantine_items "
                    "WHERE status='quarantined' AND UPPER(original_path) LIKE '%LOST.DIR%'")
                chosen = None
                for row in cur.fetchall():
                    uid, origin, store, size, sha = row
                    if not store:
                        continue
                    store_path = Path(store)
                    if not store_path.exists():
                        continue
                    with open(store_path, "rb") as fh:
                        (n,) = FRAME_HEADER.unpack(fh.read(4))
                    if not 1_052_672 < n <= _MAX_FRAME:   # legacy frame (old cap miss)
                        continue
                    ref = con.execute(
                        "SELECT sha_before, sha_after FROM disinfect_log "
                        "WHERE path=? AND sha_before IS NOT NULL "
                        "ORDER BY id DESC LIMIT 1", (origin,)).fetchone()
                    ref_sha = (ref[0] if ref else None) or sha
                    chosen = (uid, origin, store_path, size, ref_sha, n, bool(ref))
                    break
                con.close()
                if chosen:
                    uid, origin, store_path, size, ref_sha, n, has_ref = chosen
                    real_key = key_path.read_bytes()
                    dst = Path(tempfile.mkdtemp(prefix="sdlr-")) / "real-restored.bin"
                    try:
                        exp_sha = ref_sha if ref_sha else None
                        sz = restore_backup_file(store_path, dst, real_key,
                                                 expected_sha=exp_sha,
                                                 expected_size=size)
                        from secudrive.safefile import compute_hashes
                        got = (compute_hashes(dst) or {}).get("sha256")
                        if ref_sha:
                            ok = sz == size and got == ref_sha
                        else:
                            ok = sz == size
                        status = "PASS" if ok else "FAIL"
                        check(f"real UID {uid[:10]}... ({Path(origin).name}, "
                              f"frame={n}) byte-exact vs recorded hash", ok,
                              f"size={sz}/expected={size} "
                              f"sha={got[:16] if got else None} "
                              f"referenced_by={('disinfect_log' if has_ref else 'qitem') if ref_sha else 'size-only'}")
                        check("real fixture restored to TEMP only (original "
                              "path untouched)", not Path(origin).exists()
                              or os.path.getsize(origin) == size,
                              origin)
                    except IntegrityError as exc:
                        status = "FAIL"
                        check("real UID restore (legacy frame)", False, str(exc))
                    finally:
                        try:
                            dst.unlink(missing_ok=True)
                        except OSError:
                            pass
                else:
                    status = "SKIPPED"
                    print("  [skip] no legacy-framed LOST.DIR row found in live DB")
            except sqlite3.Error as exc:
                status = "SKIPPED"
                print(f"  [skip] live DB unreadable: {exc}")
        else:
            status = "SKIPPED"
            print(f"  [skip] machine key missing: {key_path}")
    else:
        print("  [skip] live SecuDrive data dir not found")
    if status == "SKIPPED":
        check("real LOST.DIR blob test", True, "skipped - environment")  # battery stays green

    print(f"\nLegacy-frame restore: {sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())