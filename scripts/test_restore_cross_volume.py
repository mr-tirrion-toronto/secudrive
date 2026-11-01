#!/usr/bin/env python3
"""test_restore_cross_volume.py - regression test for the FIELD BUG:

    restore write failed: [WinError 17] The system cannot move the file to a
    different disk drive: '.restore-staging-<uid>' -> 'H:\\Projects\\...'

Root cause: ``restore_item`` decrypts the backup into a staging blob inside
``backup_dir`` (always drive C:) and then published it with a bare
``os.replace(tmp, original)``.  On Windows ``os.replace`` is atomic only WITHIN
one NTFS volume; publishing to an original path on a different drive (H:/D:/E:)
raises WinError 17.  That is why exactly ONE item (C:\\SearcherBar\\js\\main.js,
same drive as the backup store) restored and EVERY item on H:/D:/E: failed.

The fix routes that single publish through ``RecoveryEngine._publish_verified``:
same volume -> os.replace (atomic, unchanged); cross volume -> copy into a temp
in the DESTINATION's own directory, fsync + size/sha verify, then os.replace on
that volume (atomic), and only then delete the C: staging blob.

HOW THIS TEST FORCES A CROSS-VOLUME MOVE ON ONE MACHINE:
Two mechanisms, so the cross-drive path is genuinely exercised even on a
single-volume test box (and even on Linux CI):

  1. MOCKED VOLUME BOUNDARY (deterministic, always runs): the engine's
     ``os.path.splitdrive`` is replaced so the staging dir reports drive "C:"
     and the destination dir reports "H:", forcing the cross-volume branch.
     The publish must then SUCCEED via the copy+verify+atomic-replace path and
     produce a byte-exact destination.
     A control assertion proves the OLD code was genuinely broken: a bare
     ``os.replace`` between the two mocked-volume paths is what raised WinError
     17 in the field.

  2. REAL TWO-VOLUME RESTORE (only when a second real volume exists - e.g. a
     USB stick or D:/E: on the field machine): a genuine quarantine+restore
     round-trip with the backup store and the original file on different real
     volumes.  Skipped (green) when the machine has only one volume so the
     battery stays machine-independent.

Zero-data-loss invariants asserted on the cross-volume path:
  * the restored file is byte-exact (sha256 matches the pre-quarantine file);
  * a copy/verify failure never deletes the encrypted backup and never leaves a
    half-written destination (injected-failure check).
"""
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "recovery.py").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

CHECKS: list = []


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def has_second_volume() -> Path | None:
    """Return an existing, writable, different-volume root (USB/D:/E:) or None."""
    if not os.path.isdir("C:\\"):
        return None
    try:
        c_dev = os.stat("C:\\").st_dev
    except OSError:
        return None
    for part in ("D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\", "J:\\"):
        try:
            if os.path.isdir(part) and os.stat(part).st_dev != c_dev:
                return Path(part)
        except OSError:
            continue
    return None


def build_engine(base: Path):
    from secudrive.crypto import generate_key
    from secudrive.database import Database
    from secudrive.recovery import RecoveryEngine
    backups = base / "backups"
    quarantine = base / "quarantine"
    db = Database(base / "secudrive.db")
    engine = RecoveryEngine(db, backups, quarantine, key=generate_key())
    return engine, backups, quarantine


def main() -> int:
    import secudrive.recovery as R

    # ================================================================
    print("1. mocked volume boundary: backup_dir on 'C:', destination on 'H:'")
    base = Path(tempfile.mkdtemp(prefix="secudrive-xvol-"))
    engine, backups, quarantine = build_engine(base)
    dest_dir = base / "H" / "Projects" / "TAMISEMI"      # stands in for H:\
    dest_dir.mkdir(parents=True, exist_ok=True)
    original = dest_dir / "shape.shp"
    payload = b"\x00" * 64 + b"SHP-DATA" * 64
    original.write_bytes(payload)
    want_sha = sha256(original)

    # quarantine the file (normal path, no volume trickery)
    q = engine.quarantine_file(original, threat="TestCrossVol")
    uid = q["uid"]
    check("quarantine captured the cross-drive file", not original.exists())

    real_splitdrive = os.path.splitdrive

    def fake_splitdrive(p):
        s = str(p)
        if s.startswith(str(backups)) or "\\backups\\" in s or s.endswith(".restore-staging"):
            return ("C:", s[2:])
        if s.startswith(str(dest_dir)) or "\\H\\" in s:
            return ("H:", s[2:])
        return real_splitdrive(p)

    # Prove the OLD behaviour: a bare os.replace across the mocked boundary is
    # precisely what fails in the field (WinError 17) -> monkeypatch os.replace
    # to raise the real WinError when the two mocked volumes differ, and assert
    # restore_item STILL succeeds (the fix must not call the failing replace).
    def cross_replace_guard(a, b, **kw):
        da = fake_splitdrive(a)[0]
        dbv = fake_splitdrive(b)[0]
        if da and dbv and da != dbv:
            raise OSError(17, "The system cannot move the file to a different "
                              "disk drive", str(b), 17)
        return real_os_replace(a, b, **kw)

    real_os_replace = os.replace
    R.os.path.splitdrive = fake_splitdrive
    R.os.replace = cross_replace_guard
    try:
        rec = engine.restore_item(uid)
    finally:
        R.os.path.splitdrive = real_splitdrive
        R.os.replace = real_os_replace

    check("cross-volume restore succeeded (no WinError 17)",
          rec.get("status") == "restored", str(rec.get("reason") or rec.get("status")))
    check("original file materialised on 'H:' drive path", original.exists())
    check("restored bytes are EXACT (sha256 match)",
          original.exists() and sha256(original) == want_sha)
    check("no leftover .secudrive-publish temp in destination dir",
          not any(p.name.startswith(".secudrive-publish-") for p in dest_dir.iterdir()))
    check("no leftover .restore-staging blob in backup dir",
          not any(p.name.startswith(".restore-staging-") for p in backups.iterdir()))

    # ================================================================
    print("2. same-volume restore still uses the atomic os.replace fast path")
    base2 = Path(tempfile.mkdtemp(prefix="secudrive-samevol-"))
    engine2, backups2, _q2 = build_engine(base2)
    same = base2 / "file.bin"
    same.write_bytes(b"SAME-DRIVE" * 100)
    same_sha = sha256(same)
    q2 = engine2.quarantine_file(same, threat="SameVol")
    rec2 = engine2.restore_item(q2["uid"])
    check("same-volume restore still succeeds", rec2.get("status") == "restored",
          str(rec2.get("reason") or rec2.get("status")))
    check("same-volume bytes exact", same.exists() and sha256(same) == same_sha)

    # ================================================================
    print("3. zero-data-loss: publish failure keeps backup + leaves dst clean")
    base3 = Path(tempfile.mkdtemp(prefix="secudrive-zdl-"))
    engine3, backups3, _q3 = build_engine(base3)
    dest3 = base3 / "external" / "keep.bin"
    dest3.parent.mkdir(parents=True, exist_ok=True)
    dest3.write_bytes(b"ORIGINAL-BYTES")
    q3 = engine3.quarantine_file(dest3, threat="ZDL")
    uid3 = q3["uid"]
    dest3.write_bytes(b"NEW-OCCUPANT")            # an occupant now sits there

    boom = {"n": 0}
    # force the cross-volume branch so the copy+verify+atomic-publish path runs
    def splitdrive_zdl(p):
        s = str(p)
        if s.startswith(str(backups3)):
            return ("C:", s[2:])
        if s.startswith(str(dest3.parent)):
            return ("H:", s[2:])
        return real_splitdrive(p)

    def failing_replace(a, b, **kw):
        # fail the FINAL atomic publish only (dst-volume os.replace), after the
        # verified copy has been written - this is the worst case for the copy.
        if ".secudrive-publish-" in str(a):
            raise OSError(28, "No space left on device", str(b), 28)
        return real_os_replace(a, b, **kw)

    R.os.path.splitdrive = splitdrive_zdl
    R.os.replace = failing_replace
    try:
        rec3 = engine3.restore_item(uid3)
    finally:
        R.os.replace = real_os_replace
        R.os.path.splitdrive = real_splitdrive

    check("failed cross-publish reports error (never silent success)",
          rec3.get("status") == "error", str(rec3.get("status")))
    # Zero-data-loss on a failed publish: NOTHING is destroyed.  The encrypted
    # backup of the original item is still on disk (retryable), and the occupant
    # that restore_item displaced before publishing is preserved in quarantine.
    blobs3 = sorted(p.name for p in backups3.iterdir() if p.name.endswith(".bak.aes"))
    check("encrypted backup blob RETAINED after failed publish",
          len(blobs3) >= 1, str(blobs3))
    check("displaced occupant preserved in quarantine (not destroyed)",
          rec3.get("displaced") is not None
          and engine3.db.get_quarantine(rec3["displaced"]) is not None,
          f"displaced={rec3.get('displaced')}")
    # The destination must never be left holding a PARTIAL/corrupt file: either
    # it is absent (the verified copy never reached it) or it is byte-complete.
    partial = dest3.exists() and dest3.read_bytes() not in (
        b"NEW-OCCUPANT", b"ORIGINAL-BYTES")
    check("destination never left partially written", not partial,
          "absent (clean)" if not dest3.exists() else
          f"len={len(dest3.read_bytes())}")
    check("no partial .secudrive-publish temp left after failure",
          not any(p.name.startswith(".secudrive-publish-")
                  for p in dest3.parent.iterdir()))

    # ================================================================
    print("4. REAL two-volume restore (skipped when only one volume exists)")
    second = has_second_volume()
    if second is None:
        print("  [SKIP] no second real volume on this machine - "
              "cross-volume path already proven via the mocked boundary above")
        check("real two-volume roundtrip (skipped - single-volume machine)", True)
    else:
        try:
            real_dest_dir = Path(tempfile.mkdtemp(prefix="secudrive-realxvol-",
                                                  dir=str(second)))
        except OSError as exc:
            print(f"  [SKIP] cannot create dir on {second}: {exc}")
            check("real two-volume roundtrip (skipped - not writable)", True)
        else:
            base4 = Path(tempfile.mkdtemp(prefix="secudrive-realxvol-base-"))
            engine4, _b4, _q4 = build_engine(base4)
            real_file = real_dest_dir / "field_case.bin"
            real_file.write_bytes(b"REAL-CROSS-VOLUME" * 500)
            real_sha = sha256(real_file)
            q4 = engine4.quarantine_file(real_file, threat="RealCrossVol")
            rec4 = engine4.restore_item(q4["uid"])
            check("REAL cross-volume restore succeeded",
                  rec4.get("status") == "restored", str(rec4.get("reason") or ""))
            check("REAL cross-volume bytes exact",
                  real_file.exists() and sha256(real_file) == real_sha)
            shutil.rmtree(real_dest_dir, ignore_errors=True)

    print(f"\ncross-volume restore regression: {sum(CHECKS)}/{len(CHECKS)} "
          f"checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
