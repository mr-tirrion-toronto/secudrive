#!/usr/bin/env python3
"""test_resolve_infector.py - regression test for the REFINED multi-strategy
"resolve harder before quarantine" Outcome A, plus the Outcome B delete-lock
manual-review signal.

Covers the four REQUIRED deliverables:

  (a) strategy 1 succeeds on the first honest attempt -> resolved in place,
      short-lived backup purged, single attempt recorded;
  (b) strategy 1 fails, a MEANINGFULLY DIFFERENT strategy 2 succeeds;
  (c) EVERY strategy fails -> quarantine keeps the PRE-ATTEMPT encrypted backup
      intact (exact-byte round-trip) and records the FULL attempt history in
      the quarantine notes;
  (d) a failed-verify candidate is NEVER written back to the original path -
      the original stays pristine until a VERIFIED candidate is published;
  (e) the conservative SignatureAnchored strategy strips ONLY when the trailing
      region matches a known-bad signature (declines otherwise);
  (f) Outcome B delete-lock: after retries the engine signals
      ``requires_manual_review`` instead of quarantining or deleting silently.

KEY PRINCIPLE under test: minimize Quarantine by trying harder, but NEVER
sacrifice correctness - a failed/ambiguous candidate is never published.
"""
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive import recovery as recovery_mod  # noqa: E402
from secudrive.crypto import restore_backup_file  # noqa: E402
from secudrive.database import Database  # noqa: E402
from secudrive.recovery import RecoveryEngine  # noqa: E402
from secudrive.safefile import compute_hashes  # noqa: E402

CHECKS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""))


def make_engine(tmp: Path, **kw):
    db = Database(tmp / "secudrive.db")
    engine = RecoveryEngine(db=db, backup_dir=tmp / "backups",
                            quarantine_dir=tmp / "quarantine",
                            key_path=tmp / ".key", **kw)
    return db, engine


JPEG_HEAD = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00" + b"\x00" * 40


def write_jpeg(tmp: Path, name: str = "photo.jpg",
               payload: bytes = b"PAYLOADJUNK" * 5, head: bytes = JPEG_HEAD) -> Path:
    p = tmp / name
    p.write_bytes(head + b"\xff\xd9" + payload)
    return p


def write_mz(tmp: Path, name: str = "evil.exe") -> Path:
    p = tmp / name
    p.write_bytes(b"MZ" + b"\x00" * 96 + b"evil dropper payload")
    return p


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-infector-"))
    try:
        print("(a) strategy 1 succeeds on the first honest attempt")
        tmp = sandbox / "a"
        tmp.mkdir(parents=True)
        db, engine = make_engine(tmp)
        jpeg = write_jpeg(tmp)
        before = jpeg.read_bytes()
        rec = engine.resolve_infector(jpeg)
        check("status == stripped, outcome == resolved_in_place",
              rec.get("status") == "stripped"
              and rec.get("outcome") == "resolved_in_place", str(rec))
        check("exactly 1 attempt recorded (StableBoundary ok)",
              (rec.get("attempts") or []) and rec["attempts"][0].get("strategy")
              == "StableBoundary" and rec["attempts"][0].get("result") == "ok",
              str(rec.get("attempts")))
        check("payload removed, file structurally valid at ORIGINAL path",
              jpeg.exists() and b"PAYLOADJUNK" not in jpeg.read_bytes()
              and jpeg.read_bytes().endswith(b"\xff\xd9"))
        check("backup expected_before the change + purged on success",
              len(engine_backups := list((tmp / "backups").glob("*.bak.aes"))) == 0,
              f"leftover={engine_backups}")
        check("original bytes differ (bytes actually removed)",
              jpeg.read_bytes() != before)

        print("(b) strategy 1 fails -> MEANINGFULLY DIFFERENT strategy 2 succeeds")
        tmp = sandbox / "b"
        tmp.mkdir(parents=True)
        # engine_b uses a TINY tail window so the stable strategy cannot see a
        # marker that sits deep (>64B) before EOF; the FullFileScan strategy
        # relaxes the window up to 256MB and finds it.
        db_b, engine_b = make_engine(tmp, tail_window=64)
        big_payload = b"LARGEPAYLOAD" * 10000          # 120 KB appended junk
        big = write_jpeg(tmp, name="big.jpg", payload=big_payload)
        before_b = big.read_bytes()
        rec_b = engine_b.resolve_infector(big)
        attempts_b = rec_b.get("attempts") or []
        check("outcome == resolved_in_place", rec_b.get("outcome") == "resolved_in_place",
              str(rec_b))
        check("attempt 1 StableBoundary DECLINED (marker outside tiny window)",
              len(attempts_b) >= 2 and attempts_b[0].get("strategy") == "StableBoundary"
              and attempts_b[0].get("result") == "declined", str(attempts_b))
        check("attempt 2 FullFileScan SUCCEEDED (relaxed boundary)",
              attempts_b[1].get("strategy") == "FullFileScan"
              and attempts_b[1].get("result") == "ok", str(attempts_b))
        check("huge payload stripped from a deep position",
              big.exists() and b"LARGEPAYLOAD" not in big.read_bytes()
              and big.read_bytes().endswith(b"\xff\xd9"))
        check("short-lived backups all purged after success",
              not list((tmp / "backups").glob("*.bak.aes")))

        print("(c) every strategy fails -> quarantine keeps PRE-ATTEMPT backup "
              "+ full attempt history")
        tmp = sandbox / "c"
        tmp.mkdir(parents=True)
        db_c, engine_c = make_engine(tmp)
        evil = write_mz(tmp)
        before_c = evil.read_bytes()
        before_sha = (compute_hashes(evil) or {}).get("sha256")
        rec_c = engine_c.resolve_infector(evil, threat="TestDropper")
        attempts_c = rec_c.get("attempts") or []
        check("status == quarantined, outcome == quarantined_after_attempts",
              rec_c.get("status") == "quarantined"
              and rec_c.get("outcome") == "quarantined_after_attempts", str(rec_c))
        check("all THREE strategies honestly attempted (each declined)",
              len(attempts_c) == 3
              and all(a.get("result") == "declined" for a in attempts_c),
              str(attempts_c))
        check("live copy moved out, quarantine store captured ORIGINAL bytes",
              not evil.exists()
              and Path(rec_c["quarantine_uid"] and
                       (tmp / "quarantine" / f"{rec_c['quarantine_uid']}.q")).exists())
        qrows = [r for r in db_c.list_quarantine()
                 if r["original_path"] == str(evil)]
        check("quarantine row written with notes history",
              len(qrows) == 1 and (qrows[0].get("notes") or ""))
        check("attempt history lists EVERY strategy + why each declined",
              all(a["strategy"] in (qrows[0].get("notes") or "")
                  and "declined" in a["result"] for a in attempts_c))
        check("PRE-ATTEMPT encrypted backup preserved (not the failed attempts)",
              Path(qrows[0]["backup_path"]).exists())
        restored = tmp / "restored.exe"
        restore_backup_file(Path(qrows[0]["backup_path"]), restored, engine_c.key,
                            expected_sha=before_sha,
                            expected_size=len(before_c))
        check("pre-attempt backup round-trips to the EXACT original bytes",
              restored.read_bytes() == before_c)
        check("quarantine store blob holds EXACT pre-attempt bytes (never "
              "damaged/corrupted)",
              Path(qrows[0]["store_path"]).read_bytes() == before_c)

        print("(d) a failed-verify candidate is NEVER written back to the "
              "original path")
        tmp = sandbox / "d"
        tmp.mkdir(parents=True)
        db_d, engine_d = make_engine(tmp)
        # Register the appended payload as a known-bad signature so the
        # conservative SignatureAnchored strategy ALSO finds a boundary and
        # reaches verification: all three candidates must then be rejected by
        # the failing verifier and NONE may be published.
        d_payload = b"PAYLOADJUNK" * 5
        db_d.upsert_signature(hashlib.sha256(d_payload).hexdigest(), "sha256",
                              "GuardedPayload")
        jpeg_d = write_jpeg(tmp, name="guarded.jpg", payload=d_payload)
        before_d = jpeg_d.read_bytes()
        orig_verify = engine_d._verify_sanitized
        verified_candidates: list = []

        def fake_verify(path, magic, size):
            verified_candidates.append(Path(path).name)
            return False, "injected verify failure", {}

        engine_d._verify_sanitized = fake_verify
        try:
            rec_d = engine_d.resolve_infector(jpeg_d)
        finally:
            engine_d._verify_sanitized = orig_verify
        check("every candidate was attempted AND rejected by verification",
              len(verified_candidates) == 3
              and all(a.get("result") == "failed" and "candidate did not verify"
                      in (a.get("reason") or "")
                      for a in (rec_d.get("attempts") or [])),
              str(rec_d.get("attempts")))
        check("status == quarantined (correctness over avoiding quarantine)",
              rec_d.get("status") == "quarantined"
              and rec_d.get("outcome") == "quarantined_after_attempts", str(rec_d))
        qd = [r for r in db_d.list_quarantine()
              if r["original_path"] == str(jpeg_d)]
        check("original path was NEVER polluted by a failed candidate - the "
              "only surviving artifacts equal the pristine bytes",
              len(qd) == 1
              and Path(qd[0]["store_path"]).read_bytes() == before_d
              and Path(qd[0]["backup_path"]).exists()
              and not jpeg_d.exists())

        print("(e) conservative SignatureAnchored strips only known-bad "
              "signatures")
        tmp = sandbox / "e"
        tmp.mkdir(parents=True)
        db_e, engine_e = make_engine(tmp)
        anchor_payload = b"ANCHORED-CODE" * 4           # >= 32B trailing region
        payload_sha = hashlib.sha256(anchor_payload).hexdigest()
        db_e.upsert_signature(payload_sha, "sha256", "AnchoredBadness")
        anch = write_jpeg(tmp, name="anchored.jpg", payload=anchor_payload)
        rec_e = engine_e.resolve_infector(
            anch, strategies=(recovery_mod._STRATEGY_ANCHORED,))
        check("anchored trailing region stripped in place",
              rec_e.get("outcome") == "resolved_in_place"
              and b"ANCHORED-CODE" not in anch.read_bytes(), str(rec_e))
        # A trailing region that is NOT anchored declines instead of guess-
        # stripping - this is the anti-false-positive guarantee.
        unreg = write_jpeg(tmp, name="unknown.jpg", payload=b"RANDOMJUNK" * 5)
        before_u = unreg.read_bytes()
        rec_f = engine_e.resolve_infector(
            unreg, strategies=(recovery_mod._STRATEGY_ANCHORED,))
        check("unanchored trailing region DECLINES (not guess-stripped)",
              rec_f.get("status") == "quarantined"
              and (rec_f.get("attempts") or [])
              and rec_f["attempts"][0].get("result") == "declined", str(rec_f))
        check("declined file moved to quarantine store with EXACT original "
              "bytes",
              not unreg.exists()
              and Path(rec_f["quarantine_uid"] and
                       (tmp / "quarantine" / f"{rec_f['quarantine_uid']}.q"))
              .read_bytes() == before_u)

        print("(f) Outcome B delete-lock retries -> manual review, never a "
              "silent quarantine")
        tmp = sandbox / "f"
        tmp.mkdir(parents=True)
        db_f, engine_f = make_engine(tmp)
        locked = write_mz(tmp, name="locked.exe")
        if os.name == "nt":
            # A plain open() handle on Windows does NOT request
            # FILE_SHARE_DELETE, so unlink fails with PermissionError [Win32
            # 32] - the realistic "file in use" lock.  The engine must retry a
            # few times, then signal requires_manual_review (never quarantine).
            fh = locked.open("rb")
            try:
                rec_g = engine_f.purge_verified_file(locked, threat="LockedDropper")
            finally:
                fh.close()
            check("delete returned error with requires_manual_review",
                  rec_g.get("status") == "error"
                  and rec_g.get("requires_manual_review") is True, str(rec_g))
            check("file left IN PLACE (not deleted, not quarantined)",
                  locked.exists()
                  and not [r for r in db_f.list_quarantine()
                           if r["original_path"] == str(locked)])
            check("no orphaned backup after the failed delete",
                  not list((tmp / "backups").glob("*.bak.aes")))
        else:
            check("(POSIX) no forced file-lock mechanism - skipped", True)

        print(f"\nResolve-infector: {sum(CHECKS)}/{len(CHECKS)} checks passed")
        return 0 if all(CHECKS) else 1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nResolve-infector: FAIL ({exc})", file=sys.stderr)
        raise