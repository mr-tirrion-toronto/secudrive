#!/usr/bin/env python3
"""test_outcome_executors.py - regression test for RecoveryEngine Outcome A/B.

Guards the engine side of IMMEDIATE-RESOLVE (REVISED):

  * Outcome A (execute_outcome_a -> resolve_infector): the engine tries a chain
    of MEANINGFULLY DIFFERENT disinfection strategies, each applied to a temp
    copy and verified BEFORE the original path may change.  On the first
    verified candidate the fixed file is atomically published to its original
    path and the short-lived encrypted backup is purged.  Only when EVERY
    honest attempt fails does it fall back to the quarantine store keeping the
    PRE-ATTEMPT encrypted backup + full attempt history
    ('quarantined_after_attempts') - the file is never damaged and never left
    corrupted or still-infected at its original path.
  * Outcome B (execute_outcome_b): move the live copy into the encrypted
    quarantine store (old always-quarantine behavior) - threat may come from
    a Finding, a dict (name or threat_name) or an explicit string.
  * execute_plan dispatches resolve_plan() plans through the executors,
    including reveal and skip.

ZERO DATA LOSS is asserted: an encrypted backup always exists before any byte
changes, the pre-attempt backup round-trips to the EXACT original bytes, and a
successful resolve purges the short-lived backup.
"""
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
from secudrive.recovery import (  # noqa: E402
    PLAN_QUARANTINE, PLAN_REVEAL, PLAN_SKIP, PLAN_STRIP,
    RecoveryEngine, resolve_plan)
from secudrive.safefile import compute_hashes  # noqa: E402
from secudrive.scanner import Finding  # noqa: E402

CHECKS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""))


def make_engine(tmp: Path):
    db = Database(tmp / "secudrive.db")
    engine = RecoveryEngine(db=db, backup_dir=tmp / "backups",
                            quarantine_dir=tmp / "quarantine",
                            key_path=tmp / ".key")
    return db, engine


def write_jpeg(tmp: Path, name: str = "photo.jpg",
               payload: bytes = b"PAYLOADJUNK" * 5) -> Path:
    p = tmp / name
    p.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00"
                  + b"\x00" * 40 + b"\xff\xd9" + payload)
    return p


def write_mz(tmp: Path, name: str = "evil.exe") -> Path:
    p = tmp / name
    p.write_bytes(b"MZ" + b"\x00" * 96 + b"evil dropper payload")
    return p


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-executors-"))
    try:
        tmp = sandbox / "ai"
        tmp.mkdir(parents=True)
        db, engine = make_engine(tmp)

        print("1. Outcome A - resolve IN PLACE on a strip-able container")
        jpeg = write_jpeg(tmp)
        original_head = jpeg.read_bytes()[:4]
        original_size = jpeg.stat().st_size
        captured: dict = {}
        orig_backup_file = recovery_mod.backup_file

        def spy(src, *a, **k):
            captured["size"] = Path(src).stat().st_size
            captured["res"] = orig_backup_file(src, *a, **k)
            return captured["res"]

        try:
            recovery_mod.backup_file = spy
            rec = engine.execute_outcome_a(jpeg)
        finally:
            recovery_mod.backup_file = orig_backup_file
        check("status == stripped", rec.get("status") == "stripped", str(rec))
        check("outcome == resolved_in_place",
              rec.get("outcome") == "resolved_in_place", str(rec.get("outcome")))
        check("fixed file STAYS at its original path", jpeg.exists())
        data = jpeg.read_bytes()
        check("appended payload gone",
              b"PAYLOADJUNK" not in data and data.endswith(b"\xff\xd9"))
        check("header magic intact", data[:4] == original_head)
        check("pre-attempt encrypted backup captured the original (zero data loss)",
              captured.get("size") == original_size, str(captured))
        check("short-lived backup purged on successful resolve",
              not any((tmp / "backups").glob("*.bak.aes")))
        rows = [r for r in db.disinfect_history()
                if r["path"] == str(jpeg) and r["action"] == "resolve"]
        check("audit row logged 'resolve' ok", len(rows) == 1 and rows[0]["status"] == "ok")

        print("2. Outcome A - honest fallback when EVERY strategy fails")
        evil = write_mz(tmp)
        before_size = evil.stat().st_size
        before_sha = (compute_hashes(evil) or {}).get("sha256")
        rec2 = engine.execute_outcome_a(evil)
        check("status == quarantined (all attempts failed, never damaged)",
              rec2.get("status") == "quarantined", str(rec2))
        check("outcome == quarantined_after_attempts",
              rec2.get("outcome") == "quarantined_after_attempts",
              str(rec2.get("outcome")))
        check("attempt history recorded (2+ honest strategies tried)",
              len(rec2.get("attempts") or []) >= 2,
              str(rec2.get("attempts")))
        check("live copy moved out (gone from origin)",
              not evil.exists())
        qrows = [r for r in db.list_quarantine()
                 if r["original_path"] == str(evil)]
        check("quarantine row + pre-attempt encrypted backup preserved",
              len(qrows) == 1 and Path(qrows[0]["backup_path"]).exists())
        check("attempt history surfaced in quarantine notes",
              "StableBoundary" in (qrows[0].get("notes") or "")
              and "FullFileScan" in (qrows[0].get("notes") or ""),
              (qrows[0].get("notes") or ""))
        restored = tmp / "evil-restored.exe"
        restore_backup_file(Path(qrows[0]["backup_path"]), restored, engine.key,
                            expected_sha=before_sha, expected_size=before_size)
        check("pre-attempt backup round-trips to the EXACT original bytes",
              restored.read_bytes() == write_mz(tmp).read_bytes()
              and restored.stat().st_size == before_size)

        print("3. Outcome B - remove live copy into the quarantine store")
        txt = tmp / "notes.txt"
        txt.write_bytes(b"clean text\n")
        b_f = Finding(path=txt, category="heuristic", name="DangerousExtension",
                      confidence=0.9)
        rec3 = engine.execute_outcome_b(txt, b_f)
        check("status == quarantined", rec3.get("status") == "quarantined", str(rec3))
        check("outcome == quarantined_removed",
              rec3.get("outcome") == "quarantined_removed", str(rec3.get("outcome")))
        check("live copy gone, store + backup exist",
              not txt.exists() and Path(rec3["store"]).exists()
              and Path(rec3["backup"]).exists())

        txt2 = tmp / "notes2.txt"
        txt2.write_bytes(b"dict row\n")
        rec3b = engine.execute_outcome_b(txt2, {"threat_name": "FromDbRow"})
        check("dict finding with threat_name accepted",
              rec3b.get("status") == "quarantined"
              and "FromDbRow" in str(db.list_quarantine()), str(rec3b))
        txt3 = tmp / "notes3.txt"
        txt3.write_bytes(b"str threat\n")
        rec3c = engine.execute_outcome_b(txt3, threat="ExplicitLabel")
        check("explicit threat string accepted",
              rec3c.get("status") == "quarantined"
              and "ExplicitLabel" in str(db.list_quarantine()), str(rec3c))

        print("4. execute_plan - dispatcher honors the classify/execute contract")
        jpg2 = write_jpeg(tmp, name="photo2.jpg")
        plan_strip = resolve_plan(jpg2, db,
                                  Finding(path=jpg2, category="heuristic",
                                          name="TrailingPayload", confidence=0.82))
        rec4 = engine.execute_plan(plan_strip, jpg2, Finding(path=jpg2,
                                                             category="heuristic",
                                                             name="TrailingPayload",
                                                             confidence=0.82))
        check("plan strip -> resolved_in_place",
              rec4.get("outcome") == "resolved_in_place"
              and rec4.get("status") == "stripped", str(rec4))

        evil2 = write_mz(tmp, name="evil2.exe")
        plan_q = resolve_plan(evil2, db,
                              Finding(path=evil2, category="signature",
                                      name="TestDropper", confidence=1.0))
        rec5 = engine.execute_plan(plan_q, evil2,
                                   Finding(path=evil2, category="signature",
                                           name="TestDropper", confidence=1.0))
        check("plan quarantine -> quarantined_removed",
              rec5.get("outcome") == "quarantined_removed"
              and rec5.get("status") == "quarantined", str(rec5))

        keep = tmp / "keep.txt"
        keep.write_bytes(b"keep\n")
        rec6 = engine.execute_plan({"plan": PLAN_SKIP,
                                    "reason": "manual review only"}, keep, None)
        check("plan skip -> never touched",
              rec6.get("outcome") == "skipped" and rec6.get("status") == "skipped"
              and keep.exists(), str(rec6))

        plain_dir = tmp / "plaindir"
        plain_dir.mkdir()
        rec7 = engine.execute_plan({"plan": PLAN_REVEAL}, plain_dir, None)
        check("plan reveal on plain dir -> no_change (no attrs to fix)",
              rec7.get("outcome") == "no_change", str(rec7.get("outcome")))

        print(f"\nOutcome executors: {sum(CHECKS)}/{len(CHECKS)} checks passed")
        return 0 if all(CHECKS) else 1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nOutcome executors: FAIL ({exc})", file=sys.stderr)
        raise