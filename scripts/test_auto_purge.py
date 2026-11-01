#!/usr/bin/env python3
"""test_auto_purge.py - feature/regression test for Auto-Purge Mode.

Guards the ``quarantine_retention_mode`` policy ('keep_forever' default /
'auto_purge_verified' / 'purge_after_days') added to the auto-scan/disinfect
pipeline:

  * a PURE-MALWARE file (confident live full-file signature hit, non-container
    extension) is backup -> deleted -> verified -> its short-lived encrypted
    backup purged; it is NEVER moved into long-term Quarantine;
  * the safety guardrail holds: heuristic hits, low-confidence hits, document-
    like containers, and files whose hash no longer matches the signature
    table are (a) rejected by is_auto_purge_candidate() and (b) never
    silently deleted - the fallback keeps the original and quarantines it;
  * a file that changed since the scan (hash mismatch) is REFUSED by the
    engine with the original left in place (no half-delete, no orphan blob);
  * the purge_after_days sweep (Database.purge_due + engine.purge_item) only
    retires items OLDER than the window and keeps the audit row as 'purged';
  * cumulative 'Storage freed by auto-purge' (Database.auto_purge_stats) is
    tracked over the disinfect_log audit trail.

Each check is atomic to a temp dir; PASS/FAIL is printed per check.
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

from secudrive.autopilot import DISINFECT, AutoPilotWorker  # noqa: E402
from secudrive.database import Database  # noqa: E402
from secudrive.recovery import (  # noqa: E402
    RecoveryEngine, is_auto_purge_candidate)
from secudrive.safefile import compute_hashes  # noqa: E402
from secudrive.scanner import Finding, ScanOptions  # noqa: E402

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


def write_malicious(tmp: Path, name: str = "evil.exe", body: bytes = None) -> Path:
    p = tmp / name
    p.write_bytes(body or b"MZ" + b"\x00" * 64 + b"evil dropper payload")
    return p


def main() -> int:
    # ------------------------------------------------------------ setup sandbox
    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-autopurge-"))
    try:
        tmp = sandbox / "ai"
        tmp.mkdir(parents=True)
        db, engine = make_engine(tmp)

        # ---- check 1: classifier accepts a true pure-malware candidate -------
        print("1. is_auto_purge_candidate()")
        evil = write_malicious(tmp)
        sha = (compute_hashes(evil) or {}).get("sha256")
        db.upsert_signature(sha, "sha256", "TestDropper")
        finding = Finding(path=evil, category="signature", name="TestDropper",
                          confidence=1.0, sha256=sha)
        check("full-file signature + exec ext + live hash",
              is_auto_purge_candidate(evil, db, finding) is True)
        as_dict = {"path": evil, "category": "signature", "confidence": 1.0,
                   "sha256": sha, "name": "TestDropper"}
        check("dict-form finding also accepted",
              is_auto_purge_candidate(evil, db, as_dict) is True)

        # ---- check 2: never accept ambiguous / possibly-legitimate files -----
        print("2. guardrail - ambiguous files are REJECTED, never auto-deleted")
        legit_doc = tmp / "invoice.pdf"
        legit_doc.write_bytes(b"%PDF-1.4\nlegit document bytes")
        sha_doc = (compute_hashes(legit_doc) or {}).get("sha256")
        db.upsert_signature(sha_doc, "sha256", "RogueDoc")
        doc_finding = Finding(path=legit_doc, category="signature",
                              name="RogueDoc", confidence=1.0, sha256=sha_doc)
        check("document-like container rejected",
              is_auto_purge_candidate(legit_doc, db, doc_finding) is False)
        heur = Finding(path=evil, category="heuristic", name="DoubleExtension",
                       confidence=1.0, sha256=sha)
        check("heuristic hit rejected",
              is_auto_purge_candidate(evil, db, heur) is False)
        low = Finding(path=evil, category="signature", name="TestDropper",
                      confidence=0.5, sha256=sha)
        check("low-confidence signature rejected",
              is_auto_purge_candidate(evil, db, low) is False)
        no_sh = Finding(path=evil, category="signature", name="TestDropper",
                        confidence=1.0, sha256=None)
        check("exec with no hash proof still accepted (live table covers it)",
              is_auto_purge_candidate(evil, db, no_sh) is True)
        db._execute("DELETE FROM signatures WHERE hash=?", (sha,))
        check("hash no longer in live table -> rejected (re-verified)",
              is_auto_purge_candidate(evil, db, finding) is False)
        db.upsert_signature(sha, "sha256", "TestDropper")

        # ---- check 3: full auto-purge happy path -----------------------------
        print("3. purge_verified_file() - pure malware fully removed")
        before = {p.name for p in (tmp / "backups").glob("*")}
        evil_size = evil.stat().st_size
        rec = engine.purge_verified_file(evil, threat=finding.name,
                                         expected_sha=finding.sha256)
        check("status == auto_purged", rec.get("status") == "auto_purged",
              str(rec))
        check("original file deleted", not evil.exists())
        after = {p.name for p in (tmp / "backups").glob("*")}
        check("short-lived encrypted backup purged",
              after == before, f"leftover: {after - before}")
        check("never moved to long-term Quarantine",
              db.list_quarantine() == [] and
              not any((tmp / "quarantine").iterdir()))
        stats = db.auto_purge_stats()
        check("storage-freed stat tracked (1 file, exact bytes)",
              stats["files"] == 1 and stats["bytes"] == evil_size,
              f"{stats}")
        audit = [r for r in db.recent_audit() if r["event"] == "auto_purge"]
        check("audit trail logged", len(audit) == 1)

        # ---- check 4: hash-mismatch = refuse, keep the file + no orphan ------
        print("4. file changed since scan -> REFUSED, original kept")
        evil2 = write_malicious(tmp, name="evil2.exe", body=b"E2" + b"\x00" * 80)
        sha2 = (compute_hashes(evil2) or {}).get("sha256")
        db.upsert_signature(sha2, "sha256", "TestDropper2")
        b4_before = {p.name for p in (tmp / "backups").glob("*.bak.aes")}
        rec2 = engine.purge_verified_file(evil2, threat="TestDropper2",
                                          expected_sha="0" * 64)
        check("engine refused (error)", rec2.get("status") == "error",
              str(rec2.get("reason")))
        check("original file still present",
              rec2.get("file_present") is True and evil2.exists())
        b4_after = {p.name for p in (tmp / "backups").glob("*.bak.aes")}
        check("no orphan short-lived backup left behind",
              b4_after == b4_before, f"leftover: {b4_after - b4_before}")

        # ---- check 5: driver fallback = quarantine, never silent delete ------
        print("5. ambiguity fallback -> Quarantine (never delete)")
        q = engine.quarantine_file(evil2, threat="TestDropper2")
        check("refused file ends up quarantined",
              q.get("status") == "quarantined", str(q))
        check("quarantined file blob + backup exist",
              Path(q["store"]).exists() and Path(q["backup"]).exists())
        check("row status quarantined, not purged",
              db.get_quarantine(q["uid"])["status"] == "quarantined")

        # ---- check 6: purge_after_days sweep window --------------------------
        print("6. purge_after_days sweep (db.purge_due + purge_item)")
        old = tmp / "old.exe"
        old.write_bytes(b"OLD" + b"\x00" * 64)
        sha_old = (compute_hashes(old) or {}).get("sha256")
        db.upsert_signature(sha_old, "sha256", "OldDropper")
        fresh = tmp / "fresh.exe"
        fresh.write_bytes(b"NEW" + b"\x00" * 64)
        sha_fresh = (compute_hashes(fresh) or {}).get("sha256")
        db.upsert_signature(sha_fresh, "sha256", "FreshDropper")
        old_q = engine.quarantine_file(old, threat="OldDropper")
        fresh_q = engine.quarantine_file(fresh, threat="FreshDropper")
        db._execute("UPDATE quarantine_items SET created=datetime('now', '-40 days') "
                    "WHERE uid=?", (old_q["uid"],))
        due = [r["uid"] for r in db.purge_due(30)]
        check("only the 40-day-old item is due",
              due == [old_q["uid"]], f"{due}")
        rec_old = engine.purge_item(old_q["uid"])
        check("old item purged", rec_old.get("status") == "purged")
        check("old blobs unlinked",
              not Path(old_q["store"]).exists() and
              not Path(old_q["backup"]).exists())
        check("row kept as 'purged' (audit preserved)",
              db.get_quarantine(old_q["uid"])["status"] == "purged")
        check("purge never stamps restored_at",
              not db.get_quarantine(old_q["uid"]).get("restored_at"))
        check("fresh item untouched",
              db.get_quarantine(fresh_q["uid"])["status"] == "quarantined"
              and Path(fresh_q["store"]).exists())
        # a due row must be purgeable idempotently (missing blobs tolerated)
        rec_basic = engine.purge_item(old_q["uid"])
        check("re-purge of already-purged row is safe",
              rec_basic.get("status") == "purged")

        # baseline auto-purge trail (check 3 logged one row) - checks 7/8 must
        # NOT add to it: prompt/manual approvals never auto-purge.
        baseline_files = db.auto_purge_stats()["files"]
        baseline_ap_paths = {str(r[0]) for r in
                             db._query("SELECT path FROM disinfect_log "
                                       "WHERE action='auto_purge'")}

        # ---- check 7: prompt mode user-approved Disinfect NEVER auto-purges ---
        print("7. prompt mode: user-approved Disinfect keeps Quarantine")
        from types import SimpleNamespace

        evil3 = write_malicious(tmp, name="evil3.exe", body=b"MZ3" + b"\x00" * 200)
        sha3 = (compute_hashes(evil3) or {}).get("sha256")
        db.upsert_signature(sha3, "sha256", "TestDropper3")
        f3 = Finding(path=evil3, category="signature", name="TestDropper3",
                     confidence=1.0, sha256=sha3)
        check("pure-malware candidate qualifies (would auto-purge if silent)",
              is_auto_purge_candidate(evil3, db, f3) is True)

        class _Cfg:
            def get(self, key, default=None):
                return {"quarantine_retention_mode": "auto_purge_verified"}.get(
                    key, default)

        ap_ctx = SimpleNamespace(db=db, cfg=_Cfg())
        prompt_worker = AutoPilotWorker(ap_ctx, updater=None, targets=[],
                                        options=ScanOptions(), policy="prompt")
        import threading as _t
        _t.Timer(0.25, lambda: prompt_worker.respond(DISINFECT)).start()
        prompt_worker._handle_finding(engine, f3)
        check("prompt approval did NOT auto-purge (counter stays 0)",
              prompt_worker.report["auto_purged"] == 0)
        rows3 = [r for r in db.list_quarantine()
                 if r["original_path"] == str(evil3)]
        check("user-approved file captured in Quarantine, not purged",
              len(rows3) == 1 and rows3[0]["status"] == "quarantined")
        check("live copy moved into quarantine (never left in place)",
              not evil3.exists())
        ap_paths = {str(r[0]) for r in
                    db._query("SELECT path FROM disinfect_log "
                              "WHERE action='auto_purge'")}
        check("prompt approval added no auto-purge row",
              ap_paths == baseline_ap_paths and str(evil3) not in ap_paths)
        check("freed-bytes stat unchanged (no auto-purge logged)",
              db.auto_purge_stats()["files"] == baseline_files)

        # ---- check 8: Findings viewer manual 'Clean' path keeps quarantine ---
        print("8. manual 'Clean' (engine.disinfect_file) never purges")
        evil4 = write_malicious(tmp, name="evil4.exe", body=b"MZ4" + b"\x00" * 128)
        sha4 = (compute_hashes(evil4) or {}).get("sha256")
        db.upsert_signature(sha4, "sha256", "TestDropper4")
        f4 = Finding(path=evil4, category="signature", name="TestDropper4",
                     confidence=1.0, sha256=sha4)
        check("pure-malware candidate qualifies",
              is_auto_purge_candidate(evil4, db, f4) is True)
        rec4 = engine.disinfect_file(evil4, dry_run=False)   # = _apply_clean()
        check("manual disinfect lands as quarantined (not deleted)",
              rec4.get("status") == "quarantined",
              str(rec4.get("status")))
        rows4 = [r for r in db.list_quarantine()
                 if r["original_path"] == str(evil4)]
        check("file + encrypted backup kept in Quarantine",
              len(rows4) == 1 and rows4[0]["status"] == "quarantined"
              and Path(rows4[0]["backup_path"]).exists())
        ap_paths8 = {str(r[0]) for r in
                     db._query("SELECT path FROM disinfect_log "
                               "WHERE action='auto_purge'")}
        check("manual Clean added no auto-purge row",
              ap_paths8 == baseline_ap_paths and str(evil4) not in ap_paths8)
        check("still no auto-purge logged for this file",
              db.auto_purge_stats()["files"] == baseline_files)

        # ---- check 9: SILENT auto flow DOES auto-purge (positive control) -----
        print("9. silent 'auto' flow auto-purges (positive control)")
        evil5 = write_malicious(tmp, name="evil5.exe", body=b"MZ5" + b"\x00" * 96)
        sha5 = (compute_hashes(evil5) or {}).get("sha256")
        db.upsert_signature(sha5, "sha256", "TestDropper5")
        f5 = Finding(path=evil5, category="signature", name="TestDropper5",
                     confidence=1.0, sha256=sha5)
        auto_worker = AutoPilotWorker(ap_ctx, updater=None, targets=[],
                                      options=ScanOptions(), policy="auto")
        auto_worker._handle_finding(engine, f5)
        check("silent auto DID auto-purge (counter 1)",
              auto_worker.report["auto_purged"] == 1,
              f"{auto_worker.report['auto_purged']}")
        check("original gone, no quarantine row captured",
              not evil5.exists() and
              not [r for r in db.list_quarantine()
                   if r["original_path"] == str(evil5)])
        check("freed-bytes stat incremented exactly once more",
              db.auto_purge_stats()["files"] == baseline_files + 1)

        print(f"\nAuto-Purge Mode: {sum(CHECKS)}/{len(CHECKS)} checks passed")
        return 0 if all(CHECKS) else 1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # keep the traceback meaningful on failure
        print(f"\nAuto-Purge Mode: FAIL ({exc})", file=sys.stderr)
        raise