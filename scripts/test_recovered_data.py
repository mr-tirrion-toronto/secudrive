#!/usr/bin/env python3
"""test_recovered_data.py - P0 regression: OS/filesystem-recovery artifacts
(LOST.DIR, FOUND.NNN, $RECYCLE.BIN, macOS recovery dirs) must NEVER be
auto-acted on (no auto-disinfect / auto-quarantine / auto-purge) and must be
routed to explicit manual review instead.  Guards the real-world false-positive
where 550 LOST.DIR media files were quarantined by the disinfect fallback.
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
    from secudrive.heuristics import is_recovery_data_path

    print("1. is_recovery_data_path() matching matrix")
    cases = [
        (True, r"E:\LOST.DIR\123454321"),
        (True, r"F:\Richard D-Backup\personal\sim\LOST.DIR\10149"),
        (True, r"/storage/sdcard1/LOST.DIR/42"),
        (True, r"F:\something\lost.dir\19"),
        (True, r"D:\FOUND.000\file1"),
        (True, r"D:\FOUND.005\file2"),
        (True, r"C:\$Recycle.Bin\S-1-5-18\$R71XWY3"),
        (True, r"C:\System Volume Information\_restore{abc}"),
        (True, r"/home/u/.Trash-1000/files/x.jpg"),
        (True, r"/Volumes/x/.Trashes/501/x"),
        (True, r"/Volumes/x/.Spotlight-V100/Store-V1/idx"),
        (True, r"/Volumes/x/.fseventsd/0000008f"),
        (True, r"/Volumes/x/.TemporaryItems/folders.501"),
        (False, r"FOUND.0009/file"),                 # 4 digits -> not chkdsk
        (False, r"D:\FOUND9\file"),                  # malformed
        (False, r"C:\Users\Me\Desktop\photo.jpg"),
        (False, r"C:\Windows\System32\drivers\etc\hosts"),
        (False, r"E:\Downloads\found.000.exe"),      # file, not dir component
        (False, r"/home/u/Documents/report.pdf"),
    ]
    for want, p in cases:
        check(f"{p} -> {want}", is_recovery_data_path(p) is want)

    # ---- 2. real engine + autopilot: silent auto NEVER acts on LOST.DIR ----
    from types import SimpleNamespace

    from secudrive.database import Database
    from secudrive.recovery import (RecoveryEngine, is_auto_purge_candidate)
    from secudrive.crypto import generate_key
    from secudrive.autopilot import AutoPilotWorker
    from secudrive.scanner import Finding, ScanOptions
    from secudrive.safefile import compute_hashes
    from secudrive.config import Config

    base = tempfile.mkdtemp(prefix="secudrive-recv-")
    data = Path(base) / "data"; data.mkdir()
    bdir = Path(base) / "backups"; bdir.mkdir()
    qdir = Path(base) / "quarantine"; qdir.mkdir()
    key = generate_key()
    db = Database(Path(base) / "data" / "secudrive.db")
    cfg = Config(Path(base) / "config.json")
    cfg.set("quarantine_retention_mode", "auto_purge_verified")
    engine = RecoveryEngine(db, bdir, qdir, key=key)

    lost = Path(base) / "LOST.DIR"
    lost.mkdir()
    victim = lost / "10149"
    victim.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 300 + b"\xff\xd9"
                       + b"\x00" * 5000)
    original_size = victim.stat().st_size
    sha = (compute_hashes(victim) or {}).get("sha256")
    db.upsert_signature(sha, "sha256", "EICAR-SIM")   # "would match" in signatures

    f = Finding(path=victim, category="signature", name="Signature:EICAR-SIM",
                confidence=1.0, sha256=sha)
    check("auto-purge classifier REJECTS recovery-data paths",
          is_auto_purge_candidate(victim, db, f) is False)

    class _Cfg:
        def get(self, key, default=None):
            return cfg.get(key, default)

    ctx = SimpleNamespace(db=db, cfg=_Cfg())
    worker = AutoPilotWorker(ctx, updater=None, targets=[],
                             options=ScanOptions(), policy="auto")
    worker._handle_finding(engine, f)
    check("auto mode did NOT disinfect/quarantine/purge",
          worker.report["disinfected"] == 0
          and worker.report["quarantined"] == 0
          and worker.report["auto_purged"] == 0)
    check("auto mode counted it as requires-manual-review",
          worker.report["requires_manual_review"] == 1,
          str(worker.report["requires_manual_review"]))
    check("file left untouched on disk",
          victim.exists() and victim.stat().st_size == original_size)
    check("no quarantine row created",
          len(db.list_quarantine()) == 0)
    check("no auto-purge logged",
          not db._query("SELECT 1 FROM disinfect_log WHERE action='auto_purge'"))

    # ---- 3. a genuinely malicious file OUTSIDE recovery dirs still works ----
    evil = Path(base) / "evil.exe"
    evil.write_bytes(b"MZ" + b"\x00" * 200)
    esha = (compute_hashes(evil) or {}).get("sha256")
    db.upsert_signature(esha, "sha256", "TestDropper")
    fe = Finding(path=evil, category="signature", name="Signature:TestDropper",
                 confidence=1.0, sha256=esha)
    worker2 = AutoPilotWorker(ctx, updater=None, targets=[],
                              options=ScanOptions(), policy="auto")
    worker2._handle_finding(engine, fe)
    check("normal malware still auto-purges (path not in recovery dirs)",
          worker2.report["auto_purged"] == 1,
          str(worker2.report))

    print(f"\nRecovered-data regression: {sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())