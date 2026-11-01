#!/usr/bin/env python3
"""test_immediate_resolve.py - regression test for the IMMEDIATE-RESOLVE default.

Guards the behavior change end to end (config -> autopilot -> engine -> report):

  * the platform default is resolve-first: ``on_detection == 'resolve'`` and
    ``quarantine_retention_mode == 'auto_purge_verified'``;
  * the SILENT auto flow resolves a strip-able finding IN PLACE (file stays,
    payload gone, no quarantine row, no auto-purge) - the new default;
  * with the retention default enabled, a pure-malware executable still goes
    through the silent-only Auto-Purge path (positive control, unchanged);
  * prompt mode: user-approved Disinfect resolves in place; user-approved
    Quarantine moves the file to the store;
  * the opt-in ``on_detection == 'quarantine'`` restores the OLD
    always-quarantine behavior for the auto flow AND the manual bulk path
    (Findings viewer "Clean All");
  * the manual per-item "Clean" tool (engine.disinfect_file) still resolves
    in place regardless of the opt-in config.
"""
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive import recovery as recovery_mod  # noqa: E402
from secudrive.autopilot import DISINFECT, QUARANTINE, AutoPilotWorker  # noqa: E402
from secudrive.config import DEFAULT_CONFIG  # noqa: E402
from secudrive.database import Database  # noqa: E402
from secudrive.recovery import RecoveryEngine, resolve_plan  # noqa: E402
from secudrive.safefile import compute_hashes  # noqa: E402
from secudrive.scanner import Finding, ScanOptions  # noqa: E402

CHECKS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""))


class _Cfg:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def get(self, key, default=None):
        return self.values.get(key, default)


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


def worker(policy: str, ctx) -> AutoPilotWorker:
    return AutoPilotWorker(ctx, updater=None, targets=[], options=ScanOptions(),
                           policy=policy)


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-resolve-"))
    try:
        print("0. platform defaults")
        check("config on_detection defaults to 'resolve'",
              str(DEFAULT_CONFIG.get("on_detection")) == "resolve")
        check("config quarantine_retention_mode defaults to auto_purge_verified",
              str(DEFAULT_CONFIG.get("quarantine_retention_mode"))
              == "auto_purge_verified")

        tmp = sandbox / "ai"
        tmp.mkdir(parents=True)
        db, engine = make_engine(tmp)
        auto_cfg = _Cfg({"quarantine_retention_mode": "auto_purge_verified"})
        ap_ctx = SimpleNamespace(db=db, cfg=auto_cfg)

        print("1. auto flow: strip-able finding is RESOLVED IN PLACE (new default)")
        jpeg = write_jpeg(tmp)
        sha = (compute_hashes(jpeg) or {}).get("sha256")
        db.upsert_signature(sha, "sha256", "EvilCode")
        auto = worker("auto", ap_ctx)
        before_size = jpeg.stat().st_size
        captured: dict = {}
        orig_backup_file = recovery_mod.backup_file

        def spy(src, *a, **k):
            captured["size"] = Path(src).stat().st_size
            captured["res"] = orig_backup_file(src, *a, **k)
            return captured["res"]

        recovery_mod.backup_file = spy
        try:
            auto._handle_finding(engine, Finding(
                path=jpeg, category="signature", name="EvilCode",
                confidence=1.0, sha256=sha))
        finally:
            recovery_mod.backup_file = orig_backup_file
        check("disinfected counter == 1", auto.report["disinfected"] == 1,
              str(auto.report["disinfected"]))
        check("NOT auto-purged", auto.report["auto_purged"] == 0)
        check("NOT quarantined",
              auto.report["quarantined"] == 0
              and not [r for r in db.list_quarantine()
                       if r["original_path"] == str(jpeg)])
        check("fixed file keeps its original path", jpeg.exists())
        check("payload stripped in place",
              b"PAYLOADJUNK" not in jpeg.read_bytes())
        check("pre-attempt encrypted backup secured before resolve (zero data loss)",
              captured.get("size") == before_size, str(captured))
        check("short-lived backup purged on successful resolve",
              not any((tmp / "backups").glob("*.bak.aes")))

        print("2. auto flow + retention default: pure malware still auto-purges")
        evil = write_mz(tmp)
        sha_e = (compute_hashes(evil) or {}).get("sha256")
        db.upsert_signature(sha_e, "sha256", "TestDropper")
        auto2 = worker("auto", ap_ctx)
        auto2._handle_finding(engine, Finding(
            path=evil, category="signature", name="TestDropper",
            confidence=1.0, sha256=sha_e))
        check("silent auto auto-purged the pure-malware exe",
              auto2.report["auto_purged"] == 1 and not evil.exists(),
              str(auto2.report))
        check("freed bytes counted", auto2.report["freed_bytes"] > 0)

        print("3. prompt mode: Disinfect resolves in place, Quarantine moves")
        jpeg3 = write_jpeg(tmp, name="photo3.jpg")
        ap3 = worker("prompt", ap_ctx)
        threading.Timer(0.2, lambda: ap3.respond(DISINFECT)).start()
        ap3._handle_finding(engine, Finding(
            path=jpeg3, category="heuristic", name="TrailingPayload",
            confidence=0.82))
        check("prompt Disinfect -> resolved in place",
              ap3.report["disinfected"] == 1 and jpeg3.exists()
              and b"PAYLOADJUNK" not in jpeg3.read_bytes(),
              str(ap3.report))

        jpeg4 = write_jpeg(tmp, name="photo4.jpg")
        ap4 = worker("prompt", ap_ctx)
        threading.Timer(0.2, lambda: ap4.respond(QUARANTINE)).start()
        ap4._handle_finding(engine, Finding(
            path=jpeg4, category="heuristic", name="TrailingPayload",
            confidence=0.82))
        check("prompt Quarantine -> moved to store",
              ap4.report["quarantined"] == 1 and not jpeg4.exists()
              and [r for r in db.list_quarantine()
                   if r["original_path"] == str(jpeg4)],
              str(ap4.report))

        print("4. opt-in on_detection='quarantine' restores old behavior")
        jpeg5 = write_jpeg(tmp, name="photo5.jpg")
        opt_cfg = _Cfg({"on_detection": "quarantine",
                        "quarantine_retention_mode": "auto_purge_verified"})
        opt_ctx = SimpleNamespace(db=db, cfg=opt_cfg)
        auto5 = worker("auto", opt_ctx)
        auto5._handle_finding(engine, Finding(
            path=jpeg5, category="heuristic", name="TrailingPayload",
            confidence=0.82))
        check("strip-able jpeg MOVED to quarantine under the opt-in",
              auto5.report["quarantined"] == 1
              and auto5.report["disinfected"] == 0 and not jpeg5.exists(),
              str(auto5.report))
        check("no in-place bytes were stripped",
              [r for r in db.list_quarantine()
               if r["original_path"] == str(jpeg5)][0]["status"] == "quarantined")

        print("5. manual bulk path (Findings 'Clean All') agrees")
        jpeg6 = write_jpeg(tmp, name="photo6.jpg")
        row6 = {"path": str(jpeg6), "category": "heuristic",
                "name": "TrailingPayload", "confidence": 0.82}
        rec = engine.execute_plan(resolve_plan(jpeg6, db, row6,
                                               config=auto_cfg), jpeg6, row6)
        check("default config bulk clean -> resolved in place",
              rec.get("outcome") == "resolved_in_place" and jpeg6.exists(),
              str(rec))
        jpeg7 = write_jpeg(tmp, name="photo7.jpg")
        row7 = {"path": str(jpeg7), "category": "heuristic",
                "name": "TrailingPayload", "confidence": 0.82}
        rec7 = engine.execute_plan(resolve_plan(jpeg7, db, row7,
                                                config=opt_cfg), jpeg7, row7)
        check("opt-in config bulk clean -> always quarantined (old behavior)",
              rec7.get("outcome") == "quarantined_removed" and not jpeg7.exists(),
              str(rec7))

        print("6. manual per-item 'Clean' (disinfect_file) is unaffected")
        jpeg8 = write_jpeg(tmp, name="photo8.jpg")
        rec8 = engine.disinfect_file(jpeg8, dry_run=False)
        check("per-item tool still resolves in place regardless of config",
              rec8.get("status") == "stripped" and jpeg8.exists()
              and b"PAYLOADJUNK" not in jpeg8.read_bytes(), str(rec8))

        print(f"\nImmediate-resolve: {sum(CHECKS)}/{len(CHECKS)} checks passed")
        return 0 if all(CHECKS) else 1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nImmediate-resolve: FAIL ({exc})", file=sys.stderr)
        raise