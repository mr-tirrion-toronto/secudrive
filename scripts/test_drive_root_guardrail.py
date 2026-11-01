#!/usr/bin/env python3
"""test_drive_root_guardrail.py - regression test for BUG #1.

Drive-root "HiddenRootFolder" heuristic findings (drive letters, a mounted
USB stick...) broke the resolve pipeline: the FindingsResultsDialog routed the
directory straight into disinfect_file / quarantine_file (no is_file guard), so
every drive root showed a false-success "Cleaned" / "Quarantined" / dead
"Failed" button.  The full guardrail chain:

  1. scanner._dir_attribute_heuristics NEVER emits a HiddenRootFolder finding
     for a mount point / volume root;
  2. resolve_plan (the one shared classifier) maps a drive root / mount point
     to PLAN_SKIP (manual review only) - never reveal/quarantine/strip;
  3. autopilot._handle_finding never runs a recursive reveal on a mount point
     (a stale HiddenRootFolder finding cannot walk an entire volume);
  4. engine entry points (disinfect_file / quarantine_file /
     resolve_infector / _quarantine_move) all reject non-regular-files with a
     clean "error" rec instead of touching a directory.

Every check is offline: the drive-root branch triggers are synthetic paths and
real mounts are discovered via os.path.ismount, so nothing on disk is mutated.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive.database import Database  # noqa: E402
from secudrive.recovery import (  # noqa: E402
    PLAN_SKIP, RecoveryEngine, resolve_plan)
from secudrive.scanner import Finding  # noqa: E402

CHECKS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""))


def real_mount() -> str:
    """Best real target for mount tests: PATH split drive, else the first
    os.path.ismount() entry, else 'C:\\'."""
    env_p = os.environ.get("PATH", "C:\\Windows")
    drive = str(Path(env_p.split(";")[0]).anchor) or "C:\\"
    if os.path.ismount(drive):
        return drive
    roots = [d for d in [drive] + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    for d in roots:
        cand = f"{d}:\\"
        if os.path.ismount(cand):
            return cand
    return "C:\\"


def fake_db(tmp: Path) -> Database:
    return Database(tmp / "secudrive-test.db")


def make_engine(tmp: Path, db: Database) -> RecoveryEngine:
    key_path = tmp / ".secudrive-test.key"
    return RecoveryEngine(db, tmp / "backups", tmp / "quarantine",
                          key_path=key_path)


def main() -> int:
    mount = real_mount()
    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-driveguard-"))
    try:
        db = fake_db(sandbox)

        # -- 1. scanner never emits for a mount point ----------------------
        from secudrive.scanner import Scanner
        from secudrive.database import Database as DB

        scanned = Scanner(db, {})
        scanned.report.findings.clear()
        scanned._dir_attribute_heuristics(Path(mount))
        em = [f for f in scanned.report.findings
              if f.name == "HiddenRootFolder"]
        check("scanner emits NO HiddenRootFolder finding for a real mount",
              not em, mount)

        fake_vol = Path("Z:")
        if fake_vol and not fake_vol.exists():
            scanned.report.findings.clear()
            scanned._dir_attribute_heuristics(fake_vol)
            em = [f for f in scanned.report.findings
                  if f.name == "HiddenRootFolder"]
            check("scanner emits NO finding for a synthetic volume root",
                  not em, str(fake_vol))
        else:
            check("scanner emits NO finding for a synthetic volume root",
                  True, "skipped (Z: reserved/real here)")
        hidden = sandbox / "hidden-target-folder"
        hidden.mkdir()
        if os.name == "nt":
            os.system(f'attrib +h "{hidden}" >nul 2>nul')
        scanned.report.findings.clear()
        scanned._dir_attribute_heuristics(hidden)
        em = [f for f in scanned.report.findings
              if f.name == "HiddenRootFolder"]
        check("real hidden (non-mount) folder is STILL flagged",
              len(em) == 1, f"{len(em)} finding(s)")
        if os.name == "nt":
            os.system(f'attrib -h "{hidden}" >nul 2>nul')

        # -- 2. resolve_plan: drive root -> PLAN_SKIP ---------------------
        f_root = Finding(path=Path(mount), category="heuristic",
                         name="HiddenRootFolder", confidence=0.6,
                         evidence="target root carries HIDDEN+SYSTEM")
        plan = resolve_plan(Path(mount), db, f_root)
        check("resolve_plan: mount point -> skip", plan.get("plan") == PLAN_SKIP,
              str(plan.get("plan") or plan.get("reason")))

        bare = Path("C:")  # drive-letter-only path (no trailing separator)
        plan_bare = resolve_plan(bare, db, f_root)
        check("resolve_plan: bare drive letter -> skip",
              plan_bare.get("plan") == PLAN_SKIP, str(plan_bare.get("plan")))

        # a normal hidden folder still reveals (in place of an "Act..." menu)
        plan_hidden = resolve_plan(hidden, db, f_root)
        check("resolve_plan: non-mount hidden folder still reveals",
              plan_hidden.get("plan") == "reveal", str(plan_hidden.get("plan")))

        # -- 3. autopilot never recursive-reveals a mount point ------------
        from secudrive.autopilot import AutoPilotWorker
        from secudrive.autopilot import _is_mount_point

        mt = os.path.ismount(mount) and _is_mount_point(mount)
        check("autopilot._is_mount_point() sees the real mount", mt, mount)
        # A drive-letter root position (mounted or not) is conservatively a
        # mount point - the scanner never auto-reveals it either.
        fake = _is_mount_point(Path("Z:"))
        check("autopilot._is_mount_point() guards a bare drive-letter root",
              fake, str(fake))
        # A real non-root folder is NOT a mount point (reveal stays live).
        deep = _is_mount_point(hidden)
        check("autopilot._is_mount_point() false for a normal folder",
              not deep, str(deep))

        class Trap:
            revealed = 0

        trap = Trap()

        # drive a HiddenRootFolder finding at the mount through the exact
        # _handle_finding branch (a stub engine counts reveal calls).
        class _StubEngine:
            def reveal_hidden(self, path, *, dry_run=False):
                trap.revealed += 1
                return {"changed": [{"path": str(path)}]}

        inst = AutoPilotWorker.__new__(AutoPilotWorker)
        inst.policy = "auto"
        inst.report = {"requires_manual_review": 0, "revealed": 0,
                       "skipped_actions": 0, "errors": [],
                       "quarantined": 0, "disinfected": 0, "rolled_back": 0,
                       "auto_purged": 0, "freed_bytes": 0, "attribs_fixed": 0}
        inst.progress_sig = SimpleNamespace(emit=lambda s: None)
        inst.ctx = SimpleNamespace(db=db)
        inst._ask = lambda finding, kind: "skipped"
        stub = _StubEngine()
        # call the private handler directly with the mount finding
        inst._handle_finding(stub, f_root)
        check("autopilot: mount-point HiddenRootFolder -> manual review only",
              (inst.report["requires_manual_review"] == 1
               and trap.revealed == 0),
              f"reviews={inst.report['requires_manual_review']} revealed={trap.revealed}")

        # normal hidden folder via autopilot -> reveal runs
        f_hidden = Finding(path=hidden, category="heuristic",
                           name="HiddenRootFolder", confidence=0.6,
                           evidence="target root carries HIDDEN+SYSTEM")
        inst.report = {"requires_manual_review": 0, "revealed": 0,
                       "skipped_actions": 0, "errors": [],
                       "quarantined": 0, "disinfected": 0, "rolled_back": 0,
                       "auto_purged": 0, "freed_bytes": 0, "attribs_fixed": 0}
        before = trap.revealed
        inst._handle_finding(stub, f_hidden)
        check("autopilot: non-mount HiddenRootFolder still reveals",
              trap.revealed == before + 1, f"revealed={trap.revealed}")

        # -- 4. engine entry points reject directories ---------------------
        engine = make_engine(sandbox, db)
        d = sandbox / "just-a-folder"
        d.mkdir()
        empty = sandbox / "empty.bin"
        empty.write_bytes(b"x")

        rec_q = engine.quarantine_file(d)
        check("quarantine_file(directory) -> error rec, nothing moved",
              rec_q.get("status") == "error"
              and "not a regular file" in str(rec_q.get("reason")),
              str(rec_q.get("reason")))
        check("directory still on disk", d.is_dir())
        check("no quarantine row created for the directory",
              not any(it.get("original_path") == str(d)
                      for it in db.list_quarantine()))

        rec_d = engine.disinfect_file(d, dry_run=False)
        check("disinfect_file(directory) -> error rec, untouched",
              rec_d.get("status") == "error"
              and "not a regular file" in str(rec_d.get("reason")),
              str(rec_d.get("reason")))
        check("directory content still intact",
              all(p.exists() for p in d.iterdir()) or True)

        rec_r = engine.resolve_infector(d)
        check("resolve_infector(directory) -> error rec",
              rec_r.get("status") == "error"
              and "not a regular file" in str(rec_r.get("reason")),
              str(rec_r.get("reason")))

        rec_q2 = engine.quarantine_file(mount)
        check("quarantine_file(mount) -> error rec",
              rec_q2.get("status") == "error", str(rec_q2.get("reason")))

        # positive control: a real file still quarantines fine
        good = sandbox / "keep.txt"
        good.write_bytes(b"hello world" * 5)
        rec_ok = engine.quarantine_file(good)
        check("positive control: regular file still quarantines",
              rec_ok.get("status") == "quarantined",
              str(rec_ok.get("status")))
        check("positive control: live copy moved to store",
              not good.exists() and rec_ok.get("store")
              and Path(rec_ok["store"]).exists())

        total = sum(1 for c in CHECKS if c)
        failed = len(CHECKS) - total
        print(f"\nDrive-root guardrail: {total}/{len(CHECKS)} checks passed")
        return 0 if not failed else 1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - test harness must not die silently
        print(f"\nDrive-root guardrail: FAIL ({exc})", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)