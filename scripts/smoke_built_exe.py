#!/usr/bin/env python3
"""smoke_built_exe.py - POST-BUILD smoke test of the FROZEN SecuDrive binary.

MANDATORY RELEASE GATE: every future fix must be verified against this script's
checks on the ACTUAL built .exe, not source.  Run it from an ELEVATED shell
(the exe requests UAC admin at launch):

    python scripts/smoke_built_exe.py                 # dist\\SecuDrive.exe
    python scripts/smoke_built_exe.py C:/path/SecuDrive.exe

Happens entirely inside a throwaway sandbox dir (SECUDRIVE_BASE_DIR + --base):
the user's real AppData state is NEVER touched.  Steps:
  1. --cli --help                       : frozen argv/entry parses
  2. --cli scan <sandbox> --base        : frozen scanner + db boot, files seen
3. --cli disinfect <payload.jpg>       : frozen recovery engine strips payload
                                           (backup+verify), file shrinks
   4. --cli quarantine + restore roundtrip : frozen cipher restore returns the file
                                           with byte-exact content AND the DB row
                                           transitions quarantined -> restored
   4c. --cli restore on a deliberately corrupted blob: rc != 0, the failure reason
     is printed (never a silent do-nothing), and the row stays quarantined - never
     silently flipped to a green "Restored".
   5. GUI launch (windowed) with SECUDRIVE_BASE_DIR: process alive after N s and
     drops an 'app_start' debug log line (frozen PyQt6 surface boots).

MANDATORY GATE: a fix is NOT fixed/shipped until this script passes against the
actual rebuilt .exe - source-only passes are never accepted as done.
"""
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJ = Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive")
DEFAULT_EXE = PROJ / "dist" / "SecuDrive.exe"

CHECKS: list = []


def check(name: str, ok: bool, extra: str = "") -> None:
    CHECKS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {extra}" if extra else ""))


def run_exe(exe: Path, args: list, env: dict | None = None, timeout: int = 180):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    proc = subprocess.run(
        [str(exe), *args], capture_output=True, text=True,
        env=full_env, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def main() -> int:
    exe = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EXE
    if not exe.exists():
        print(f"built exe not found: {exe}", file=sys.stderr)
        return 1

    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-exe-smoke-"))
    print(f"built exe : {exe}")
    print(f"sandbox   : {sandbox}\n")

    # --- 1. frozen CLI entry parses -----------------------------------------
    print("1. --cli --help (frozen entry/imports)")
    rc, out, err = run_exe(exe, ["--cli", "--help"])
    check("rc == 0", rc == 0, f"rc={rc}")
    check("usage text present", "usage" in out.lower() or "usage" in err.lower())

    # --- 2. frozen scanner + database over the sandbox ----------------------
    print("2. --cli scan <sandbox> (frozen scanner/db/crypto boot)")
    victim = sandbox / "photo.jpg"
    victim.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 200 + b"\xff\xd9"
                       + b"\x00" * 3000)
    orig_size = victim.stat().st_size
    rc, out, err = run_exe(exe, ["--cli", "--base", str(sandbox), "scan", str(sandbox)])
    check("rc == 0", rc == 0, f"rc={rc}")
    scan_files = re.search(r"files[^0-9]*(\d+)", out, re.I)
    check("files seen > 0", bool(scan_files) and int(scan_files.group(1)) > 0,
          str(scan_files.group(1)) if scan_files else out[:120])
    trailing = re.search(r"TrailingPayload", out, re.I)
    if trailing:
        check("TrailingPayload heuristic fires on recovered-style jpeg", True)
    else:
        print("  [note] no TrailingPayload text in scan output (not fatal here)")
        check("TrailingPayload heuristic fires on recovered-style jpeg", False,
              "heuristic did not fire - inspect output below")
        print(out[-600:])

    # --- 3. frozen disinfect strips payload (backup + verify) ----------------
    print("3. --cli disinfect (frozen recovery engine strips payload)")
    rc, out, err = run_exe(exe, ["--cli", "--base", str(sandbox), "disinfect", str(victim)])
    check("rc == 0", rc == 0, f"rc={rc}")
    stripped = victim.exists() and victim.stat().st_size < orig_size
    check("payload stripped (file shrank)", stripped,
         f"{orig_size} -> {victim.stat().st_size if victim.exists() else 'gone'}")

    # --- 4. frozen quarantine + restore round-trip --------------------------
    print("4. --cli quarantine + restore round-trip (frozen cipher)")
    evil = sandbox / "evil.exe"
    payload = b"MZ" + b"\x00" * 150
    evil.write_bytes(payload)
    rc, out, err = run_exe(exe, ["--cli", "--base", str(sandbox), "quarantine",
                                 str(evil), "--threat", "SmokeTest"])
    check("quarantine rc == 0", rc == 0, f"rc={rc}")
    # quarantine_moves the original out of place - it is already gone from here
    m = re.search(r"uid['\"]?\s*[:=]\s*['\"]?([0-9a-f]{24,40})", out, re.I) \
        or re.search(r"([0-9a-f]{32})", out)
    check("quarantine uid captured", bool(m), out[-200:])
    uid = m.group(1) if m else ""
    rc, out, err = run_exe(exe, ["--cli", "--base", str(sandbox), "restore", uid])
    check("restore rc == 0", rc == 0, f"rc={rc}")
    check("file restored with exact bytes",
          evil.exists() and evil.read_bytes() == payload)

    # --- 4b. DB row status transition (quarantined -> restored) ---------------
    print("4b. row status transition in the sandbox DB")
    db_path = sandbox / "data" / "secudrive.db"
    con = sqlite3.connect(db_path)
    row_status = con.execute(
        "SELECT status FROM quarantine_items WHERE uid=?", (uid,)).fetchone()
    con.close()
    check("row status == restored (not just file-on-disk)",
          bool(row_status) and row_status[0] == "restored",
          str(row_status))

    # --- 4c. corrupted blob: restore must FAIL LOUDLY, never silently ---------
    print("4c. corrupted backup restore (must surface failure, not go green)")
    evil2 = sandbox / "evil2.exe"
    evil2.write_bytes(b"MZ" + b"\x00" * 150)
    rc, out, err = run_exe(exe, ["--cli", "--base", str(sandbox), "quarantine",
                                 str(evil2), "--threat", "SmokeCorrupt"])
    check("quarantine #2 rc == 0", rc == 0, f"rc={rc}")
    m2 = re.search(r"uid['\"]?\s*[:=]\s*['\"]?([0-9a-f]{24,40})", out, re.I) \
        or re.search(r"([0-9a-f]{32})", out)
    check("quarantine #2 uid captured", bool(m2), out[-200:])
    uid2 = m2.group(1) if m2 else ""
    blob2 = sandbox / "data" / "backups" / f"{uid2}.bak.aes"
    check("corrupt target blob present at expected path", blob2.exists(),
          str(blob2))
    blob2.write_bytes(b"\x00" * 64)       # smash the ciphertext into garbage
    rc, out, err = run_exe(exe, ["--cli", "--base", str(sandbox), "restore", uid2])
    combined = (out or "") + (err or "")
    check("corrupt restore rc != 0 (failure is a real exit code)",
          rc != 0, f"rc={rc}")
    check("failure reason surfaced in output (never silent)",
          "corrupt" in combined.lower() and "implausible" in combined.lower(),
          combined[-220:].replace("\n", " "))
    con = sqlite3.connect(db_path)
    corrupt_status = con.execute(
        "SELECT status FROM quarantine_items WHERE uid=?", (uid2,)).fetchone()
    con.close()
    check("row NOT flipped to a green restored (stays quarantined)",
          bool(corrupt_status) and corrupt_status[0] == "quarantined",
          str(corrupt_status))

    # --- 5. frozen GUI surface boots (windowed, sandboxed) ------------------
    print("5. GUI launch (windowed, SECUDRIVE_BASE_DIR=sandbox)")
    gui_env = {"SECUDRIVE_BASE_DIR": str(sandbox)}
    proc = subprocess.Popen([str(exe)], env={**os.environ, **gui_env})
    time.sleep(20)
    if proc.poll() is None:
        alive = True
        proc.kill()
    else:
        alive = False
        print(proc.returncode)
    check("windowed GUI alive after 20s (no frozen boot crash)", alive)
    log = sandbox / "secudrive_debug.log"
    if log.exists():
        check("GUI wrote app_start debug line",
              "app_start" in log.read_text(errors="ignore"))
    else:
        check("GUI wrote app_start debug line", False, "no log file")

    print(f"\nBuilt-exe smoke: {sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())