#!/usr/bin/env python3
"""fallback_smoke.py - verify scanner.py still works via the pure-Python
engine after the Rust integration changes (run with the *unmodified* engine
installed, i.e. secudrive_rust NOT present -> exercises the fallback path)."""
import os
import sys
import tempfile
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "scanner.py").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

import secudrive.scanner as scanner_mod  # noqa: E402
from secudrive.scanner import ScanOptions, Scanner, ScanCancelled  # noqa: E402

os.environ["SECUDRIVE_RUST_DISABLE"] = "1"  # force fallback deterministically


class NullDb:
    def lookup(self, *a, **k):
        return None

    def record_findings(self, *a, **k):
        return 0


def main() -> int:
    rust = scanner_mod._rust_engine()
    print(f"rust engine detected: {rust}")
    assert rust is None, "fallback smoke expects the rust engine to be absent"

    root = Path(tempfile.mkdtemp(prefix="sd_fallback_"))
    try:
        (root / "a.txt").write_text("hello world")
        (root / "sub").mkdir()
        (root / "sub" / "b.dat").write_bytes(b"\x00" * 2048)
        (root / "sub" / "c").write_bytes(b"")          # zero-byte file
        (root / "skipped.windows").write_text("excluded-name file")
        (root / "node_modules").write_text("exact excluded file-name match")
        (root / "windows").mkdir()                     # excluded directory
        (root / "windows" / "win.txt").write_text("never scanned")

        opts = ScanOptions()
        scanner = Scanner(NullDb(), opts, progress=lambda info: None)
        report = scanner.scan([root])
        report.finish()
        print(f"dir scan : files={report.files_seen} dirs={report.dirs_seen} "
              f"bytes={report.bytes_scanned} errors={report.errors}")
        # Files counted: a.txt, sub/b.dat, sub/c, skipped.windows.
        # "node_modules" matches an excluded name exactly -> skipped.
        # "windows/" is excluded -> not entered (win.txt never seen).
        assert report.files_seen == 4, report.files_seen
        assert report.dirs_seen == 2, report.dirs_seen    # root + sub
        assert report.bytes_scanned == 2048 + 11 + 18, report.bytes_scanned
        assert report.errors == 0
        assert not report.findings

        # single-file target (non-dir path must still exercise _scan_file)
        scanner2 = Scanner(NullDb(), ScanOptions())
        rep2 = scanner2.scan([root / "a.txt"])
        assert rep2.files_seen == 1, rep2.files_seen

        # cancellation unwinds cleanly
        sc = Scanner(NullDb(), ScanOptions())
        sc.cancel()
        rep3 = sc.scan([root])
        assert rep3.finished, "cancel should return a finished report"

        # rust fallback on a dir target when the engine is present-but-disabled
        print("fallback smoke: PASS")
        return 0
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())