#!/usr/bin/env python3
"""benchmark.py - before/after scanner throughput comparison.

Generates a synthetic tree of many small files (default 20,000), times the
pure-Python scan engine vs the compiled Rust engine, and cross-checks the
hashes the Rust engine produces against Python's hashlib on a sample.

Usage:
    python benchmark.py                # 20,000 files, both engines
    python benchmark.py --files 50000  # bigger tree
    python benchmark.py --keep         # keep the generated tree on disk
"""
from __future__ import annotations

import argparse
import hashlib
import random
import shutil
import tempfile
import time
from pathlib import Path

from secudrive.scanner import ScanOptions, Scanner

SAMPLE = 40


class NullDb:
    """Minimal stand-in: benchmark only exercises scan + hashing."""

    def lookup(self, *a, **k):
        return None

    def record_findings(self, *a, **k):
        return 0


def build_tree(root: Path, file_count: int, seed: int = 12345) -> None:
    """Deterministic small-file tree (walk depth up to 3, nested dirs)."""
    rng = random.Random(seed)
    root.mkdir(parents=True, exist_ok=True)
    for i in range(file_count):
        depth = rng.randint(0, 3)
        parts = [f"d{rng.randint(0, 12)}" for _ in range(depth)]
        sub = root.joinpath(*parts)
        sub.mkdir(parents=True, exist_ok=True)
        kind = i % 7
        if kind == 0:
            body, fname = b"", f"f{i:08d}.empty"
        else:
            size = ({1: 128, 2: 2048, 3: 64 * 1024}.get(kind) or 4096)
            base = f"f{i:08d}".encode() * (size // 16 + 1)
            body = base[:size]
            fname = f"f{i:08d}.txt"
        (sub / fname).write_bytes(body)


def time_scan(root: Path, opts: ScanOptions) -> tuple[float, int, int]:
    scanner = Scanner(NullDb(), opts, progress=lambda info: None)
    t0 = time.perf_counter()
    report = scanner.scan([root])
    return time.perf_counter() - t0, report.files_seen, report.bytes_scanned


def verify_hashes(root: Path, rust_module) -> int:
    """Compare Rust-produced hashes against hashlib for a sample of files."""
    outcome = rust_module.scan_directory(
        str(root), hash_algo="sha256+md5",
        max_hash_size=512 * 1024 * 1024, max_depth=0,
        follow_symlinks=False, exclude_dirs=sorted({".git", "node_modules"}),
        threads=0, progress_cb=None, cancel_cb=None,
    )
    candidates = [r for r in outcome.results if r.sha256 and r.size > 0]
    sample = random.Random(7).sample(candidates, min(SAMPLE, len(candidates)))
    mismatches = 0
    for r in sample:
        data = Path(r.path).read_bytes()
        want = hashlib.sha256(data).hexdigest()
        if r.sha256 != want:
            print(f"  SHA256 MISMATCH {r.path}")
            mismatches += 1
        want_md5 = hashlib.md5(data).hexdigest()
        if r.md5 != want_md5:
            print(f"  MD5 MISMATCH {r.path}")
            mismatches += 1
    print(f"hash cross-check: {len(sample)} files verified "
          f"({'OK' if mismatches == 0 else f'{mismatches} FAILURES'})")
    return mismatches


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=20000)
    ap.add_argument("--keep", action="store_true", help="keep the tree on disk")
    ap.add_argument("--threads", type=int, default=0, help="rust worker threads")
    args = ap.parse_args()

    root = Path(tempfile.mkdtemp(prefix="secudrive_bench_"))
    try:
        t_gen = time.perf_counter()
        build_tree(root, args.files)
        gen_s = time.perf_counter() - t_gen
        print(f"tree ready: {args.files} files in {gen_s:.1f}s  ({root})")

        opts = ScanOptions()
        opts.threads = args.threads

        dt_py, files_py, bytes_py = time_scan(root, opts.with_overrides(use_rust=False))

        from secudrive.scanner import _rust_engine  # private, for status only
        rust = _rust_engine()
        rust_ok = rust is not None
        print(f"\nengine report: {'compiled (secudrive_rust)' if rust_ok else 'pure-Python only'}")
        print("================ ENGINE COMPARISON ================")
        rate = files_py / dt_py if dt_py else 0.0
        print(f"pure-python : {dt_py:7.2f}s  {files_py:>6} files  "
              f"{bytes_py / 1e6:8.1f} MB  ({rate:,.0f} files/s)")

        if not rust_ok:
            print("rust        : NOT AVAILABLE - install cargo + maturin then run")
            print("              `python build.py`, or pip install the built wheel.")
            return 1

        dt_rs, files_rs, bytes_rs = time_scan(root, opts.with_overrides(use_rust=True))
        rate_rs = files_rs / dt_rs if dt_rs else 0.0
        print(f"rust        : {dt_rs:7.2f}s  {files_rs:>6} files  "
              f"{bytes_rs / 1e6:8.1f} MB  ({rate_rs:,.0f} files/s)")
        if files_rs:
            print(f"files seen  : python={files_py} rust={files_rs} "
                  f"{'MATCH' if files_py == files_rs else 'DIFFER'}")
            print(f"speedup     : {dt_py / dt_rs:,.1f}x")

        mismatches = verify_hashes(root, rust)
        print("====================================================")
        return 1 if mismatches else 0
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
            print(f"cleaned up temp tree ({root})")


if __name__ == "__main__":
    raise SystemExit(main())