#!/usr/bin/env python3
"""rust_smoke.py - post-toolchain verification of the compiled scan engine.

Run AFTER:  pip install maturin && cargo (rustup), then `python build.py`
(or `maturin develop --release --manifest-path rust_engine/Cargo.toml`).

Verifies (against the pure-Python engine as ground truth):
  1. the real engine loads (rejects the repo crate dir namespace package);
  2. files/dirs/bytes/errors counters match between the two engines;
  3. Rust hashes (sha256+md5) match hashlib for a sample;
  4. .lnk discovery surfaces in lnk_dirs;
  5. max_depth semantics match for a bounded tree;
  6. max_hash_size cap is honoured (oversized files reported, not hashed);
  7. a seeded signature produces identical signature findings in both engines;
  8. cancellation propagates ScanCancelled; progress callback fires.
"""
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "scanner.py").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive.database import Database  # noqa: E402
from secudrive.scanner import ScanCancelled, ScanOptions, Scanner, _rust_engine  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name} {extra}")
        sys.exit(1)


def hashlib_for(path: Path):
    data = path.read_bytes()
    return (hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest())


def build_tree(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "a.txt").write_text("payload-a" * 1000)
    (root / "b.bin").write_bytes(bytes(range(256)) * 40)
    (root / "empty.dat").write_bytes(b"")
    (root / "sub").mkdir()
    (root / "sub" / "c.txt").write_text("nested" * 500)
    big = (root / "sub" / "big.bin")
    big.write_bytes(b"\xDE\xAD" * (60 * 1024))          # ~120 KB
    (root / "windows").mkdir()                          # excluded directory
    (root / "windows" / "never.txt").write_text("hidden")
    (root / "node_modules").write_text("excluded-name file")
    (root / "shortcut.lnk").write_text("fake lnk body")  # .lnk discovery


def scan(root: Path, db, rust: bool, *, max_depth: int = 0,
         max_hash: int = 512 * 1024 * 1024):
    opts = ScanOptions().with_overrides(use_rust=rust, max_depth=max_depth,
                                        max_hash_size=max_hash)
    scanner = Scanner(db, opts, progress=lambda info: None)
    report = scanner.scan([root])
    scanner.persist()
    return report


def main() -> int:
    rust = _rust_engine()
    check("real engine loaded", rust is not None and hasattr(rust, "scan_directory"))
    print(f"engine version: {getattr(rust, '__version__', '?')}")

    tmp = Path(tempfile.mkdtemp(prefix="rust_smoke_"))
    try:
        tree = tmp / "tree"
        build_tree(tree)

        db = Database(tmp / "smoke.db")
        # seed: exact sha256 of a.txt -> must be found through the rust path
        sha_a, _ = hashlib_for(tree / "a.txt")
        db.upsert_signature(sha_a, "sha256", "RustSmokeTest", "test", "rust_smoke")

        print("\n-- counter parity (unlimited depth) --")
        r_py = scan(tree, db, False)
        r_rs = scan(tree, db, True)
        print(f"  python files={r_py.files_seen} dirs={r_py.dirs_seen} "
              f"bytes={r_py.bytes_scanned} errors={r_py.errors}")
        print(f"  rust   files={r_rs.files_seen} dirs={r_rs.dirs_seen} "
              f"bytes={r_rs.bytes_scanned} errors={r_rs.errors}")
        check("files_seen parity", r_py.files_seen == r_rs.files_seen,
              f"({r_py.files_seen} vs {r_rs.files_seen})")
        check("dirs_seen parity", r_py.dirs_seen == r_rs.dirs_seen,
              f"({r_py.dirs_seen} vs {r_rs.dirs_seen})")
        check("bytes_scanned parity", r_py.bytes_scanned == r_rs.bytes_scanned,
              f"({r_py.bytes_scanned} vs {r_rs.bytes_scanned})")
        check("errors parity", r_py.errors == r_rs.errors,
              f"({r_py.errors} vs {r_rs.errors})")
        check("signature finding found via rust engine",
              any(f.name.startswith("Signature:RustSmokeTest") for f in r_rs.findings),
              f"got {len(r_rs.findings)} findings")
        check("same finding set across engines",
              {(f.path.name, f.name) for f in r_py.findings} ==
              {(f.path.name, f.name) for f in r_rs.findings})
        # excluded dir/file never counted: a.txt,b.bin,empty.dat,sub/c.txt,
        # sub/big.bin,shortcut.lnk = 6 files; dirs root+sub = 2
        check("exclusion honoured (6 files, 2 dirs)",
              r_rs.files_seen == 6 and r_rs.dirs_seen == 2,
              f"files={r_rs.files_seen} dirs={r_rs.dirs_seen}")

        print("\n-- hash spot-check vs hashlib --")
        outcome = rust.scan_directory(str(tree), hash_algo="sha256+md5",
                                      max_hash_size=512 * 1024 * 1024,
                                      max_depth=0, follow_symlinks=False,
                                      exclude_dirs=sorted({"windows", "node_modules"}),
                                      threads=0, progress_cb=None, cancel_cb=None)
        by_path = {Path(r.path).name: r for r in outcome.results if r.sha256}
        leaks = 0
        for name, r in list(by_path.items())[:6]:
            w = hashlib_for(tree / name if (tree / name).exists()
                            else tree / "sub" / name)
            if (r.sha256, r.md5) != w:
                leaks += 1
                print(f"  MISMATCH {name}")
        check("sha256+md5 match hashlib on sample", leaks == 0)
        check("lnk_dirs surfaced", any("tree" in d for d in outcome.lnk_dirs),
              f"lnk_dirs={outcome.lnk_dirs}")

        print("\n-- max_depth=1 parity --")
        r1_py = scan(tree, db, False, max_depth=1)
        r1_rs = scan(tree, db, True, max_depth=1)
        check("depth-1 files parity", r1_py.files_seen == r1_rs.files_seen,
              f"({r1_py.files_seen} vs {r1_rs.files_seen})")
        check("depth-1 dirs parity", r1_py.dirs_seen == r1_rs.dirs_seen,
              f"({r1_py.dirs_seen} vs {r1_rs.dirs_seen})")

        print("\n-- oversized / locked handling --")
        o = rust.scan_directory(str(tree), hash_algo="sha256+md5",
                                max_hash_size=10 * 1024,   # 10 KB cap
                                max_depth=0, follow_symlinks=False,
                                exclude_dirs=["windows"], threads=0,
                                progress_cb=None, cancel_cb=None)
        big = next((r for r in o.results if r.path.endswith("big.bin")), None)
        check("oversized file still reported", big is not None and big.sha256 is None,
              f"big={big}")
        small = next(r for r in o.results if r.path.endswith("c.txt"))
        check("small file hashed under cap", small.sha256 is not None)

        print("\n-- progress + cancellation --")
        ticks = []

        def prog(*a):
            ticks.append(a)

        def cancel():
            raise ScanCancelled()

        try:
            rust.scan_directory(str(tree), hash_algo="sha256+md5",
                                max_hash_size=512 * 1024 * 1024, max_depth=0,
                                follow_symlinks=False, exclude_dirs=["windows"],
                                threads=0, progress_cb=prog, cancel_cb=cancel)
            raise SystemExit("cancel_cb did not interrupt the scan")
        except ScanCancelled:
            pass
        check("cancel_cb raised ScanCancelled", True)
        check("progress callback fired", len(ticks) > 0, f"ticks={len(ticks)}")

        print("\nrust_smoke: ALL PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())