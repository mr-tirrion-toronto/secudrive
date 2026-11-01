#!/usr/bin/env python3
"""build.py - one-command production build of SecuDrive.

Usage:
    python build.py                     # default: PyInstaller onefile, windowed, UAC admin
    python build.py -- --clean          # pass extra flags straight to PyInstaller

Output lands in dist\\SecuDrive.exe (Windows) or dist/SecuDrive (Linux).
Requires:  pip install pyinstaller

RELEASE GATE (mandatory, EVERY release, permanently - never skippable):
    No fix is ever to be reported as fixed / complete / shipped unless
    scripts/smoke_built_exe.py passes against a FRESHLY REBUILT binary.
    Source-only passes do NOT qualify - the frozen .exe is the artifact that
    ships, and an import-resolution bug once slipped through a source-green
    review and caused a multi-day cascade (see scripts/SESSION_MEMORY.md).
        python scripts/smoke_built_exe.py    # run from an ELEVATED shell
    The smoke drives the frozen .exe against a throwaway sandbox (scan,
    disinfect, quarantine+restore round-trip incl. DB row status transition
    and a loud-failure restore case, windowed GUI boot) and must pass before
    the build is declared done.  See scripts/smoke_built_exe.py.

TOOLCHAIN SETUP (one-time, on this machine):
    1. Install Rust:      https://rustup.rs   (rustup-init.exe, accept defaults)
    2. Install maturin:   pip install "maturin>=1.7,<2.0"
    3. Rebuild:           python build.py

The build script will automatically call ``maturin build --release`` (if cargo
and maturin are found) to compile the Rust scan engine and install the wheel
into the active Python environment *before* running PyInstaller.  If the Rust
toolchain is not installed the step is skipped and the shipped binary falls back
to the pure-Python scan engine automatically.

Linux builds additionally hard-require the real-time backends (pyinotify, pyudev)
so protection works out of the box.  Windows requires only pywin32.
macOS is not a supported build/release target.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = ROOT / "SecuDrive.spec"
RUST_DIR = ROOT / "rust_engine"
WHEEL_DIR = ROOT / "target" / "wheels"


def _require(name: str, hint: str) -> None:
    try:
        __import__(name)
    except ImportError:
        print(f"missing build dependency: {name}\n  hint: {hint}", file=sys.stderr)
        sys.exit(1)


def _build_rust_engine() -> bool:
    """Compile and install the secudrive_rust wheel.  Returns True on
    success (or when the toolchain is not installed — fallback is fine)."""
    if not RUST_DIR.exists():
        print("[build] rust_engine/ not found; skipping compiled engine.")
        return False
    cargo = shutil.which("cargo")
    maturin_ok = shutil.which("maturin") is not None
    if not cargo:
        print("[build] cargo not found; skipping maturin wheel (pure-Python fallback).")
        return False
    if not maturin_ok:
        try:
            subprocess.check_call([sys.executable, "-m", "maturin", "--version"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            maturin_ok = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    if not maturin_ok:
        print("[build] maturin not found; skipping compiled engine.")
        print("        pip install \"maturin>=1.7,<2.0\"  to enable it.")
        return False

    print(f"[build] compiling Rust scan engine ({RUST_DIR})...")
    WHEEL_DIR.mkdir(parents=True, exist_ok=True)
    maturin_cmd = [
        sys.executable, "-m", "maturin",
        "build",
        "--release",
        "--manifest-path", str(RUST_DIR / "Cargo.toml"),
        "--out", str(WHEEL_DIR),
    ]
    print("running: " + " ".join(maturin_cmd))
    try:
        subprocess.check_call(maturin_cmd, cwd=str(RUST_DIR))
    except subprocess.CalledProcessError as exc:
        print(f"[build] maturin build failed ({exc}); proceeding with pure-Python engine.",
              file=sys.stderr)
        return False

    # Install the just-built wheel into the active Python environment.
    wheels = sorted(WHEEL_DIR.glob("secudrive_rust-*.whl"))
    if not wheels:
        print("[build] maturin built but no wheel found; pure-Python fallback.",
              file=sys.stderr)
        return False
    wheel = wheels[-1]
    print(f"[build] installing {wheel.name} ...")
    pip_cmd = [sys.executable, "-m", "pip", "install",
               "--force-reinstall", "--no-deps", "--quiet", str(wheel)]
    try:
        subprocess.check_call(pip_cmd)
    except subprocess.CalledProcessError as exc:
        print(f"[build] pip install failed ({exc}); pure-Python fallback.", file=sys.stderr)
        return False
    print("[build] secudrive_rust installed successfully.")
    return True


def main() -> int:
    if platform.system() == "Darwin":
        print("SecuDrive supports Windows and Linux only; macOS builds are disabled.",
              file=sys.stderr)
        return 1

    _require("PyInstaller", "python -m pip install pyinstaller")
    _require("PyQt6", "python -m pip install pyqt6")

    # Non-Windows Linux builds ship their real-time backend as a hard dep so
    # protection works out of the box (no slim/polling-only builds unless the
    # deps are removed by hand).  Windows skips these - pywin32 covers both
    # device notification and real-time file watch natively.
    if platform.system() == "Linux":
        _require("pyinotify", "python -m pip install pyinotify")
        _require("pyudev", "python -m pip install pyudev")

    if not SPEC.exists():
        print(f"spec file not found: {SPEC}", file=sys.stderr)
        return 1

    _build_rust_engine()

    extra = sys.argv[1:]
    if extra and extra[0] == "--":
        extra = extra[1:]

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        str(SPEC),
        *extra,
    ]
    print("running: " + " ".join(cmd))
    try:
        subprocess.check_call(cmd, cwd=str(ROOT))
    except subprocess.CalledProcessError as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 1

    out = ROOT / "dist" / ("SecuDrive.exe" if platform.system() == "Windows"
                           else "SecuDrive")
    if out.exists():
        size = out.stat().st_size / (1024 * 1024)
        print(f"\nSUCCESS: {out} ({size:.1f} MB)")
        print("NOTE: the binary requests admin at launch (uac_admin) and is "
              "windowed (no console). Use 'SecuDrive --cli --help' for CLI mode.")
    else:
        print(f"build finished but dist/{out.name} was not produced", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
