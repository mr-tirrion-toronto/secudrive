# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec - SecuDrive.exe (single-file, windowed, UAC admin).

Build with:  python build.py
"""
import importlib.util as _ilu
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH)  # provided by PyInstaller at parse time

# --- optional amber icon ---------------------------------------------------
icon_path = ROOT / "assets" / "SecuDrive.ico"
icon = str(icon_path) if icon_path.exists() else None

# --- hidden imports --------------------------------------------------------
# PyQt6 + cryptography have first-party hooks; pywin32 and socket glue need a
# nudge when they are installed. collect_submodules yields [] when absent, so
# this spec also builds on machines without pywin32.
hiddenimports = (
    collect_submodules("win32com")
    + collect_submodules("win32gui")
    + collect_submodules("win32api")
    + [
        "cryptography",
        "cryptography.hazmat.backends.openssl",
        "sqlite3",
        "secudrive_rust",
    ]
)

# --- optional compiled scan engine (secudrive_rust .pyd) -------------------
_rust_binaries = []
try:
    _rs_spec = _ilu.find_spec("secudrive_rust")
except Exception:
    _rs_spec = None
if _rs_spec and getattr(_rs_spec, "origin", None) and \
        _rs_spec.origin.endswith((".pyd", ".so")):
    _rust_binaries = [[str(_rs_spec.origin), "."]]

# --- optional non-Windows real-time backends (added only when installed) ----
# pyinotify/pyudev (Linux) are runtime deps that never exist on a Windows
# build, so guarding keeps the Windows build un-polluted. macOS is disabled.
_os_backends = []
for _mod in ("pyinotify", "pyudev"):
    try:
        if _ilu.find_spec(_mod) is not None:
            _os_backends.append(_mod)
    except (ImportError, ValueError):
        pass

a = Analysis(
    ["bootstrap.py"],
    pathex=[str(ROOT)],
    binaries=_rust_binaries,
    datas=[
        # ship the schema-seeding module graph; data dir is created at runtime
        (str(ROOT / "secudrive"), "secudrive"),
    ],
    hiddenimports=list(hiddenimports) + _os_backends,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "PyQt5",
        "PySide2",
        "PySide6",
        "IPython",
        "pytest",
        "setuptools",
        "pydoc_data",
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="SecuDrive",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # windowed: no console window on launch
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon,
    uac_admin=True,         # native Windows UAC elevation request
    version=str(ROOT / "assets" / "version_info.txt"),
)