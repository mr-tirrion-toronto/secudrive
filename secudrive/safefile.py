"""Safe (non-executing) byte-level file access - the isolation-sandbox primitives.

Everything in secudrive reads files through this module.  Guarantees:

* files are opened strictly ``'rb'`` - never loaded by an interpreter, shell,
  AV engine, or the OS shell.
* all reads go through small bounded windows (head / tail) plus a streaming
  hasher; a 500 GB drive image is never slurped into RAM.
* every call degrades to ``None`` / ``b""`` on permission or I/O errors so the
  scanner keeps walking instead of aborting.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, Optional, Sequence

from .logging_utils import get_logger

logger = get_logger("safefile")

_IO_CHUNK = 1024 * 1024

# Magic sniffing table: (magic_bytes, human name). Order matters (check longest first).
MAGIC_MAP: Sequence[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF-", "pdf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF89a", "gif"),
    (b"GIF87a", "gif"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),     # docx / xlsx / pptx / jar / apk
    (b"PK\x05\x06", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BM", "bmp"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"RIFF", "riff"),          # wav / avi / webp
    (b"ftyp", "mp4"),
    (b"\x00\x00\x00\x18ftyp", "mp4"),
    (b"ID3", "mp3"),
    (b"OggS", "ogg"),
    (b"{\\rtf", "rtf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),  # .doc / .xls / .ppt / .msi
]


def sniff_magic(head: bytes) -> Optional[str]:
    """Return the detected container type from a file head, or None."""
    for magic, name in MAGIC_MAP:
        if head.startswith(magic):
            return name
    return None


def stat_safe(path: Path) -> Optional[os.stat_result]:
    """stat() that returns None instead of raising on permission / I/O errors."""
    try:
        return Path(path).stat()
    except (OSError, PermissionError):
        return None


def read_head(path: Path, n: int = 64 * 1024) -> bytes:
    """Read the first ``n`` bytes. Returns b'' on error rather than raising."""
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except (OSError, PermissionError, ValueError):
        return b""


def read_tail(path: Path, n: int = 64 * 1024) -> bytes:
    """Read the last ``n`` bytes. Returns b'' on error rather than raising."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            start = max(0, end - n)
            fh.seek(start)
            return fh.read(end - start)
    except (OSError, PermissionError, ValueError):
        return b""


def read_range(path: Path, offset: int = 0, size: int = 64 * 1024) -> bytes:
    """Read an explicit byte window. Returns b'' on error rather than raising."""
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            return fh.read(size)
    except (OSError, PermissionError, ValueError):
        return b""


def compute_hashes(path: Path, algorithms: Sequence[str] = ("sha256", "md5")) -> Optional[Dict[str, str]]:
    """Stream a file through the requested hashers. None on permission/I-O error.

    Used both for signature matching and for post-disinfection integrity checks.
    """
    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_IO_CHUNK)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
    except (OSError, PermissionError, ValueError):
        return None
    return {alg: h.hexdigest() for alg, h in hashers.items()}


def looks_text(head: bytes, sample: int = 4096) -> bool:
    """Cheap text-vs-binary guess over the head window.

    Two censuses:
      * control characters (excluding normal whitespace) — high count ⇒ binary
      * high-bit bytes (≥ 0x80) — real text files are overwhelmingly ASCII; a
        polyglot image/PDF whose head is mostly high-byte data will correctly
        fail this gate so ``check_trailing_payload`` can run.
    """
    blob = head[:sample]
    if not blob:
        return False
    nulls = blob.count(0)
    if nulls > 0:
        return False
    n = len(blob)
    controls = sum(1 for b in blob if b < 0x09 or (0x0E <= b < 0x20))
    high_bit = sum(1 for b in blob if b >= 0x80)
    return (controls / n) < 0.05 and (high_bit / n) < 0.10


def looks_likely_script(name: str) -> bool:
    """Script-ish names we attach obfuscation heuristics to."""
    ext = Path(name).suffix.lower()
    return ext in {
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsc", ".hta", ".bat",
        ".cmd", ".ps1", ".psm1", ".cpl", ".scr", ".pif",
    }