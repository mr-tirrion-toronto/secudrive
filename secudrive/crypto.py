"""Encrypted backup / restore primitives (Zero Data Loss guarantee).

Uses ``cryptography``'s audited Fernet implementation (AES-128-CBC + HMAC-SHA256)
with a length-prefixed frame format so arbitrarily large files stream in
bounded memory:

    [u32 BE frame length][Fernet token]  ...  repeated until EOF

The per-user machine key is persisted once and its ACL locked down to the
current user (POSIX chmod 0600, Windows icacls inheritance:r).  Passphrase
derived keys are supported so the tool can ride on a master secret if desired.
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple

from .logging_utils import get_logger
from .safefile import compute_hashes

logger = get_logger("crypto")

FRAME_HEADER = struct.Struct(">I")
_IO_CHUNK = 1024 * 1024

# Decrypt-side frame bound.  A "frame" is the base64 Fernet token carrying one
# plaintext chunk, so its byte length is ceil((chunk + 57) / 3) * 4.  A 1 MiB
# chunk therefore produces a frame of exactly 1,398,200 bytes (verified
# empirically) - and that same 1,398,200 is the maximum found in EVERY
# pre-existing encrypted backup on this machine (frame-size census over the real
# data dir, current AND legacy-build blobs: nothing ever exceeds it).  The old
# bound (_IO_CHUNK + 4096 = 1,052,672) sat below this number, so any blob
# holding a file >= ~1 MiB was rejected on restore with "implausible frame size
# 1398200" even though its data was perfectly intact.  The bound must clear that
# maximum:
#
#   1,398,200   largest legitimate frame ever written (1 MiB chunk, census-exact)
#   +   8,192   safety margin (1/16 chunk of headroom) so tooling/rounding drift
#               can never false-positive a real backup
#   = 1,406,392   _MAX_FRAME
#
# Anything >= this sits at least 8 KiB above the largest frame this software has
# ever produced: a torn write, a reversed/corrupted header, or foreign junk -
# and is still rejected by the same guard (0 < n <= _MAX_FRAME) in both
# decrypt_stream() and _verify_blob_headers().
_LEGACY_FRAME_MAX = 1_398_200
_FRAME_SAFETY_MARGIN = 8_192
_MAX_FRAME = _LEGACY_FRAME_MAX + _FRAME_SAFETY_MARGIN


class IntegrityError(RuntimeError):
    """Raised when a decrypted/restored blob fails its hash verification."""


def _fernet(key: bytes):
    """Lazy import so ``scan`` / ``reveal`` work without cryptography installed."""
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "cryptography is required for backup/disinfect operations. "
            "Install with:  python -m pip install cryptography"
        ) from exc
    return Fernet(key)


def generate_key() -> bytes:
    from cryptography.fernet import Fernet
    return Fernet.generate_key()


def passphrase_to_key(passphrase: str) -> bytes:
    """PBKDF2-SHA256 (480k iterations) -> url-safe b64 32-byte Fernet key."""
    digest = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), b"secudrive::kdf-v1", 480_000, dklen=32)
    return base64.urlsafe_b64encode(digest)


def load_or_create_key(key_path: Path, passphrase: Optional[str] = None) -> bytes:
    """Return a stable key, creating and locking it down on first use."""
    if passphrase:
        return passphrase_to_key(passphrase)

    key_path = Path(key_path)
    if key_path.exists():
        data = key_path.read_bytes()
        if len(data) not in (32, 44):  # Fernet keys are 44 b64 chars
            raise IntegrityError(f"malformed key file: {key_path}")
        return data

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = generate_key()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(str(key_path), flags, 0o600)
    except FileExistsError:
        return key_path.read_bytes()
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    _harden_key_file(key_path)
    logger.info("created new encryption key at %s", key_path)
    return key


def _harden_key_file(path: Path) -> None:
    """Best-effort ACL lockdown: no other local user may read the key."""
    try:
        path.chmod(0o600)
    except OSError:
        pass
    if os.name == "nt":
        try:
            user = os.getenv("USERNAME") or os.getlogin()
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True, timeout=20, check=True)
        except (OSError, subprocess.SubprocessError):
            logger.warning("could not lock key ACL on %s (continuing)", path)


# -------------------------------------------------------------------- streaming
def encrypt_stream(src: Path, dst: Path, key: bytes) -> int:
    """Encrypt src -> dst (framed). Returns bytes written."""
    fernet = _fernet(key)
    written = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(_IO_CHUNK)
            if not chunk:
                break
            token = fernet.encrypt(chunk)
            fout.write(FRAME_HEADER.pack(len(token)))
            fout.write(token)
            written += 4 + len(token)
    return written


def decrypt_stream(src: Path, dst: Path, key: bytes) -> int:
    """Decrypt a framed blob src -> dst. Returns bytes written.

    Crypto-corruption of the store (truncated/zeroed blob, wrong key, tampered
    frame) surfaces as a single ``IntegrityError`` - never as a raw
    ``cryptography.fernet.InvalidToken`` / ``InvalidSignature`` that would
    escape as an unclassified crash from ``restore_item`` / ``disinfect_file``
    (the "restore produced an empty folder / just says Failed" class)."""
    fernet = _fernet(key)
    written = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            header = fin.read(4)
            if not header:
                break
            if len(header) != 4:
                raise IntegrityError("truncated frame header in encrypted blob")
            (n,) = FRAME_HEADER.unpack(header)
            if not 0 < n <= _MAX_FRAME:
                raise IntegrityError(f"implausible frame size {n}")
            token = fin.read(n)
            if len(token) != n:
                raise IntegrityError("truncated frame body in encrypted blob")
            try:
                data = fernet.decrypt(token)
            except Exception as exc:  # InvalidToken / InvalidSignature etc.
                try:
                    dst.unlink(missing_ok=True)
                except OSError:
                    pass
                raise IntegrityError(
                    f"encrypted blob verify failed for {src}: {exc}") from exc
            fout.write(data)
            written += len(data)
    return written


# -------------------------------------------------------------------- high level
def _verify_blob_headers(fh) -> None:
    """Cheap structural self-check of a freshly written backup: walk every frame
    header and confirm the body length is plausible and fully present, WITHOUT
    decrypting.  Catches torn/truncated/corrupt writes before a blob is ever
    published as a restore source, so a bad .bak.aes can never silently appear."""
    fh.seek(0, os.SEEK_END)
    total = fh.tell()
    fh.seek(0)
    while True:
        header = fh.read(4)
        if not header:
            break
        if len(header) != 4:
            raise IntegrityError("truncated frame header in new backup")
        (n,) = FRAME_HEADER.unpack(header)
        if not 0 < n <= _MAX_FRAME:
            raise IntegrityError(f"implausible frame size {n}")
        body_start = fh.tell()
        if body_start + n > total:
            raise IntegrityError("truncated frame body in new backup")
        fh.seek(body_start + n)


def backup_file(src: Path, backup_dir: Path, key: bytes) -> Dict[str, object]:
    """Encrypt src into backup_dir; returns metadata safe for the quarantine table.

    The encrypted blob is written to a temp sibling, structurally verified, then
    atomically renamed into place - the final ``<uid>.bak.aes`` is therefore EITHER
    complete and valid OR absent (never a torn/corrupt partial that fails later
    restores with 'implausible frame size')."""
    uid = uuid.uuid4().hex
    store = Path(backup_dir) / f"{uid}.bak.aes"
    tmp = store.with_name(store.name + ".tmp")
    try:
        encrypt_stream(src, tmp, key)
        with open(tmp, "rb") as fb:
            _verify_blob_headers(fb)
        os.replace(tmp, store)                  # atomic publish
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    hashes = compute_hashes(src) or {}
    sha = hashes.get("sha256") or hashes.get("md5")
    try:
        source_size = Path(src).stat().st_size
    except OSError:  # file vanished between backup and stat - report encrypted size
        source_size = None
    return {
        "backup_uid": uid,
        "store_path": str(store),
        "sha256": sha,
        "size": source_size,          # plaintext size (integrity gate for restores)
        "encrypted_size": store.stat().st_size,
    }


def restore_backup_file(store: Path, dst: Path, key: bytes,
                        expected_sha: Optional[str] = None,
                        expected_size: Optional[int] = None) -> int:
    """Decrypt store -> dst and verify size/hash. Raises IntegrityError on mismatch.

    On any failure the partially written ``dst`` is removed so the caller never
    inherits a garbage restore artifact.  A corrupt/truncated/wrong-key blob
    (``cryptography.fernet`` InvalidToken / InvalidSignature) is TRANSLATED to
    ``IntegrityError`` - never left to escape as an unclassified exception -
    so every call site (restore_item, disinfect-file verify, CLI, GUI) can
    classify it uniformly as "backup corrupted (unrecoverable)" instead of
    crashing mid-restore."""
    try:
        size = decrypt_stream(store, dst, key)
    except Exception as exc:  # InvalidToken / InvalidSignature / struct errors
        # Fulfil the boundary contract in the docstring ABOVE: a corrupt /
        # truncated / wrong-key blob is NEVER allowed to escape as an
        # unclassified "cryptography.fernet.InvalidToken".  Every caller
        # (recovery.restore_item, CLI restore, the GUI restore worker) classifies
        # a restore failure uniformly by catching IntegrityError - so a vault
        # restore reports "backup corrupted (unrecoverable)" instead of crashing
        # out of the restore pipeline (which - before the staging fix - left an
        # empty folder where the file should have appeared).
        _unlink_best_effort(dst)
        raise IntegrityError(f"decrypt blob failed: {exc}") from exc
    except Exception as exc:  # InvalidToken / InvalidSignature / struct errors
        _unlink_best_effort(dst)
        raise IntegrityError(f"decrypt blob failed: {exc}") from exc
    try:
        if expected_size is not None and size != expected_size:
            raise IntegrityError(
                f"size mismatch restoring {store}: got {size}, expected {expected_size}")
        if expected_sha:
            hashes = compute_hashes(dst) or {}
            got = hashes.get("sha256") or hashes.get("md5")
            if got != expected_sha:
                raise IntegrityError(
                    f"hash mismatch restoring {store}: {got} != {expected_sha}")
    except Exception:
        _unlink_best_effort(dst)
        raise
    return size


def _unlink_best_effort(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass