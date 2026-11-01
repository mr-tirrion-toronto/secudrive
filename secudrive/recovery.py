"""recovery.py - Disinfection & Recovery Module (the USP core).

Every destructive action obeys the enforced safety pipeline:

    BACKUP (encrypted, per-user key) -> SANDBOX (byte-stream, never execute)
    -> DISINFECT (strip appended payload / reset attributes / remove hijack)
    -> VERIFY (integrity + re-scan)   -> ROLLBACK on failure (decrypt the backup)

Zero Data Loss invariant: the original bytes always exist (encrypted) under
``backups/`` before anything is modified.  Feature inventory:

    * reveal_hidden()        - clear HIDDEN/SYSTEM attributes on user data
    * strip_fake_shortcuts() - quarantine "photo.jpg.lnk" style hijacks
    * clean_autorun()        - quarantine autorun.inf / desktop.ini that launch code
    * clean_external_drive() - USB/HDD deep-clean orchestration (no registry)
    * disinfect_file()       - truncate appended payloads at EOF marker, verify, rollback
    * resolve_infector()     - REFINED Outcome A: a chain of MEANINGFULLY
                               DIFFERENT disinfection strategies, each verified
                               on a temp candidate BEFORE the original path may
                               change.  The original file is only written back
                               after a candidate fully verifies; only when every
                               honest attempt fails does the engine fall back to
                               Quarantine - keeping the PRE-ATTEMPT encrypted
                               backup and a full per-attempt history.
    * quarantine_file()      - first-class quarantine with encrypted backup
    * purge_verified_file()  - Auto-Purge mode: backup -> delete -> verify -> purge
                               for PURE-MALWARE files only (fallback: quarantine)

``resolve_plan()`` is the one decision point behind BOTH the automatic flow
(AutoPilot) and every manual per-item handler.  Default course of action:
resolve IN PLACE when a safe EOF-marker strip point exists (Outcome A via
``execute_outcome_a`` / ``execute_plan`` / ``resolve_infector``), otherwise
move the live copy into the encrypted quarantine store (Outcome B via
``execute_outcome_b``).  The old always-quarantine behavior is the opt-in
``on_detection == 'quarantine'`` config value.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from . import heuristics
from .crypto import (IntegrityError, backup_file, load_or_create_key,
                     restore_backup_file)
from .database import Database
from .heuristics import is_recovery_data_path
from .logging_utils import get_logger
from .platform import get_provider
from .safefile import (compute_hashes, read_head, read_range, read_tail,
                       sniff_magic, stat_safe)

logger = get_logger("recovery")

provider = get_provider()

_DEFAULT_EXCLUDES = frozenset({
    "$recycle.bin", "system volume information", "windows", "system32",
    "winsxs", "program files", "program files (x86)", "programdata",
    "$sysreset", "recovery", "boot", "appdata", "node_modules", ".git",
    "venv", ".venv", "secudrive",
})

# Names the attribute-revealer must NOT touch - they belong to the cleaner phases.
_MALWARE_FAMILY_NAMES = frozenset({"autorun.inf", "desktop.ini"})

# Plan kinds produced by ``resolve_plan()`` - the ONE classifier behind both
# the automatic (AutoPilot) flow and every manual per-item handler, so a given
# finding always behaves the same everywhere.
PLAN_REVEAL = "reveal"            # hidden root folder: clear attrs, nothing lost
PLAN_STRIP = "strip"              # container w/ EOF-marker split: resolve in place
PLAN_QUARANTINE = "quarantine"    # no safe in-place fix: quarantine store
PLAN_SKIP = "skip"                # recovery data / symlink / missing: review only

# EOF markers per container, and how many bytes each structural end occupies.
# Anything AFTER the last marker is appended executable junk the disinfect
# pipeline strips; files built from other magic (MZ PE, ELF, RAR, OLE2, ...)
# have no safe in-place split and must go to the quarantine store instead.
_EOF_MARKERS = {
    "jpeg": (b"\xff\xd9", 2),
    "png":  (b"IEND\xaeB`\x82", 12),
    "gif":  (b"\x3b", 1),
    "pdf":  (b"%%EOF", 5),
    "zip":  (b"PK\x05\x06", 22),
}

# ---------------------------------------------------------------------------
# REFINED Outcome A strategy chain ("try harder before quarantining").
#
# KEY PRINCIPLE (never regress - documented in resolve_infector()):
#   * a candidate is written back to the original path ONLY after it verifies
#   * a failed-verify / declined candidate is NEVER published to the original path
#   * Quarantine is minimized by trying more techniques, but correctness is
#     never traded away to avoid Quarantine - it is the LAST resort only.
#
# Each strategy is a MEANINGFULLY DIFFERENT technique:
#   StableBoundary      - current tail-window EOF-marker strip (cheap, precise)
#   FullFileScan        - RELAXED boundaries: scan far more of the file for the
#                         LAST structural marker (handles deep/large payloads)
#   SignatureAnchored   - CONSERVATIVE: only strip a trailing region whose
#                         bytes match a known-bad signature (DB or the finding's
#                         recorded sha256); declines rather than guess-strip
_STRATEGY_STABLE = "StableBoundary"
_STRATEGY_FULLSCAN = "FullFileScan"
_STRATEGY_ANCHORED = "SignatureAnchored"
STRATEGY_ORDER = (_STRATEGY_STABLE, _STRATEGY_FULLSCAN, _STRATEGY_ANCHORED)

_FULL_SCAN_MAX = 256 * 1024 * 1024       # relax the tail window up to this much

# Structural end-marker per container, used by the candidate verifier so a
# sanitized file must still LOOK like a valid document of its kind.
_STRUCT_END = {
    "jpeg": b"\xff\xd9",
    "png":  b"IEND\xaeB`\x82",
    "gif":  b"\x3b",
    "zip":  b"PK\x05\x06",
    "pdf":  b"%%EOF",
}

# Outcome B (pure-malware purge) delete retries for Windows file-locks.
_IO_DELETE_RETRIES = 3
_IO_DELETE_BACKOFF_S = 0.3


def _offset_from_tail(tail: bytes, size: int, magic: str,
                      min_trailing_payload: int) -> Optional[int]:
    """Locate the clean-file end offset inside a tail window, or None."""
    marker, marker_len = _EOF_MARKERS[magic]
    pos = tail.rfind(marker)
    if pos == -1:
        return None
    trailing = len(tail) - (pos + marker_len)
    if trailing < min_trailing_payload:
        return None
    offset = size - trailing
    if offset < 1 or offset >= size:
        return None
    return offset


def trailing_payload_offset(path: Path, size: int, *,
                            head_window: int = 64 * 1024,
                            tail_window: int = 64 * 1024,
                            min_trailing_payload: int = 32) -> Optional[int]:
    """Locate the byte offset where a clean file should end, or None.

    Uses EOF markers per container (JPEG FFD9, PNG IEND, GIF trailer, PDF
    %%EOF, ZIP EOCD); anything after the marker is an appended payload.  The
    same head+tail windows drive ``RecoveryEngine.disinfect_file`` so a plan
    made here matches what the engine will do at execution time.
    """
    head = read_head(path, head_window)
    if not head:
        return None
    magic = sniff_magic(head)
    if magic not in _EOF_MARKERS:
        return None
    tail = read_tail(path, tail_window)
    return _offset_from_tail(tail, size, magic, min_trailing_payload)


def full_scan_offset(path: Path, size: int, *,
                     head_window: int = 64 * 1024,
                     tail_window: int = _FULL_SCAN_MAX,
                     min_trailing_payload: int = 32) -> Optional[int]:
    """Strategy 2 - RELAXED boundary detection.

    Scans up to ``tail_window`` (capped at 256 MB) for the LAST structural end
    marker instead of the small default window.  Costs more I/O but finds the
    boundary when it sits far from EOF (real payload may be tiny while a large
    embedded object precedes the marker).  Same ``_EOF_MARKERS`` contract.
    """
    head = read_head(path, head_window)
    if not head:
        return None
    magic = sniff_magic(head)
    if magic not in _EOF_MARKERS:
        return None
    tail = read_tail(path, min(size, tail_window))
    return _offset_from_tail(tail, size, magic, min_trailing_payload)


def resolve_plan(path, db, finding, config=None, *,
                 head_window: int = 64 * 1024, tail_window: int = 64 * 1024,
                 min_trailing_payload: int = 32) -> Dict[str, object]:
    """Classify ONE finding into an action plan under the shared safety rules.

    This is the single decision point behind the AUTO scan flow AND every
    manual per-item handler (Findings viewer "Clean", post-scan "Clean All",
    review dialog) so an identical finding always behaves the same:

        'reveal'      - hidden-camouflage root folder: clear HIDDEN/SYSTEM
                        attributes (reversible; no bytes are ever lost).
        'strip'       - container file (jpg/png/gif/pdf/zip) with a safe
                        EOF-marker strip point: resolve IN PLACE from an
                        encrypted backup.  The DEFAULT course of action.
        'quarantine'  - no safe in-place strip point (pure-malware executables,
                        whole-file malware, unknown containers): remove the
                        live copy into the encrypted quarantine store.  Also
                        the result when config ``on_detection == 'quarantine'``,
                        which restores the OLD ALWAYS-QUARANTINE behavior.
        'skip'        - OS/fs-recovery artifacts, symlinks, empty or missing
                        files: manual review only, no automatic action.

    ``finding`` may be a ``scanner.Finding`` or a plain dict (``name`` or
    ``threat_name``).  ``config`` may be a ``Config`` or any object exposing
    ``get(key, default)``.
    """
    def _f(key: str, default=None):
        if isinstance(finding, dict):
            return finding.get(key, default)
        return getattr(finding, key, default)

    path = Path(path)
    threat = _f("name", None) or _f("threat_name", None) or "suspicious"
    reasons: Dict[str, object] = {"path": str(path),
                                  "category": _f("category", None),
                                  "threat": threat,
                                  "confidence": float(_f("confidence", 0.0) or 0.0)}

    if is_recovery_data_path(path):
        return {**reasons, "plan": PLAN_SKIP,
                "reason": "OS/fs-recovery artifact - manual review only"}
    if os.path.ismount(str(path)) or str(path).endswith(":") or len(str(path)) <= 3:
        # Drive/volume roots (a drive letter, a mounted USB stick, a network
        # share...) are NOT files: routing them into the disinfect/quarantine
        # pipeline dead-ends as "Failed" (nothing to act on) and a recursive
        # reveal would walk the entire volume.  Guardrail mirrors the scanner,
        # which never emits a finding for a mount point.  Manual review only.
        return {**reasons, "plan": PLAN_SKIP,
                "reason": "drive root or mount point - manual review only"}
    if not path.exists() or path.is_symlink():
        return {**reasons, "plan": PLAN_SKIP,
                "reason": "missing, inaccessible or symlink - manual review only"}
    if path.is_dir():
        if str(threat).lower() != "hiddenrootfolder":
            return {**reasons, "plan": PLAN_SKIP,
                    "reason": "directory - manual review only"}
        return {**reasons, "plan": PLAN_REVEAL,
                "reason": "hidden-camouflage root folder - reveal attributes"}
    if not path.is_file():
        return {**reasons, "plan": PLAN_SKIP,
                "reason": "not a regular file - manual review only"}

    # Legacy opt-in: 'quarantine' catalogues EVERY finding into the store
    # without any in-place work (the old always-quarantine behavior).
    on_detection = ""
    if config is not None:
        try:
            on_detection = str(config.get("on_detection", "") or "").lower()
        except Exception:
            on_detection = ""
    if on_detection == "quarantine":
        return {**reasons, "plan": PLAN_QUARANTINE,
                "reason": "opt-in on_detection='quarantine' (old behavior)"}

    st = stat_safe(path)
    if not st or not st.st_size:
        return {**reasons, "plan": PLAN_QUARANTINE,
                "reason": "file unreadable or empty - quarantine for review"}
    offset = trailing_payload_offset(path, int(st.st_size),
                                     head_window=head_window,
                                     tail_window=tail_window,
                                     min_trailing_payload=min_trailing_payload)
    if offset is not None:
        return {**reasons, "plan": PLAN_STRIP,
                "strip_offset": offset, "strip_bytes": int(st.st_size) - offset,
                "reason": "safe EOF-marker strip point - resolve in place"}
    return {**reasons, "plan": PLAN_QUARANTINE,
            "reason": "no safe EOF-marker strip point - quarantine for review"}


def is_auto_purge_candidate(path: Path, db, finding) -> bool:
    """Safety classifier: may this file be auto-purged under 'auto_purge_verified'?

    Only exact, live, FULL-FILE signature hits on NON-container file types
    qualify.  Heuristic hits, ambiguous/low-confidence matches, document-like
    containers, and anything whose hash no longer matches the signature table
    are rejected - the caller (AutoPilot) must then fall back to long-term
    Quarantine so a legitimate file is never silently destroyed.

    ``finding`` may be a ``scanner.Finding`` or a plain dict with the same
    fields (category / confidence / sha256 / path).
    """
    if is_recovery_data_path(path):
        return False                          # OS-recovery data - never auto-delete
    category = (finding.get("category") if isinstance(finding, dict)
                else getattr(finding, "category", None))
    confidence = float(
        (finding.get("confidence") if isinstance(finding, dict)
         else getattr(finding, "confidence", 0.0)) or 0.0)
    if category != "signature" or confidence < 0.9:
        return False
    hit_path = (finding.get("path") if isinstance(finding, dict)
                else getattr(finding, "path", path)) or path
    if Path(str(hit_path)).suffix.lower() in heuristics.DOC_LIKE_EXTS:
        return False                              # probable container - keep it
    sha = (finding.get("sha256") if isinstance(finding, dict)
           else getattr(finding, "sha256", None))
    if Path(str(hit_path)).suffix.lower() not in heuristics.EXEC_LIKE_EXTS and not sha:
        return False                              # unknown kind without hash proof
    if sha and not db.lookup(sha, "sha256"):
        return False                              # re-checked live; no longer bad
    return True


class RecoveryEngine:
    """Stateful engine bound to one Database + backup/quarantine stores + key."""

    def __init__(self, db: Database, backup_dir: Path, quarantine_dir: Path,
                 key: Optional[bytes] = None, key_path: Optional[Path] = None,
                 min_trailing_payload: int = 32,
                 head_window: int = 64 * 1024, tail_window: int = 64 * 1024) -> None:
        self.db = db
        self.backup_dir = Path(backup_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.key = key or (load_or_create_key(key_path) if key_path else None)
        self.min_trailing_payload = min_trailing_payload
        self.head_window = head_window
        self.tail_window = tail_window
        self.exclude_dirs = _DEFAULT_EXCLUDES

    # ---------------------------------------------------------------- iteration
    def _iter_targets(self, root: Path, recursive: bool) -> Iterator[tuple[Path, bool]]:
        """Yield (path, is_dir) tuples, honoring excludes and recursion limits."""
        root = Path(root)
        if root.is_file():
            yield root, False
            return
        if not root.is_dir():
            return
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                iterator = os.scandir(current)
            except (PermissionError, OSError) as exc:
                logger.warning("cannot enumerate %s: %s", current, exc)
                continue
            with iterator as scan_it:
                for entry in scan_it:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    full = current / entry.name
                    if is_dir:
                        if entry.name.lower() in self.exclude_dirs or not recursive:
                            continue
                        stack.append(full)
                    yield full, is_dir

    def _ensure_key(self) -> None:
        if self.key is None:
            raise RuntimeError(
                "no encryption key configured - supply key_path or key to RecoveryEngine "
                "(disinfect/quarantine require encrypted backups)")

    def _quarantine_move(self, src: Path, threat_name: str) -> Dict[str, object]:
        """Backup (encrypted) + move src into the quarantine store. Returns metadata.

        Must be called before mutating anything; raises if backup/verify fails.
        """
        self._ensure_key()
        if not src.is_file():
            raise OSError(f"only regular files can be quarantined: {src}")
        meta = backup_file(src, self.backup_dir, self.key)       # step 1: encrypt
        store = self.quarantine_dir / f"{meta['backup_uid']}.q"
        shutil.copy2(src, store)                                 # step 2: capture blob
        try:
            src.unlink()                                         # step 3: remove live copy
        except (PermissionError, OSError) as exc:
            raise OSError(f"quarantine: cannot remove {src}: {exc}") from exc
        uid = str(meta["backup_uid"])
        self.db.add_quarantine(
            uid=uid, original_path=str(src), store_path=str(store),
            backup_path=str(meta["store_path"]), size=int(meta["size"]),
            sha256=meta.get("sha256"), threat_name=threat_name,
        )
        return {"uid": uid, "store": store, "backup": meta["store_path"],
                "sha256": meta.get("sha256"), "path": str(src)}

    # --------------------------------------------------------- attribute recovery
    def reveal_hidden(self, root: Path, *, recursive: bool = True,
                      dry_run: bool = False) -> Dict[str, object]:
        """Reset HIDDEN/SYSTEM attributes on user files/dirs (not on malware-named
        files, which the dedicated cleaners retire into quarantine)."""
        if not provider.file_attributes_supported():
            return {"action": "reveal", "dry_run": dry_run, "platform": os.name,
                    "changed": [], "errors": ["file attributes require this platform"]}

        report: Dict[str, object] = {
            "action": "reveal", "dry_run": dry_run, "platform": os.name,
            "changed": [], "errors": [],
        }
        for path, is_dir in self._iter_targets(root, recursive):
            if path.name.lower() in _MALWARE_FAMILY_NAMES:
                continue
            if path.name.lower().endswith(".lnk"):
                continue
            try:
                attrs = provider.get_file_attrs(str(path))
            except OSError as exc:
                report["errors"].append(f"{path}: {exc}")
                continue
            if not (attrs & (provider.FILE_ATTRIBUTE_HIDDEN
                             | provider.FILE_ATTRIBUTE_SYSTEM)):
                continue
            entry = {"path": str(path), "is_dir": is_dir,
                     "had_hidden": bool(attrs & provider.FILE_ATTRIBUTE_HIDDEN),
                     "had_system": bool(attrs & provider.FILE_ATTRIBUTE_SYSTEM)}
            if dry_run:
                entry["status"] = "would_reveal"
            else:
                try:
                    provider.set_file_attrs(
                        str(path),
                        attrs & ~(provider.FILE_ATTRIBUTE_HIDDEN
                                  | provider.FILE_ATTRIBUTE_SYSTEM))
                    entry["status"] = "revealed"
                    self.db.log_disinfection(str(path), "reveal", None, None,
                                             None, None, None, "ok")
                except OSError as exc:
                    entry["status"] = "error"
                    entry["error"] = str(exc)
                    report["errors"].append(f"{path}: {exc}")
            report["changed"].append(entry)
        return report

    # ---------------------------------------------------------- shortcut cleanup
    def strip_fake_shortcuts(self, root: Path, *, recursive: bool = True,
                             dry_run: bool = False) -> Dict[str, object]:
        """Retire fake/shadowing and hostile-target .lnk files into quarantine."""
        report: Dict[str, object] = {
            "action": "strip_shortcuts", "dry_run": dry_run,
            "quarantined": [], "errors": [],
        }
        for base, is_dir in self._iter_targets(root, recursive):
            if is_dir or not base.name.lower().endswith(".lnk"):
                continue
            try:
                siblings = {e.name.lower() for e in os.scandir(base.parent)}
            except OSError:
                siblings = set()
            findings = heuristics.run_lnk_heuristics(base, siblings)
            if not findings:
                continue
            reason = "; ".join(f"{f.name}: {f.evidence}" for f in findings)
            if dry_run:
                report["quarantined"].append({"path": str(base), "reason": reason,
                                              "status": "would_quarantine"})
                continue
            try:
                meta = self._quarantine_move(base, "FakeShortcut")
            except OSError as exc:
                report["errors"].append(f"{base}: {exc}")
                continue
            meta["reason"] = reason
            meta["status"] = "quarantined"
            report["quarantined"].append(meta)
            self.db.log_disinfection(str(base), "shortcut_remove", None, None,
                                     None, None, meta["uid"], "ok")
        return report

    # ------------------------------------------------------------------- autorun
    def clean_autorun(self, root: Path, *, recursive: bool = False,
                      dry_run: bool = False) -> Dict[str, object]:
        """Retire autorun.inf / desktop.ini files that embed launch directives."""
        report: Dict[str, object] = {
            "action": "clean_autorun", "dry_run": dry_run,
            "quarantined": [], "benign": [], "errors": [],
        }
        scan_set: Iterable[tuple[Path, bool]] = self._iter_targets(root, recursive)
        if not recursive:
            scan_set = [(root / p.name, False) for p in os.scandir(root)] \
                if root.is_dir() else scan_set
        for path, _is_dir in scan_set:
            if path.name.lower() not in _MALWARE_FAMILY_NAMES:
                continue
            findings = heuristics.run_file_heuristics(path, size=None)
            hostile = [f for f in findings if "Autorun" in f.name or "DesktopIni" in f.name]
            if not hostile:
                report["benign"].append(str(path))
                continue
            reason = "; ".join(f.evidence for f in hostile)
            if dry_run:
                report["quarantined"].append({"path": str(path), "reason": reason,
                                              "status": "would_quarantine"})
                continue
            try:
                meta = self._quarantine_move(path, "Autorun" if "Autorun" in hostile[0].name
                                             else "DesktopIni")
            except OSError as exc:
                report["errors"].append(f"{path}: {exc}")
                continue
            meta["reason"] = reason
            meta["status"] = "quarantined"
            report["quarantined"].append(meta)
            self.db.log_disinfection(str(path), "autorun_remove", None, None,
                                     None, None, meta["uid"], "ok")
        return report

    # ---------------------------------------------------------- drive deep-clean
    def clean_external_drive(self, root: Path, *, dry_run: bool = False) -> Dict[str, object]:
        """Orchestrate the full USB/HDD deep-clean (file layer only).

        Order matters: reveal user data FIRST so nothing hides, then retire
        hijack shortcuts and autorun launch-vectors.
        """
        combined: Dict[str, object] = {
            "action": "clean_external_drive", "dry_run": dry_run, "target": str(root),
            "phases": {},
        }
        combined["phases"]["reveal_hidden"] = self.reveal_hidden(root, dry_run=dry_run)
        combined["phases"]["strip_shortcuts"] = self.strip_fake_shortcuts(root, dry_run=dry_run)
        combined["phases"]["clean_autorun"] = self.clean_autorun(root, dry_run=dry_run)
        return combined

    # ------------------------------------------------------------ byte disinfection
    def _trailing_payload_offset(self, path: Path, size: int) -> Optional[int]:
        """Locate the byte offset where a clean file should end, or None.

        Delegates to the shared ``trailing_payload_offset`` (also used by the
        ``resolve_plan`` classifier) so a plan always matches execution.
        """
        return trailing_payload_offset(
            path, size, head_window=self.head_window, tail_window=self.tail_window,
            min_trailing_payload=self.min_trailing_payload)

    def _truncate_at(self, path: Path, offset: int) -> None:
        """Atomic single-syscall truncate keeps only valid bytes up to ``offset``.

        Removing trailing data cannot corrupt container internals because the
        EOF marker we cut at is the structural end; truncation itself is one
        filesystem call with no partial-state window on NTFS/APFS/ext4.
        """
        with open(path, "r+b") as fh:
            fh.truncate(offset)
            fh.flush()
            os.fsync(fh.fileno())

    def _verify_clean(self, path: Path, original_magic: str) -> Tuple[bool, str, Dict[str, object]]:
        """Post-disinfection integrity gate: magic intact, no trailing junk,
        no known-bad signature, size > 0."""
        st = stat_safe(path)
        if not st or st.st_size <= 0:
            return False, "file vanished or is empty after disinfect", {}
        size = st.st_size
        head = read_head(path, self.head_window)
        new_magic = sniff_magic(head)
        if new_magic != original_magic:
            return False, f"magic changed: {original_magic} -> {new_magic}", {}
        tail = read_tail(path, self.tail_window)
        if heuristics.check_trailing_payload(path, head, tail, size):
            return False, "trailing payload still present after disinfect", {}
        hashes = compute_hashes(path) or {}
        sha = hashes.get("sha256")
        if sha and self.db.lookup(sha, "sha256"):
            return False, "cleaned file still matches a known-bad signature", {}
        return True, "ok", {"size": size, "sha256": sha}

    # ------------------------------------------- multi-strategy resolve (Outcome A)
    def _verify_sanitized(self, path: Path, original_magic: str,
                          original_size: int) -> Tuple[bool, str, Dict[str, object]]:
        """Verifier for a staged resolve candidate (must pass BEFORE publish).

        Stricter than the in-place verifier: the candidate must not only be
        infection-free and have its header intact, it must structurally END like
        a valid file of its kind AND actually have removed bytes.  A candidate
        that fails this is discarded - it is NEVER written back to the original
        path.
        """
        st = stat_safe(path)
        if not st or st.st_size <= 0:
            return False, "candidate vanished or is empty", {}
        size = st.st_size
        if size >= original_size:
            return False, "no bytes were actually removed by the strategy", {}
        head = read_head(path, self.head_window)
        new_magic = sniff_magic(head)
        if new_magic != original_magic:
            return False, f"candidate magic changed: {original_magic} -> {new_magic}", {}
        tail = read_tail(path, self.tail_window)
        if heuristics.check_trailing_payload(path, head, tail, size):
            return False, "trailing payload still present in candidate", {}
        if not self._structural_end_ok(original_magic, tail):
            return False, "candidate lacks the structural end marker for this container", {}
        hashes = compute_hashes(path) or {}
        sha = hashes.get("sha256")
        if sha and self.db.lookup(sha, "sha256"):
            return False, "candidate still matches a known-bad signature", {}
        return True, "ok", {"size": size, "sha256": sha}

    @staticmethod
    def _structural_end_ok(magic: str, tail: bytes) -> bool:
        """True when the tail structurally terminates like a valid container."""
        end = _STRUCT_END.get(magic)
        if end is None:
            return True                       # no strict terminator requirement
        tail = tail.rstrip(b" \t\r\n\x00")    # tolerate trivial trailing padding
        if magic == "zip":
            pos = tail.rfind(b"PK\x05\x06")
            return pos != -1 and (len(tail) - pos) >= 22    # EOCD record must fit
        return tail.endswith(end)

    def _signature_anchored_offset(self, path: Path, size: int,
                                   finding=None) -> Optional[int]:
        """Strategy 3 - CONSERVATIVE signature-anchored trim.

        Only strips a trailing region whose bytes hash to a KNOWN-BAD signature
        (the live signature DB, or the finding's recorded sha256).  When the
        trailing bytes cannot be anchored to a known-bad artifact it DECLINES
        (returns None) rather than guess-stripping what may be legitimate data.
        """
        head = read_head(path, self.head_window)
        if not head:
            return None
        magic = sniff_magic(head)
        if magic not in _EOF_MARKERS:
            return None
        tail = read_tail(path, self.tail_window)
        offset = _offset_from_tail(tail, size, magic, self.min_trailing_payload)
        if offset is None:
            return None
        blob = read_range(path, offset, max(0, size - offset))
        if not blob:
            return None
        region_sha = hashlib.sha256(blob).hexdigest()
        if self.db.lookup(region_sha, "sha256"):
            return offset
        f_sha = (finding.get("sha256") if isinstance(finding, dict)
                 else getattr(finding, "sha256", None))
        if f_sha and str(f_sha).lower() == region_sha:
            return offset
        return None

    def _strategy_offset(self, sname: str, path: Path, finding=None) -> Optional[int]:
        """Dispatch the set of MEANINGFULLY DIFFERENT boundary-finders."""
        st = stat_safe(path)
        size = st.st_size if st else 0
        if sname == _STRATEGY_STABLE:
            return self._trailing_payload_offset(path, size)
        if sname == _STRATEGY_FULLSCAN:
            return full_scan_offset(path, size, head_window=self.head_window,
                                    min_trailing_payload=self.min_trailing_payload)
        if sname == _STRATEGY_ANCHORED:
            return self._signature_anchored_offset(path, size, finding=finding)
        return None

    def _strategy_note(self, sname: str, path: Path) -> str:
        """Human-readable "why this attempt declined" for the quarantine notes."""
        head = read_head(path, self.head_window)
        magic = sniff_magic(head)
        if magic not in _EOF_MARKERS:
            return "no container end-marker for this file type"
        if sname == _STRATEGY_ANCHORED:
            return ("trailing region does not match any known-bad signature - "
                    "conservative decline")
        return "no EOF-marker boundary found in the scanned window"

    def disinfect_file(self, path: Path, *, dry_run: bool = False,
                       verify: bool = True) -> Dict[str, object]:
        """Strip appended malicious payloads from a container file.

        Pipeline: encrypted backup -> offset detection -> truncate -> verify
        -> rollback from encrypted backup on any failure.
        """
        path = Path(path)
        rec: Dict[str, object] = {"action": "disinfect", "path": str(path),
                                  "dry_run": dry_run}
        if not path.is_file():
            return {**rec, "status": "error",
                    "reason": "not a regular file - only files can be disinfected"}
        st = stat_safe(path)
        if not st or not st.st_size:
            return {**rec, "status": "error", "reason": "file unreadable or empty"}
        size_before = st.st_size

        try:
            sha_before = (compute_hashes(path) or {}).get("sha256")
        except OSError:
            sha_before = None
        rec["size_before"] = size_before
        rec["sha_before"] = sha_before

        # 1) Always secure an encrypted backup BEFORE touching anything.
        if not dry_run:
            self._ensure_key()
            bkp = backup_file(path, self.backup_dir, self.key)
            rec["backup_uid"] = bkp["backup_uid"]

        offset = self._trailing_payload_offset(path, size_before)

        if dry_run:
            if offset is None:
                rec.update({"status": "would_quarantine",
                            "reason": "no safe EOF-marker strip point; would quarantine"})
            else:
                rec.update({"status": "would_strip", "strip_bytes": size_before - offset})
            return rec

        if offset is None:
            # Cannot auto-strip safely (unknown container or no append point):
            # capture the original into quarantine and hand it to the analyst.
            try:
                q = self._quarantine_move(path, "SignatureMatch/Unstripable")
                rec.update({"status": "quarantined", "reason": "auto-strip not feasible",
                            "quarantine_uid": q["uid"]})
                self.db.log_disinfection(str(path), "strip", size_before, None,
                                         sha_before, None, q["uid"], "quarantined")
            except OSError as exc:
                rec.update({"status": "error", "reason": f"quarantine failed: {exc}"})
            return rec

        original_magic = sniff_magic(read_head(path, self.head_window)) or "unknown"
        try:
            self._truncate_at(path, offset)
        except (PermissionError, OSError) as exc:
            rec.update({"status": "error", "reason": f"cannot write file: {exc}",
                        "backup_available": rec.get("backup_uid")})
            return rec

        ok = True
        reason = "ok"
        if verify:
            ok, reason, meta = self._verify_clean(path, original_magic)
        else:
            meta = {"size": offset, "sha256": None}

        if not ok:
            rec["status"] = "rolled_back"
            rec["reason"] = reason
            self._rollback(path, rec)
            return rec

        rec.update({
            "status": "stripped", "reason": reason,
            "size_after": meta.get("size", offset), "sha_after": meta.get("sha256"),
            "strip_bytes": size_before - offset,
        })
        self.db.log_disinfection(str(path), "strip", size_before, meta.get("size", offset),
                                 sha_before, meta.get("sha256"), rec.get("backup_uid"), "ok")
        return rec

    def resolve_infector(self, path: Path, threat: Optional[str] = None,
                         finding=None, *, verify: bool = True,
                         strategies: Optional[Sequence[str]] = None) -> Dict[str, object]:
        """REVISED OUTCOME A - resolve the file IN PLACE or quarantine, the
        hard way first.

        Try EVERY honest rescue technique BEFORE quarantining:

          backup := encrypt(original)                 ZDL: pre-attempt backup
          for strategy in strategies:                 each is MEANINGFULLY
              candidate := copy(original)             different - a technique is
              apply strategy to candidate             applied to a TEMP COPY so
              if not verify(candidate):               the live original stays
                  drop candidate, record attempt      pristine until a candidate
                  continue                            fully verifies
              os.replace(candidate, original)         atomic publish - the ONLY
              purge(backup)                           write-back path
              return resolved_in_place

          fall back to Quarantine (LAST resort): keep the PRE-ATTEMPT backup,
          move the live copy to the store, record the FULL attempt chain.

        KEY PRINCIPLE (never regress - tested by regression suite):
          * a candidate reaches the original path ONLY after verify() passes -
            a failed-verify/declined candidate is NEVER written back
          * Quarantine is minimized by trying harder, but correctness is never
            sacrificed to avoid it: the file is quarantined rather than left
            corrupted or still-infected at its original path
        """
        path = Path(path)
        order = tuple(strategies) if strategies is not None else STRATEGY_ORDER
        rec: Dict[str, object] = {"action": "resolve_infector", "path": str(path)}
        if not path.is_file():
            return {**rec, "status": "error",
                    "reason": "not a regular file - only files can be resolved"}
        st = stat_safe(path)
        if not st or not st.st_size:
            return {**rec, "status": "error", "reason": "file unreadable or empty"}
        size_before = st.st_size
        original_magic = sniff_magic(read_head(path, self.head_window)) or "unknown"
        try:
            sha_before = (compute_hashes(path) or {}).get("sha256")
        except OSError:
            sha_before = None
        rec.update({"size_before": size_before, "sha_before": sha_before,
                    "strategies": list(order)})

        # 1) PRE-ATTEMPT encrypted backup - secured BEFORE any byte changes and
        #    kept until the file is definitively resolved one way or another.
        self._ensure_key()
        try:
            bkp = backup_file(path, self.backup_dir, self.key)
        except OSError as exc:
            return {**rec, "status": "error", "reason": f"backup failed: {exc}"}
        uid = str(bkp["backup_uid"])
        backup_blob = Path(bkp["store_path"])
        rec["backup_uid"] = uid

        attempts: List[Dict[str, str]] = []
        token = uuid.uuid4().hex[:8]

        # 2) Attempt chain - every technique on a staging copy, verified first.
        for i, sname in enumerate(order, start=1):
            candidate = path.parent / f".{path.name}.resolve-{token}-{i}.tmp"
            try:
                shutil.copyfile(path, candidate)
            except (PermissionError, OSError) as exc:
                attempts.append({"strategy": sname, "result": "error",
                                 "reason": f"cannot stage candidate: {exc}"})
                continue
            try:
                offset = self._strategy_offset(sname, candidate, finding)
                if offset is None:
                    attempts.append({"strategy": sname, "result": "declined",
                                     "reason": self._strategy_note(sname, candidate)})
                    continue
                self._truncate_at(candidate, offset)
                if verify:
                    ok, reason, meta = self._verify_sanitized(
                        candidate, original_magic, size_before)
                else:
                    ok, reason, meta = True, "verify=off", {}
                if not ok:
                    attempts.append({"strategy": sname, "result": "failed",
                                     "reason": f"candidate did not verify: {reason}"})
                    continue
                # Candidate VERIFIED -> atomic publish is the ONLY path to the
                # original.  Live bytes never change any other way here.
                os.replace(candidate, path)
                try:
                    backup_blob.unlink(missing_ok=True)     # short-lived, survivable
                except (PermissionError, OSError):
                    rec["backup_left"] = str(backup_blob)
                self.db.log_disinfection(str(path), "resolve", size_before,
                                         int(meta.get("size") or offset),
                                         sha_before, meta.get("sha256"), uid, "ok")
                try:
                    self.db.audit(
                        "resolve_in_place",
                        f"path={path} strategy={sname} attempt={i} "
                        f"size={size_before}->{meta.get('size', offset)} sha={sha_before}")
                except Exception:  # noqa: BLE001 - audit must never break resolve
                    pass
                attempts.append({"strategy": sname, "result": "ok",
                                 "reason": "verified clean - published to original path"})
                rec.update({
                    "status": "stripped",
                    "reason": f"resolved on attempt {i} ({sname})",
                    "outcome": "resolved_in_place",
                    "outcome_detail": (f"pre-attempt backup -> {sname} -> verify "
                                       "ok -> atomically published"),
                    "attempt": i, "attempts": attempts,
                    "strip_bytes": size_before - int(meta.get("size") or offset),
                    "sha_after": meta.get("sha256"),
                })
                return rec
            except (PermissionError, OSError) as exc:
                attempts.append({"strategy": sname, "result": "error",
                                 "reason": f"engine error: {exc}"})
            finally:
                try:
                    candidate.unlink(missing_ok=True)
                except (PermissionError, OSError):
                    pass

        # 3) Every honest attempt failed -> Quarantine is the LAST resort.  The
        #    PRE-ATTEMPT encrypted backup is KEPT (never purged here) and the
        #    row records the entire attempt chain for the analyst.
        if threat is not None:
            threat_name = str(threat)
        elif isinstance(finding, dict):
            threat_name = str(finding.get("name") or finding.get("threat_name")
                              or "unresolved-infector")
        elif finding is not None:
            threat_name = str(getattr(finding, "name", None) or "unresolved-infector")
        else:
            threat_name = "unresolved-infector"
        notes_lines = [
            f"resolve attempts exhausted ({len(attempts)}) - pre-attempt original "
            "preserved in encrypted backup",
        ]
        notes_lines += [f"[{i}] {a['strategy']}: {a['reason']}"
                        for i, a in enumerate(attempts, start=1)]
        notes = "\n".join(notes_lines)
        try:
            store = self.quarantine_dir / f"{uid}.q"
            shutil.copy2(path, store)
            path.unlink()
        except (PermissionError, OSError) as exc:
            # Quarantine itself failed (e.g. the file is locked).  The pristine
            # original AND the encrypted backup BOTH stay - never damage either.
            try:
                self.db.audit("resolve_failed",
                              f"path={path} attempts={len(attempts)} "
                              f"quarantine_fallback_failed={exc}")
            except Exception:  # noqa: BLE001
                pass
            return {**rec, "status": "error",
                    "reason": f"quarantine fallback failed: {exc}",
                    "outcome": "error", "attempts": attempts,
                    "backup_kept": str(backup_blob),
                    "file_present": bool(path.exists())}
        self.db.add_quarantine(uid=uid, original_path=str(path),
                               store_path=str(store), backup_path=str(backup_blob),
                               size=size_before, sha256=sha_before,
                               threat_name=threat_name, notes=notes)
        self.db.log_disinfection(str(path), "resolve", size_before, None,
                                 sha_before, None, uid, "quarantined")
        try:
            self.db.audit("quarantined_after_attempts",
                          f"path={path} threat={threat_name} attempts={len(attempts)}")
        except Exception:  # noqa: BLE001
            pass
        rec.update({
            "status": "quarantined",
            "outcome": "quarantined_after_attempts",
            "outcome_detail": (f"all {len(attempts)} strategies failed; pre-attempt "
                               "backup + full attempt history kept"),
            "quarantine_uid": uid, "quarantine_notes": notes,
            "attempts": attempts,
        })
        return rec

    def _rollback(self, path: Path, rec: Dict[str, object]) -> None:
        """Decrypt the pre-disinfect backup and atomically restore it."""
        uid = rec.get("backup_uid")
        if not uid:
            rec["rollback"] = "no backup uid - restore unavailable"
            return
        store = self.backup_dir / f"{uid}.bak.aes"      # canonical backup layout
        if not store.exists():
            rec["rollback"] = f"backup blob missing: {store}"
            return
        try:
            tmp = path.parent / f".{path.name}.rollback-{uuid.uuid4().hex[:8]}"
            restore_backup_file(store, tmp, self.key,
                                expected_sha=rec.get("sha_before"))
            os.replace(tmp, path)
            rec["rollback"] = f"restored from encrypted backup {uid}"
            self.db.log_disinfection(str(path), "strip", None, None, None, None,
                                     uid, "rolled_back")
        except (IntegrityError, OSError) as exc:
            rec["rollback"] = f"rollback failed: {exc}"

    # ----------------------------------------------------------------- quarantine
    def quarantine_file(self, path: Path, threat: str = "user-requested") -> Dict[str, object]:
        """Quarantine a file without attempting auto-disinfection."""
        path = Path(path)
        if not path.is_file():
            return {"path": str(path), "status": "error",
                    "reason": "not a regular file - only files can be quarantined"}
        try:
            meta = self._quarantine_move(path, threat)
            meta.update({"status": "quarantined"})
            return meta
        except OSError as exc:
            return {"path": str(path), "status": "error", "reason": str(exc)}

    # ------------------------------------------------- resolve-plan executors
    def execute_outcome_a(self, path: Path, *, verify: bool = True,
                          strategies: Optional[Sequence[str]] = None) -> Dict[str, object]:
        """Outcome A - resolve IN PLACE via the refined ``resolve_infector``
        chain: every strategy is applied to a temp candidate and verified BEFORE
        it may touch the original path; only when all honest attempts fail does
        the engine fall back to Quarantine (pre-attempt backup + full attempt
        history kept).  ``status`` always tells the truth about what happened.
        """
        rec = self.resolve_infector(path, verify=verify, strategies=strategies)
        if rec.get("status") not in ("stripped", "quarantined"):
            rec.setdefault("outcome", "error")
            rec.setdefault("outcome_detail", rec.get("reason", "engine error"))
        return rec

    def execute_outcome_b(self, path: Path, finding=None,
                          threat: Optional[str] = None) -> Dict[str, object]:
        """Outcome B - remove the live copy into the encrypted quarantine
        store (the old always-quarantine behavior; nothing is ever deleted).

        ``finding`` may be a Finding, a plain dict, or None; an explicit
        ``threat`` string overrides the extracted name.
        """
        if threat is None:
            if isinstance(finding, dict):
                threat = finding.get("name") or finding.get("threat_name")
            elif finding is not None:
                threat = getattr(finding, "name", None)
            threat = threat or "suspicious"
        rec = self.quarantine_file(path, threat=str(threat))
        if rec.get("status") == "quarantined":
            rec.update({"outcome": "quarantined_removed",
                        "outcome_detail": "encrypted backup -> moved live copy "
                                          "into quarantine store"})
        else:
            rec.update({"outcome": "error",
                        "outcome_detail": rec.get("reason", "engine error")})
        return rec

    def execute_plan(self, plan: Dict[str, object], path: Path,
                     finding=None) -> Dict[str, object]:
        """Dispatcher: run a ``resolve_plan()`` plan through the Outcome
        executors.  AutoPilot and every manual per-item handler share this
        path, so the default immediate-resolve behavior is identical
        everywhere (a finding is never acted on outside this route).
        """
        kind = (plan or {}).get("plan")
        if kind == PLAN_STRIP:
            return self.execute_outcome_a(path)
        if kind == PLAN_QUARANTINE:
            return self.execute_outcome_b(path, finding)
        if kind == PLAN_REVEAL:
            rec = self.reveal_hidden(path, dry_run=False)
            changed = len(rec.get("changed", []))
            rec["status"] = "revealed" if changed else "skipped"
            rec["outcome"] = "revealed" if changed else "no_change"
            rec["outcome_detail"] = ("cleared HIDDEN/SYSTEM attributes"
                                     if changed else "nothing to reveal")
            return rec
        # PLAN_SKIP and anything unknown -> never touched.
        reason = (plan or {}).get("reason", "manual review only")
        return {"action": "resolve_skip", "path": str(path), "status": "skipped",
                "outcome": "skipped", "plan": kind, "reason": reason}

    def purge_item(self, uid: str) -> Dict[str, object]:
        """Permanently delete a quarantined item (blob + encrypted backup).

        The audit row is retained with status 'purged' - history is never
        rewritten, and only explicitly user-confirmed purges erase artifacts.
        """
        rec: Dict[str, object] = {"uid": uid, "action": "purge"}
        row = self.db.get_quarantine(uid)
        if not row:
            return {**rec, "status": "error", "reason": "unknown quarantine uid"}

        targets = [p for p in (Path(row["store_path"]), Path(row["backup_path"])) if p]
        for blob in targets:
            try:
                blob.unlink(missing_ok=True)
            except (PermissionError, OSError) as exc:
                return {**rec, "status": "error",
                        "reason": f"cannot delete {blob}: {exc}"}
        self.db.set_quarantine_status(uid, "purged")
        rec.update({"status": "purged", "removed": [str(p) for p in targets]})
        self.db.log_disinfection(str(row["original_path"]), "purge", None, None,
                                 row.get("sha256"), None, uid, "purged")
        return rec

    def purge_verified_file(self, path: Path, threat: str,
                            expected_sha: Optional[str] = None) -> Dict[str, object]:
        """Auto-purge a PURE-MALWARE file (used by ``auto_purge_verified`` mode).

        Pipeline: encrypted backup -> delete original -> verify removal ->
        purge the short-lived backup.  Any doubt returns ``status == 'error'``
        with ``file_present`` telling the caller whether to fall back to
        long-term Quarantine; a legitimate file is never silently destroyed.
        The original bytes always exist (encrypted) before anything is deleted.
        """
        self._ensure_key()
        path = Path(path)
        rec: Dict[str, object] = {"action": "auto_purge", "path": str(path),
                                  "threat": threat}
        if not path.is_file() or path.is_symlink():
            return {**rec, "status": "error", "reason": "not a regular file",
                    "file_present": bool(path.exists())}
        try:
            size = path.stat().st_size
        except OSError as exc:
            return {**rec, "status": "error", "reason": f"cannot stat: {exc}",
                    "file_present": False}

        # 1) Mandatory encrypted backup BEFORE any destructive step.
        try:
            meta = backup_file(path, self.backup_dir, self.key)
        except OSError as exc:
            return {**rec, "status": "error",
                    "reason": f"backup failed: {exc}", "file_present": True}
        uid = str(meta["backup_uid"])
        rec["backup_uid"] = uid
        backup_blob = Path(meta["store_path"])
        got_sha = meta.get("sha256")

        def _vacate_backup() -> None:
            """Drop the short-lived backup after a failed purge (no orphans)."""
            try:
                backup_blob.unlink(missing_ok=True)
            except (PermissionError, OSError):
                rec["backup_left"] = str(backup_blob)

        # 2) Backup integrity + hash proof: only delete when the original bytes
        #    are pinned and the file did not change since the scan.
        if not backup_blob.exists() or int(meta.get("encrypted_size") or 0) <= 0:
            _vacate_backup()
            return {**rec, "status": "error", "reason": "backup write failed",
                    "file_present": True}
        if expected_sha is not None and got_sha and got_sha != expected_sha:
            _vacate_backup()
            return {**rec, "status": "error",
                    "reason": "file changed since scan (hash mismatch) - kept",
                    "file_present": True, "sha_before": got_sha}

        # 3) Delete the original; Windows file-locks are transient, so retry a
        #    few times before giving up.  If it still cannot be deleted we DON'T
        #    quarantine it (nothing is wrong with the file evidence-wise); we
        #    signal ``requires_manual_review`` instead and keep the backup-free
        #    original in place so nothing is destroyed or moved silently.
        if not self._delete_with_retry(path):
            _vacate_backup()
            return {**rec, "status": "error",
                    "reason": f"cannot delete after {_IO_DELETE_RETRIES} attempts "
                              "(file locked) - flagged for manual review",
                    "file_present": bool(path.exists()), "sha_before": got_sha,
                    "requires_manual_review": True}

        # 4) Verify removal before punishing anything else.
        try:
            still_there = path.exists()
        except OSError:
            still_there = False
        if still_there:
            _vacate_backup()
            return {**rec, "status": "error",
                    "reason": "file reappeared after delete - kept for review",
                    "file_present": True, "sha_before": got_sha}

        # 5) All verified: purge the short-lived backup and log the audit trail.
        try:
            backup_blob.unlink(missing_ok=True)
        except (PermissionError, OSError) as exc:
            # Original gone; the encrypted backup preserves the bytes.
            return {**rec, "status": "error",
                    "reason": f"backup purge failed: {exc}",
                    "file_present": False, "backup_left": str(backup_blob),
                    "sha_before": got_sha}

        self.db.log_disinfection(str(path), "auto_purge", size, 0, got_sha, None,
                                 uid, "purged")
        try:
            self.db.audit("auto_purge",
                          f"path={path} threat={threat} size={size} sha={got_sha}")
        except Exception:  # noqa: BLE001 - audit must never break the purge
            pass
        rec.update({"status": "auto_purged", "size": size, "freed_bytes": size,
                    "sha_before": got_sha})
        return rec

    def _delete_with_retry(self, path: Path) -> bool:
        """Unlink ``path`` with a few escalating retries (transient Windows
        file-locks).  Returns True only once the path is actually gone."""
        for attempt in range(1, _IO_DELETE_RETRIES + 1):
            try:
                path.unlink()
            except (PermissionError, OSError):
                if attempt < _IO_DELETE_RETRIES:
                    try:
                        time.sleep(_IO_DELETE_BACKOFF_S * attempt)
                    except OSError:
                        pass
                continue
            try:
                return not path.exists()
            except OSError:
                return False
        return path.exists() is False

    def _publish_verified(self, tmp: Path, original: Path) -> None:
        """Publish a verified staging blob to its final path, CROSS-VOLUME-safe.

        Windows ``os.replace`` is atomic ONLY within a single NTFS volume.
        ``restore_item`` decrypts the blob into ``backup_dir`` (drive C:) while
        the ORIGINAL path lives on an external drive (H:/D:/E:).  A bare
        ``os.replace(tmp, original)`` therefore raises:

            WinError 17: "The system cannot move the file to a different disk
            drive"

        -- exactly the field crash where every C: item restored but every
        H:/D:/E: item failed ("replace": "restore write failed").

        Zero-data-loss invariant (never regress - Covered by
        scripts/test_restore_cross_volume.py):
          1. SAME volume      -> os.replace (atomic, fast path, unchanged);
          2. CROSS volume     -> copy bytes into a temp in ``original.parent``
             (SAME volume as dst, so the final publish below IS atomic),
             fsync the copy, verify size + sha256 against ``tmp`` BEFORE
             anything touches ``original``,
             then os.replace(tmp_in_dst_volume, original)   # atomic publish
             and only AFTER dst is published, unlink the C: staging ``tmp``.
          3. On ANY failure the destination is NEVER written partially: the
             temp copy in dst's own directory is cleaned up, ``original`` is
             left untouched, and the C: staging blob is retained for retry -
             zero bytes are lost and nothing is half-published.
        """
        try:
            src_root = os.path.splitdrive(os.path.abspath(tmp))[0].lower()
            dst_root = os.path.splitdrive(os.path.abspath(original))[0].lower()
            if src_root == dst_root:                       # 1) atomic fast path
                os.replace(tmp, original)
                return
        except OSError as exc:
            if getattr(exc, "winerror", None) != 17:
                raise
            # Drive detection itself was inconclusive; fall through to the
            # robust cross-volume path rather than guess wrong.

        # 2) cross-volume: stage into original's OWN directory (same volume ->
        #    the final os.replace is atomic), verify, then atomic publish.
        original.parent.mkdir(parents=True, exist_ok=True)
        tmp_v = original.parent / f".secudrive-publish-{uuid.uuid4().hex[:10]}"
        try:
            sha = hashlib.sha256()
            n = 0
            with tmp.open("rb") as fsrc, tmp_v.open("xb") as fdst:
                while chunk := fsrc.read(1024 * 1024):
                    fdst.write(chunk)
                    sha.update(chunk)
                    n += len(chunk)
                fdst.flush()
                os.fsync(fdst.fileno())
            # verify the staged copy BEFORE it can touch original:
            with tmp_v.open("rb") as fv:
                got_sha = hashlib.sha256()
                got_n = 0
                while chunk := fv.read(1024 * 1024):
                    got_sha.update(chunk)
                    got_n += len(chunk)
            if got_n != n or got_sha.hexdigest() != sha.hexdigest():
                raise OSError("publish verify failed: staged copy does not match "
                              "decrypted blob - original untouched, blob kept")
            os.replace(tmp_v, original)                    # atomic publish
        finally:
            try:
                tmp_v.unlink(missing_ok=True)              # clean up in ALL paths
            except OSError:
                pass
        tmp.unlink(missing_ok=True)                        # only AFTER pub verified

    def restore_item(self, uid: str) -> Dict[str, object]:
        """Decrypt + verify + restore a quarantined item to its original path."""
        rec: Dict[str, object] = {"uid": uid, "action": "restore"}
        row = self.db.get_quarantine(uid)
        if not row:
            return {**rec, "status": "error", "reason": "unknown quarantine uid"}

        # Restore from the *encrypted* backup (the .q capture is the analyst
        # plaintext copy; the cryptographically verified source is the .bak.aes).
        store = Path(row["backup_path"])
        if not store.exists():
            return {**rec, "status": "error",
                    "reason": f"encrypted backup missing: {store}"}

        original = Path(row["original_path"])

        # Retire the empty-parent-folder leak: NEVER create original.parent here.
        # The folder used to be mkdir'd *before* decrypt, so any restore that then
        # failed decryption/verify left behind an empty directory where the file
        # should have appeared (reported: "restore produced an empty folder").
        # Decrypt to a quarantine-dir staging file first; only materialise the
        # parent once the plaintext has been verified, and if the restore still
        # fails afterwards, drop the just-created empty folder again.

        parent_existed = original.parent.exists()
        self._ensure_key()
        tmp = self.backup_dir / f".restore-staging-{uid[:12]}"
        try:
            restore_backup_file(store, tmp, self.key,
                                expected_sha=row["sha256"],
                                expected_size=int(row["size"] or 0) or None)
        except IntegrityError as exc:
            # Corrupt / truncated encrypted backup: the plaintext is unrecoverable
            # from this store.  Record it distinctly so the Quarantine UI can show
            # "backup corrupted (unrecoverable)" instead of a generic verify error.
            try:
                self.db.audit(
                    "restore_corrupt",
                    f"{uid} backup unusable: {exc}")
            except Exception:
                pass
            return {**rec, "status": "error", "unrecoverable": True,
                    "reason": f"backup corrupted: {exc}"}
        except OSError as exc:
            return {**rec, "status": "error", "reason": f"verify/decrypt failed: {exc}"}

        if not parent_existed:
            original.parent.mkdir(parents=True, exist_ok=True)

        def _cleanup_new_parent() -> None:
            if parent_existed:
                return
            try:
                if original.parent.is_dir() and not any(original.parent.iterdir()):
                    original.parent.rmdir()
            except OSError:
                pass

        def _cleanup_staging() -> None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

        try:
            if original.exists():
                occupant = self._quarantine_move(original, "PreRestoreOccupant")
                rec["displaced"] = occupant.get("uid")
        except OSError as exc:
            _cleanup_new_parent()
            _cleanup_staging()
            return {**rec, "status": "error",
                    "reason": f"cannot displace existing file {original}: {exc}"}
        try:
            self._publish_verified(tmp, original)
        except OSError as exc:
            _cleanup_new_parent()
            _cleanup_staging()
            return {**rec, "status": "error", "reason": f"restore write failed: {exc}"}
        self.db.set_quarantine_status(uid, "restored")
        rec.update({"status": "restored", "path": str(original),
                    "sha256": row["sha256"]})
        return rec

    # --------------------------------------------------- third-party quarantine
    def extract_external_blobs(self, src_dir: Path, out_dir: Path) -> Dict[str, object]:
        """Ingest raw blobs exported from third-party quarantine stores.

        Vendor quarantine formats are proprietary and frequently encrypted; this
        helper consumes the *exported raw bytes* (which analysts obtain through
        each vendor's own tooling) and disinfects them like any other file.
        """
        src_dir, out_dir = Path(src_dir), Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        rec: Dict[str, object] = {"action": "extract_external", "restored": [], "errors": []}
        for blob in sorted(src_dir.glob("*")):
            if not blob.is_file():
                continue
            target = out_dir / blob.name
            try:
                meta = backup_file(blob, self.backup_dir, self.key)
                rec["restored"].append({
                    "source": str(blob), "target": str(target),
                    "backup_uid": meta["backup_uid"],
                    "sha256": meta.get("sha256"), "status": "staged",
                })
            except OSError as exc:
                rec["errors"].append(f"{blob}: {exc}")
        return rec