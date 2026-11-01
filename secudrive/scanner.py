"""scanner.py - File Scanner Module (Core Engine).

Design notes:
    * Single-pass ``os.scandir`` recursion - lower syscall overhead and
      materially faster than ``os.walk`` for deep USB trees.
    * Files <= ``max_hash_size`` are streamed through SHA-256 (+ optional MD-5)
      and cross-referenced against the SQLite signature table.
    * Heuristic sweep (double extensions, autorun.inf, shortcut hijacks,
      trailing payloads) runs on every file regardless of hash result.
    * Every finding is persisted to ``scan_findings`` for a full audit trail.
    * Permission / sharing / I/O errors are swallowed per-file (logged at
      debug level) so a single locked file never aborts a whole drive scan.

Performance seam: the hot loop (hashing + traversal) is deliberately isolated
in ``Scanner._scan_file`` / ``_walk`` so it can be re-implemented in Rust/Go
behind the same ``Scanner`` interface later without touching the CLI, DB, or
recovery layers.
"""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from stat import S_ISREG
from typing import Dict, Iterable, List, Optional, Union

from . import heuristics
from .database import Database
from .logging_utils import get_logger
from .safefile import compute_hashes, read_head, read_tail

logger = get_logger("scanner")


def _rust_engine():
    """Return the compiled scan engine module, or None when unavailable.

    The module is imported lazily (and cached) so the pure-Python fallback
    keeps working when the compiled extension is not installed. Set the
    ``SECUDRIVE_RUST_DISABLE`` env var to force the Python engine.
    """
    mod = getattr(_rust_engine, "_mod", None)
    if mod is None and not getattr(_rust_engine, "_tried", False):
        _rust_engine._tried = True
        if os.environ.get("SECUDRIVE_RUST_DISABLE"):
            logger.info("rust engine disabled via SECUDRIVE_RUST_DISABLE")
        else:
            try:
                import secudrive_rust as _candidate  # type: ignore
                # A repo crate SOURCE dir (e.g. "rust_engine/") must never be
                # be mistaken for the compiled wheel; verify the module really
                # exposes the compiled API.
                if (
                        hasattr(_candidate, "scan_directory")
                        and callable(_candidate.scan_directory)
                        and hasattr(_candidate, "ScanOutcome")):
                    mod = _candidate
                    logger.info("rust scan engine active: secudrive_rust %s",
                                getattr(_candidate, "__version__", "?"))
                else:
                    logger.info("secudrive_rust import found but is not the "
                                "compiled engine (namespace package?); using "
                                "Python scan engine")
            except Exception as exc:  # ImportError / ABI mismatch / missing DLL
                logger.info("rust engine unavailable (%s: %s); using Python scan engine",
                            type(exc).__name__, exc)
        _rust_engine._mod = mod
    return mod


class ScanCancelled(Exception):
    """Raised cooperatively when a scan is cancelled; unwinds cleanly."""

# Windows attribute bits used to spot hidden/system payload droppers.
if os.name == "nt":
    import ctypes

    FILE_ATTRIBUTE_HIDDEN = 0x00000002
    FILE_ATTRIBUTE_SYSTEM = 0x00000004
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

    def _get_attributes_windows(path: str) -> int:
        try:
            return ctypes.windll.kernel32.GetFileAttributesW(path)
        except Exception:  # ctypes can raise arbitrary OSErrors on exotic paths
            return INVALID_FILE_ATTRIBUTES
else:
    FILE_ATTRIBUTE_HIDDEN = 0
    FILE_ATTRIBUTE_SYSTEM = 0
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

    def _get_attributes_windows(path: str) -> int:  # pragma: no cover - posix branch
        return INVALID_FILE_ATTRIBUTES


DEFAULT_EXCLUDE_DIRS = frozenset({
    "$recycle.bin", "system volume information", "windows", "system32",
    "winsxs", "program files", "program files (x86)", "programdata",
    "$sysreset", "recovery", "boot", "appdata", "node_modules", ".git",
    "venv", ".venv", "secudrive",
})


# ---------------------------------------------------------------------- models
@dataclass
class ScanOptions:
    max_hash_size: int = 512 * 1024 * 1024
    max_depth: int = 0                     # 0 = unlimited
    follow_symlinks: bool = False
    hash_md5: bool = True
    check_heuristics: bool = True
    exclude_dirs: frozenset = DEFAULT_EXCLUDE_DIRS
    threads: int = 0                       # rust hash workers; 0 = auto (cpu count)
    use_rust: bool = True                  # prefer the compiled engine when present

    def with_overrides(self, **kw) -> "ScanOptions":
        for k, v in kw.items():
            if hasattr(self, k) and v is not None:
                setattr(self, k, v)
        return self


@dataclass
class Finding:
    path: Path
    category: str                 # 'signature' | 'heuristic'
    name: str
    confidence: float
    evidence: str = ""
    size: Optional[int] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    hidden: bool = False
    system: bool = False


@dataclass
class ScanReport:
    scan_id: str
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    files_seen: int = 0
    dirs_seen: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    findings: List[Finding] = field(default_factory=list)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.confidence, reverse=True)

    def by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts

    def top_threats(self, limit: int = 10) -> List[tuple[str, int]]:
        names: Dict[str, int] = {}
        for f in self.findings:
            names[f.name] = names.get(f.name, 0) + 1
        return sorted(names.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    def finish(self) -> "ScanReport":
        self.finished = time.time()
        return self

    def print_summary(self) -> None:
        from .logging_utils import setup_logging  # idempotent; ensures console
        elapsed = self.finished - self.started if self.finished else 0.0
        print("\n================ SCAN SUMMARY ================")
        print(f"scan id          : {self.scan_id}")
        print(f"duration         : {elapsed:.2f}s")
        print(f"dirs scanned     : {self.dirs_seen}")
        print(f"files scanned    : {self.files_seen}")
        print(f"bytes hashed     : {self.bytes_scanned:,}")
        print(f"i/o errors (skp) : {self.errors}")
        print(f"findings         : {len(self.findings)}  {dict(self.by_category())}")
        if self.findings:
            print("\n-- top threats --")
            for name, count in self.top_threats():
                print(f"  {name:<28} x{count}")
            print("\n-- details --")
            for f in self.sorted_findings()[:60]:
                flag = ""
                if f.hidden or f.system:
                    bits = []
                    if f.hidden:
                        bits.append("H")
                    if f.system:
                        bits.append("S")
                    flag = f"  [attrs:+{''.join(bits)}]"
                print(f"  [{f.confidence:.2f}] {f.category:<9} {f.name:<24} {f.path}{flag}")
                if f.evidence:
                    print(f"        {f.evidence}")
        print("==============================================")


# ---------------------------------------------------------------------- scanner
class Scanner:
    """Recursively scans targets; emits signature + heuristic findings."""

    def __init__(self, db: Database, options: Optional[ScanOptions] = None,
                 progress: Optional[callable] = None,
                 cancel_event: Optional[object] = None) -> None:
        self.db = db
        self.opts = options or ScanOptions()
        self.report = ScanReport(scan_id=uuid.uuid4().hex[:12])
        # progress: callable(dict) -> {"event","path","files_seen","dirs_seen",
        #                              "bytes_scanned","findings","elapsed_s"}
        self._progress = progress or (lambda info: None)
        self._cancel_event = cancel_event
        self._cancelled = False
        self._started_ts = None

    def cancel(self) -> None:
        """Request a cooperative stop; the scan unwinds at the next checkpoint."""
        self._cancelled = True

    def _check_cancel(self) -> None:
        if self._cancelled or (self._cancel_event and self._cancel_event.is_set()):
            raise ScanCancelled()

    def _emit_progress(self, event: str, path: Path) -> None:
        try:
            self._progress({
                "event": event,
                "path": str(path),
                "files_seen": self.report.files_seen,
                "dirs_seen": self.report.dirs_seen,
                "bytes_scanned": self.report.bytes_scanned,
                "findings": len(self.report.findings),
                "elapsed_s": (time.time() - self._started_ts) if self._started_ts else 0.0,
            })
        except Exception:  # progress callbacks must never break the scan
            pass

    # ------------------------------------------------------------- public API
    def scan(self, targets: Union[str, Path, Iterable[Union[str, Path]]]) -> ScanReport:
        self._started_ts = time.time()
        self._emit_progress("start", Path(""))
        try:
            if isinstance(targets, (str, Path)):
                targets = [targets]
            for target in targets:
                self._check_cancel()
                root = Path(target).expanduser().resolve()
                if not root.exists():
                    logger.warning("target does not exist, skipping: %s", root)
                    self.report.errors += 1
                    continue
                logger.info("scanning target: %s", root)
                if root.is_dir():
                    if self.opts.use_rust and _rust_engine() is not None:
                        self._scan_dir_rust(root)
                    else:
                        self._walk(root, depth=0)
                else:
                    self._scan_file(root)
        except ScanCancelled:
            logger.info("scan cancelled by user")
        return self.report.finish()

    # ---------------------------------------------------------------- traversal
    def _walk(self, dir_path: Path, depth: int) -> None:
        self._check_cancel()
        if self.opts.max_depth and depth > self.opts.max_depth:
            return
        self.report.dirs_seen += 1

        if depth == 0:
            self._dir_attribute_heuristics(dir_path)   # root-level hidden/attr pass

        try:
            iterator = os.scandir(dir_path)
        except (PermissionError, OSError) as exc:
            logger.warning("cannot enter directory %s: %s", dir_path, exc)
            self.report.errors += 1
            return
        with iterator as scan_it:
            for entry in scan_it:
                try:
                    is_dir = entry.is_dir(follow_symlinks=self.opts.follow_symlinks)
                except OSError:
                    self.report.errors += 1
                    continue
                full = dir_path / entry.name
                if is_dir:
                    if entry.name.lower() in self.opts.exclude_dirs:
                        logger.debug("excluding dir: %s", full)
                        continue
                    self._walk(full, depth + 1)
                else:
                    self._scan_file(full)
        self._dir_shortcut_heuristics(dir_path)

    # --------------------------------------------------- compiled engine path
    def _rust_progress(self, path: str, files_seen: int, dirs_seen: int,
                       bytes_scanned: int, errors: int) -> None:
        """Streamed progress ticks from the Rust engine (same dict shape as
        ``_emit_progress`` so every existing consumer keeps working)."""
        try:
            self._progress({
                "event": "file",
                "path": str(path),
                "files_seen": int(files_seen),
                "dirs_seen": int(dirs_seen),
                "bytes_scanned": int(bytes_scanned),
                "errors": int(errors),
                "findings": len(self.report.findings),
                "elapsed_s": (time.time() - self._started_ts) if self._started_ts else 0.0,
            })
        except Exception:  # progress callbacks must never break the scan
            pass

    def _rust_cancel_check(self) -> None:
        """Called from Rust between batches; raises ScanCancelled to unwind."""
        self._check_cancel()

    def _scan_dir_rust(self, dir_path: Path) -> None:
        """Walk + hash a directory tree with the compiled engine."""
        rust = _rust_engine()
        if rust is None:
            self._walk(dir_path, depth=0)
            return
        self._dir_attribute_heuristics(dir_path)   # root-level hidden/attr pass
        exclude_dirs = sorted(self.opts.exclude_dirs)
        try:
            outcome = rust.scan_directory(
                str(dir_path),
                hash_algo="sha256+md5",
                max_hash_size=self.opts.max_hash_size,
                max_depth=self.opts.max_depth,
                follow_symlinks=self.opts.follow_symlinks,
                exclude_dirs=exclude_dirs,
                threads=self.opts.threads,
                progress_cb=self._rust_progress,
                cancel_cb=self._rust_cancel_check,
            )
        except ScanCancelled:
            raise
        except Exception as exc:
            logger.warning("rust engine failed for %s (%s: %s); Python fallback",
                           dir_path, type(exc).__name__, exc)
            self._walk(dir_path, depth=0)
            return

        self.report.dirs_seen += outcome.stats.dirs_seen
        self.report.files_seen += outcome.stats.files_seen
        self.report.bytes_scanned += outcome.stats.bytes_scanned
        self.report.errors += outcome.stats.errors

        for result in outcome.results:
            self._check_cancel()
            self._consume_rust_result(Path(result.path), result)
            self._emit_progress("file", Path(result.path))
        for lnk_dir in outcome.lnk_dirs:
            self._dir_shortcut_heuristics(Path(lnk_dir))

    def _consume_rust_result(self, path: Path, result) -> None:
        """Post-process one compiled-engine result: attrs, signature lookups,
        and the heuristic sweep (everything that stays in Python)."""
        hidden = system = False
        if os.name == "nt":
            attrs = _get_attributes_windows(str(path))
            if attrs != INVALID_FILE_ATTRIBUTES:
                hidden = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
                system = bool(attrs & FILE_ATTRIBUTE_SYSTEM)

        sha256 = result.sha256
        md5 = result.md5 if self.opts.hash_md5 else None
        if result.error is None and (sha256 or md5) and result.size > 0:
            self._check_signature(path, result.size, sha256, md5, hidden, system)

        if self.opts.check_heuristics and result.size > 0:
            for item in heuristics.run_file_heuristics(path, size=result.size):
                self._add_finding(path, item)

    # --------------------------------------------------- per-directory heuristics
    def _dir_attribute_heuristics(self, dir_path: Path) -> None:
        """Report on hidden/system attributes at the target root (dropper lesson).

        Volume roots / mount points (drive letters, an inserted USB drive, a
        network share, a mounted VHD...) are EXCLUDED: their HIDDEN/SYSTEM bits
        are an OS/drive-affinity detail, not a drop-point signal, and a scan
        root is a directory the user asked us to inspect anyway.  Routing it into
        the file-based resolve pipeline would raise "Failed" on every drive
        (no file to disinfect/quarantine) and dead-end the Act... buttons.  The
        attribute reveal on roots is still delivered separately by
        ``Autopilot._reveal_root_attributes`` for real targets, so nothing is
        lost - only the bogus per-drive *finding* is suppressed (same guardrail
        philosophy as LOST.DIR / recovery dirs)."""
        if os.name != "nt":
            return
        try:
            if os.path.ismount(str(dir_path)):
                return
        except OSError:
            pass
        try:
            attrs = _get_attributes_windows(str(dir_path))
        except Exception:
            return
        if attrs == INVALID_FILE_ATTRIBUTES:
            return
        bits = []
        if attrs & FILE_ATTRIBUTE_HIDDEN:
            bits.append("HIDDEN")
        if attrs & FILE_ATTRIBUTE_SYSTEM:
            bits.append("SYSTEM")
        if bits:
            self.report.findings.append(Finding(
                path=dir_path,
                category="heuristic",
                name="HiddenRootFolder",
                confidence=0.6,
                evidence=f"target root carries {'+'.join(bits)} attributes",
            ))

    def _dir_shortcut_heuristics(self, dir_path: Path) -> None:
        """Cross-check all *.lnk in one directory against real sibling files."""
        try:
            names = {e.name.lower() for e in os.scandir(dir_path)}
        except OSError:
            return
        for e in os.scandir(dir_path):
            try:
                if e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if e.name.lower().endswith(".lnk"):
                for hf in heuristics.run_lnk_heuristics(dir_path / e.name, names):
                    self._add_finding(dir_path / e.name, hf)

    # ---------------------------------------------------------------- per-file
    def _scan_file(self, path: Path) -> None:
        if path.name.lower() in self.opts.exclude_dirs:
            return
        try:
            st = path.stat()
        except (PermissionError, OSError) as exc:
            logger.debug("cannot stat %s: %s", path, exc)
            self.report.errors += 1
            return
        if not S_ISREG(st.st_mode):
            return                                    # skip FIFOs, sockets, devices
        size = st.st_size
        self.report.files_seen += 1

        hidden = system = False
        if os.name == "nt":
            attrs = _get_attributes_windows(str(path))
            if attrs != INVALID_FILE_ATTRIBUTES:
                hidden = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
                system = bool(attrs & FILE_ATTRIBUTE_SYSTEM)

        sha256 = md5 = None
        if 0 < size <= self.opts.max_hash_size:
            algorithms = ("sha256", "md5") if self.opts.hash_md5 else ("sha256",)
            hashes = compute_hashes(path, algorithms)
            if hashes is None:
                logger.debug("unreadable (locked/permission) %s", path)
                self.report.errors += 1
            else:
                sha256 = hashes.get("sha256")
                md5 = hashes.get("md5")
                self.report.bytes_scanned += size
                self._check_signature(path, size, sha256, md5, hidden, system)
        else:
            logger.info("skipping hash for oversized/locked file: %s (%d bytes)", path, size)

        if self.opts.check_heuristics and size > 0:
            for item in heuristics.run_file_heuristics(path, size=size):
                self._add_finding(path, item)

        self._emit_progress("file", path)

    def _check_signature(self, path: Path, size: int, sha256: Optional[str],
                         md5: Optional[str], hidden: bool, system: bool) -> None:
        """Cross-reference hashes against the local signature DB."""
        if sha256:
            row = self.db.lookup(sha256, "sha256")
            if row:
                self.report.findings.append(Finding(
                    path=path, category="signature", name=f"Signature:{row['threat_name']}",
                    confidence=1.0, size=size, sha256=sha256, md5=md5,
                    hidden=hidden, system=system,
                    evidence=f"exact {row['hash_type']} match [{row['source'] or 'local'}]",
                ))
        if md5 and (row := self.db.lookup(md5, "md5")):
            self.report.findings.append(Finding(
                path=path, category="signature", name=f"Signature:{row['threat_name']}",
                confidence=1.0, size=size, sha256=sha256, md5=md5,
                hidden=hidden, system=system,
                evidence="exact md5 match [legacy table]",
            ))

    def _add_finding(self, path: Path, hf: heuristics.HeuristicFinding) -> None:
        self.report.findings.append(Finding(
            path=path, category=hf.category, name=hf.name,
            confidence=hf.confidence, evidence=hf.evidence, size=hf.meta.get("size"),
        ))

    # ------------------------------------------------------------------ persist
    def persist(self) -> int:
        """Write all findings to the DB. Returns row count."""
        rows = []
        for f in self.report.findings:
            rows.append({
                "path": str(f.path), "category": f.category, "name": f.name,
                "confidence": f.confidence, "size": f.size, "sha256": f.sha256,
                "evidence": f.evidence,
            })
        return self.db.record_findings(self.report.scan_id, rows)