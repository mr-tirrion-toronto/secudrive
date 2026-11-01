"""realtime_monitor.py - TRUE continuous real-time file-system protection.

Unlike periodic scans, this watches the file system continuously (on Windows
via ``ReadDirectoryChangesW`` through the platform provider) and reacts the
INSTANT a file changes.

Design:
    * One async OVERLAPPED watch loop per drive root (system drive + external),
      continuously re-armed; events stream CREATE / MODIFY / RENAME / DELETE.
      The loop itself lives in ``platform.windows_provider.WindowsWatchSession``.
    * Affected files are debounced (quiet period, config ``rt_debounce_ms``)
      so a mid-write file is not scanned until it settles (large downloads).
    * Settled files are queued into a bounded background thread pool
      (``rt_max_concurrent``) for a FAST single-file hash + heuristic pass
      that reuses ``scanner.Scanner`` (exactly the same signature DB +
      heuristics as a manual scan -- never a full re-walk).
    * Detections go through ``RecoveryEngine`` with the same Zero Data Loss
      invariant (encrypted backup first) used everywhere else.
    * Auto-throttle: when SecuDrive's own process CPU exceeds
      ``rt_cpu_threshold``%, new scans are paused until it drops (raw samples
      come from ``provider.sample_cpu_percent()``).
    * Crash-proofing: every OS callback and thread body is wrapped in
      try/except and routed through ``crashguard``; a failed watch thread is
      logged and restarted with backoff -- never fatal.

This module is GUI / CLI agnostic: it exposes plain callbacks (``on_event``,
``on_detection``, ``on_state``) that the GUI or CLI marshals into its own
event system (Qt signals, etc.).
"""
from __future__ import annotations

import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from . import crashguard
from .logging_utils import get_logger
from .platform import get_provider
from .safefile import stat_safe

logger = get_logger("realtime")

provider = get_provider()

# ---------------------------------------------------------------------------
# File-watch action codes (the watch loop itself lives in the platform
# provider; these codes still drive RealtimeMonitor event handling).
# ---------------------------------------------------------------------------
FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5

_ACTION_NEW = {FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_NEW_NAME}
_ACTION_GONE = {FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_OLD_NAME}

_SKIP_FILENAMES = frozenset({
    "secudrive.db", "secudrive_debug.log", "secudrive.json",
    ".secudrive.key",
})

# OS / system dirs excluded by default (lowercase, matching directory name).
_EXCLUDE_DIRS = frozenset({
    "$recycle.bin", "system volume information", "windows", "system32",
    "winsxs", "program files", "program files (x86)", "programdata",
    "$sysreset", "recovery", "boot", "appdata", "node_modules", ".git",
    "venv", ".venv",
})


# ---------------------------------------------------------------------------
# CPU throttle meter
# ---------------------------------------------------------------------------
class _CPUMeter:
    """Sample our own process CPU% to protect the user's foreground apps."""

    def __init__(self, threshold: float, sample_s: float) -> None:
        self.threshold = max(5.0, min(threshold, 99.0))
        self.sample_s = max(0.2, sample_s)
        self.percent = 0.0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._first_sample = True

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="RT-CPUMeter")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _sample_once(self) -> float:
        pct = provider.sample_cpu_percent()
        if self._first_sample:
            self._first_sample = False
            return min(pct, 100.0)
        self.percent = (self.percent * 0.6) + (pct * 0.4)
        return min(self.percent, 100.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._sample_once()
            self._stop.wait(self.sample_s)


# ---------------------------------------------------------------------------
# Main controller
# ---------------------------------------------------------------------------
class RealtimeMonitor:
    """GUI / CLI agnostic real-time protection engine.

    Callbacks:
        on_event(text, kind):      'info' = feed line, 'event' = rolling feed.
        on_detection(info):        path + finding + action taken.
        on_state(state):           dict with 'key', 'active', extra fields.
    """

    def __init__(self, ctx: Any, *,
                 on_event: Optional[Callable[[str, str], None]] = None,
                 on_detection: Optional[Callable[[dict], None]] = None,
                 on_state: Optional[Callable[[dict], None]] = None) -> None:
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.db = ctx.db
        self._engine = None

        self.on_event = on_event or (lambda _t, _k: None)
        self.on_detection = on_detection or (lambda _i: None)
        self.on_state = on_state or (lambda _i: None)

        # knobs (safe defaults if config is old)
        self.action = str(self.cfg.get("rt_action", "quarantine")).lower()
        self.max_concurrent = int(self.cfg.get("rt_max_concurrent", 2))
        self.debounce_ms = int(self.cfg.get("rt_debounce_ms", 500))
        self.buffer_bytes = int(self.cfg.get("rt_buffer_bytes", 1048576))
        self.cpu_threshold = float(self.cfg.get("rt_cpu_threshold", 55.0))
        self.cpu_sample_s = float(self.cfg.get("rt_cpu_sample_s", 1.0))
        self.queue_cap = int(self.cfg.get("rt_queue_cap", 1500))
        self.watch_system_drive = bool(self.cfg.get("rt_watch_system_drive", True))

        self._exclude_paths = {p.lower() for p in
                               (self.cfg.get("rt_exclude_paths") or []) if p}
        self._exclude_exts = {e.lower() if e.startswith(".") else f".{e.lower()}"
                              for e in (self.cfg.get("rt_exclude_exts") or []) if e}

        # state
        self._enabled = False
        self._started = False
        self._paused = False
        self._sessions: Dict[str, Any] = {}
        self._pending: Dict[str, float] = {}       # path -> monotonic ts
        self._attempts: Dict[str, int] = {}         # path -> retry count
        self._pool: Optional[ThreadPoolExecutor] = None
        self._meter: Optional[_CPUMeter] = None
        self._scheduler_stop = threading.Event()
        self._scheduler_thread: Optional[threading.Thread] = None
        self._roots_lock = threading.Lock()
        self._pending_lock = threading.Lock()

        # pre-computed exclude prefixes (data dirs)
        self._data_prefixes = tuple(
            str(d).lower().rstrip("\\") + "\\" for d in (
                getattr(ctx.cfg, "data_dir", None),
                getattr(ctx.cfg, "backup_dir", None),
                getattr(ctx.cfg, "quarantine_dir", None),
            ) if d is not None)

    # ------------------------------------------------------------------------ engine
    def _get_engine(self) -> Any:
        if self._engine is None:
            self._engine = self.ctx.ensure_engine()
        return self._engine

    # ------------------------------------------------------------------------ public API
    def start(self) -> None:
        if self._started:
            return
        if not provider.rt_watch_available():
            self.on_state({"key": "error", "active": False,
                           "error": "no low-latency file-watch backend "
                                    f"({provider.system()} backend not "
                                    "installed; watching is polling-only)"})
            return
        self._enabled = True
        self._started = True
        self._pool = ThreadPoolExecutor(max_workers=self.max_concurrent)
        self._meter = _CPUMeter(self.cpu_threshold, self.cpu_sample_s)
        self._meter.start()
        self._scheduler_stop.clear()
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop, daemon=True, name="RT-Scheduler")
        self._scheduler_thread.start()
        self._sync_roots()
        self.on_state({"key": "enabled", "active": True,
                        "roots": list(self._sessions.keys())})
        self.on_event("Real-time protection ON", "event")
        logger.info("realtime monitor started")

    def stop(self) -> None:
        if not self._started:
            return
        self._enabled = False
        self._scheduler_stop.set()
        if self._scheduler_thread is not None:
            self._scheduler_thread.join(timeout=2)
        with self._roots_lock:
            for s in list(self._sessions.values()):
                s.stop()
            self._sessions.clear()
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)
            self._pool = None
        if self._meter is not None:
            self._meter.stop()
            self._meter = None
        self._started = False
        with self._pending_lock:
            self._pending.clear()
            self._attempts.clear()
        self.on_state({"key": "enabled", "active": False})
        self.on_event("Real-time protection OFF", "event")
        logger.info("realtime monitor stopped")

    def set_enabled(self, enable: bool) -> None:
        if enable:
            self.start()
        else:
            self.stop()

    def is_enabled(self) -> bool:
        return self._enabled

    def status(self) -> dict:
        with self._roots_lock:
            roots = [s.root for s in self._sessions.values() if s.is_alive()]
        return {
            "enabled": self._enabled,
            "started": self._started,
            "paused": self._paused,
            "roots_watched": roots,
            "cpu_percent": self._meter.percent if self._meter else 0.0,
            "pending": len(self._pending) if self._started else 0,
        }

    def is_any_root_watched(self) -> bool:
        with self._roots_lock:
            return any(s.is_alive() for s in self._sessions.values())

    # ------------------------------------------------------------------------ root management
    @staticmethod
    def _norm_root(root: str) -> str:
        r = str(root).rstrip("\\").rstrip("/")
        if len(r) < 2 or r[1] != ":":
            return ""
        return r + os.sep

    def add_root(self, root: str) -> None:
        norm = self._norm_root(root)
        if not norm:
            return
        key = norm.lower()
        with self._roots_lock:
            if key in self._sessions:
                return
            if not self._started:
                return
            session = provider.create_watch_session(self, norm)
            self._sessions[key] = session
            session.start()
        self.on_event(f"Watching {norm}", "info")
        self.on_state({"key": "root", "active": True, "root": norm})

    def remove_root(self, root: str) -> None:
        key = self._norm_root(root).lower()
        if not key:
            return
        with self._roots_lock:
            session = self._sessions.pop(key, None)
        if session is not None:
            session.stop()
            self.on_event(f"Stopped watching {session.root}", "info")
            self.on_state({"key": "root", "active": False,
                           "root": session.root})

    def sync_roots(self) -> None:
        """Reconcile watched roots with currently mounted drives (called on poll)."""
        if not self._started:
            return
        self._sync_roots()

    def _sync_roots(self) -> None:
        from .systemutils import (external_drive_paths, logical_drive_strings,
                                  system_drive_letter)
        if self.watch_system_drive:
            wanted = logical_drive_strings()
        else:
            boot = system_drive_letter()
            wanted = external_drive_paths()
        current = set()
        with self._roots_lock:
            current = {s.root.lower() for s in self._sessions.values()}
        for root in wanted:
            norm = self._norm_root(root)
            if norm and norm.lower() not in current:
                self.add_root(norm)
        gone = set()
        with self._roots_lock:
            for key, session in list(self._sessions.items()):
                if not os.path.isdir(session.root):
                    gone.add(session)
        for s in gone:
            self.remove_root(s.root)

    # ------------------------------------------------------------------------ session callbacks (from watch threads)
    def _session_ready(self, session: Any) -> None:
        logger.debug("RT session ready: %s", session.root)

    def _session_failed(self, session: Any, error: str) -> None:
        logger.error("RT session failed %s: %s", session.root, error)
        self.on_state({"key": "root_failed", "active": False,
                       "root": session.root, "error": error})

    def _session_ended(self, session: Any) -> None:
        logger.debug("RT session ended: %s", session.root)

    def _on_watch_event(self, action: int, rel: str, root: str) -> None:
        if action in _ACTION_NEW:
            try:
                path = os.path.join(root, rel)
                self._queue_file(path)
            except Exception:
                crashguard.report_exception(
                    "rt-queue", sys.exc_info()[1], sys.exc_info()[2])

    # ------------------------------------------------------------------------ path filtering
    def _accept_path(self, path: Path) -> bool:
        if not path.is_absolute():
            return False
        low = str(path).lower()
        name = path.name.lower()
        if name in _SKIP_FILENAMES:
            return False
        if path.suffix.lower() in self._exclude_exts:
            return False
        for prefix in self._data_prefixes:
            if low.startswith(prefix):
                return False
        for ep in self._exclude_paths:
            if low.startswith(ep) or ep in low:
                return False
        for part in path.parts[1:]:
            if part.lower() in _EXCLUDE_DIRS:
                return False
        return True

    # ------------------------------------------------------------------------ debounce + scheduling
    def _queue_file(self, path: str) -> None:
        if not self._enabled:
            return
        p = Path(path)
        if p.is_dir():
            return
        if not self._accept_path(p):
            return
        key = str(p)
        with self._pending_lock:
            self._pending[key] = time.monotonic()
            if len(self._pending) > self.queue_cap:
                drop_n = len(self._pending) - self.queue_cap
                oldest = sorted(self._pending.items(), key=lambda kv: kv[1])[:drop_n]
                for k, _ in oldest:
                    self._pending.pop(k, None)

    def _scheduler_loop(self) -> None:
        quiet_s = max(0.1, self.debounce_ms / 1000.0)
        while not self._scheduler_stop.is_set():
            try:
                self._scheduler_tick(quiet_s)
            except Exception:
                crashguard.report_exception(
                    "rt-scheduler", sys.exc_info()[1], sys.exc_info()[2])
            self._scheduler_stop.wait(0.1)

    def _scheduler_tick(self, quiet_s: float) -> None:
        self._check_cpu_throttle()
        if not self._enabled or self._paused:
            return
        now = time.monotonic()
        due: List[str] = []
        with self._pending_lock:
            for k, ts in list(self._pending.items()):
                if now - ts >= quiet_s:
                    due.append(k)
            for k in due:
                self._pending.pop(k, None)
                self._attempts.pop(k, None)
        for k in due:
            self._submit_scan(k)

    def _submit_scan(self, path: str) -> None:
        if self._pool is None or self._paused:
            return
        try:
            self._pool.submit(self._safe_scan_and_act, path)
        except Exception:
            crashguard.report_exception(
                "rt-submit", sys.exc_info()[1], sys.exc_info()[2])

    # ------------------------------------------------------------------------ per-file scan + action
    def _safe_scan_and_act(self, path: str) -> None:
        crashguard.safe_run("rt-scan", lambda: self._scan_and_act(path))

    def _scan_and_act(self, path: str) -> None:
        from .scanner import Scanner, ScanOptions

        p = Path(path)
        st = stat_safe(p)
        if st is None or st.st_size <= 0:
            return
        opts = ScanOptions().with_overrides(
            max_hash_size=int(self.cfg.get("max_hash_size", 512 * 1024 * 1024)),
            max_depth=0,
            check_heuristics=True,
        )
        scanner = Scanner(self.db, opts)
        try:
            report = scanner.scan([p])
        except Exception:
            crashguard.report_exception(
                "rt-scan-scan", sys.exc_info()[1], sys.exc_info()[2])
            return
        if not report.findings:
            return
        scanner.persist()
        self._handle_findings(p, report.sorted_findings())

    def _handle_findings(self, path: Path, findings: list) -> None:
        for finding in findings:
            if finding.name == "HiddenRootFolder":
                self.on_detection({
                    "path": str(path), "name": finding.name,
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "action": "reported",
                })
                continue
            self._act_on_finding(path, finding)
            return  # handle the highest-confidence finding only

    def _act_on_finding(self, path: Path, finding: Any) -> None:
        engine = self._get_engine()
        action = self.action
        threat = finding.name
        result: Optional[dict] = None
        try:
            if action == "report":
                result = {"action": "reported"}
            elif action == "disinfect":
                result = engine.disinfect_file(path, dry_run=False)
                status = result.get("status", "")
                if status == "error" and finding.confidence >= 0.9:
                    result = engine.quarantine_file(path, threat=threat)
            else:
                result = engine.quarantine_file(path, threat=threat)
        except Exception:
            crashguard.report_exception(
                "rt-action", sys.exc_info()[1], sys.exc_info()[2])
            self._schedule_retry(path)
            return

        status = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
        if status == "error":
            self._schedule_retry(path)
        payload = {
            "path": str(path),
            "name": threat,
            "category": getattr(finding, "category", "unknown"),
            "confidence": getattr(finding, "confidence", 0.0),
            "action": status,
            "uid": result.get("uid") if isinstance(result, dict) else None,
            "reason": result.get("reason") if isinstance(result, dict) else None,
        }
        self.db.audit("realtime_detection",
                      f"action={status} threat={threat} path={path}")
        self.on_detection(payload)

    def _schedule_retry(self, path: str) -> None:
        key = str(path)
        attempt = self._attempts.get(key, 0) + 1
        self._attempts[key] = attempt
        if attempt >= 5:
            logger.error("rt-retry: giving up on %s after %d attempts", path, attempt)
            self._attempts.pop(key, None)
            return
        delay = min(2.0 * attempt, 30.0)
        with self._pending_lock:
            self._pending[key] = time.monotonic() + delay

    # ------------------------------------------------------------------------ throttle (test seam)
    def _set_paused(self, value: bool) -> None:
        if value == self._paused:
            return
        self._paused = value
        key = "throttled"
        self.on_state({"key": key, "active": value})
        if value:
            logger.info("RT throttle engaged (process CPU >= %s%%)", self.cpu_threshold)
        else:
            logger.info("RT throttle released")

    def _check_cpu_throttle(self) -> None:
        """Called periodically by meter thread (via on_state if needed)"""
        if self._meter is None:
            return
        cpu = self._meter.percent
        if self._paused and cpu < self.cpu_threshold * 0.85:
            self._set_paused(False)
        elif not self._paused and cpu >= self.cpu_threshold:
            self._set_paused(True)

    def _on_rt_event(self, text: str, kind: str = "event") -> None:
        try:
            self.on_event(text, kind)
        except Exception:
            pass
