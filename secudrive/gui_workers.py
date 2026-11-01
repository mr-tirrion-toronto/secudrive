"""gui_workers.py - QThread wrappers for scanner + engine operations.

Kept separate from gui.py so the page widgets stay readable and the worker
classes can be reused by the autopilot plumbing and tests without importing
the whole window.

Every worker runs its body through ``crashguard.safe_run``: a crash inside a
background thread can never kill the process - the full traceback goes to
secudrive_debug.log and a debounced non-fatal dialog is shown in the GUI via
the ``CrashBridge`` global signal.
"""
from __future__ import annotations

import threading
import time

from PyQt6.QtCore import QThread, pyqtSignal

from . import crashguard
from .logging_utils import get_logger

_RLOG = get_logger("restore")

CLIP = 4096  # cap for error strings surfaced to the UI


def _clamp(text: str, limit: int = CLIP) -> str:
    text = str(text)
    return text if len(text) <= limit else text[:limit] + " [...]"


class ScanWorker(QThread):
    """Runs scanner.scan() off the UI thread, streaming progress signals.

    Completion contract (all emitted from the worker thread, delivered queued
    on the GUI thread):

    * ``scan_started``            - scan() is about to iterate.
    * ``scan_finished`` (dict)    - full result payload (or error payload).
    * ``scan_stopped`` (dict)     - user cancellation mid-scan.
    * ``finished_sig``  (dict)    - legacy alias emitted for *every* completion
                                    (success / cancelled / error) so existing
                                    callers keep working unchanged.
    """

    scan_started = pyqtSignal()
    scan_finished = pyqtSignal(dict)
    scan_stopped = pyqtSignal(dict)
    finished_sig = pyqtSignal(dict)
    progress_sig = pyqtSignal(dict)

    def __init__(self, db, options, targets, parent=None) -> None:
        super().__init__(parent)
        self.db, self.options, self.targets = db, options, targets
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()
        self.requestInterruption()

    def worker_name(self) -> str:
        return "scan-worker"

    def run(self) -> None:
        def _body() -> None:
            from .scanner import ScanCancelled, Scanner

            self.scan_started.emit()
            scanner = Scanner(self.db, self.options,
                              progress=self.progress_sig.emit,
                              cancel_event=self.cancel_event)
            try:
                report = scanner.scan(self.targets)
            except ScanCancelled:
                self.scan_stopped.emit({"cancelled": True, "findings": 0})
                self.finished_sig.emit({"cancelled": True, "findings": 0})
                return
            persisted = scanner.persist()
            payload = {
                "scan_id": report.scan_id,
                "findings": len(report.findings),
                "files": report.files_seen, "dirs": report.dirs_seen,
                "bytes": report.bytes_scanned, "errors": report.errors,
                "duration_s": max(0.0, report.finished - report.started),
                "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(report.started))
                        if report.started else None,
                "persisted": persisted,
                "finding_rows": [
                    {"path": str(f.path), "category": f.category, "name": f.name,
                     "confidence": f.confidence, "evidence": f.evidence}
                    for f in report.sorted_findings()
                ],
            }
            self.scan_finished.emit(payload)
            self.finished_sig.emit(payload)

        def _error(msg: str) -> None:
            payload = {"error": _clamp(msg), "findings": 0}
            self.scan_finished.emit(payload)
            self.finished_sig.emit(payload)

        crashguard.safe_run(self.worker_name(), _body, error_hook=_error)


class ActionWorker(QThread):
    """Generic engine-operation worker (reveal / clean / immunize / restore /
    purge / signature sync / import - anything callable returning a dict)."""

    progress_sig = pyqtSignal(str)
    finished_sig = pyqtSignal(dict)

    def __init__(self, fn, progress_label: str = "", parent=None) -> None:
        super().__init__(parent)
        self.fn = fn
        self.progress_label = progress_label

    def worker_name(self) -> str:
        return "action-worker"

    def run(self) -> None:
        def _body() -> None:
            if self.progress_label:
                self.progress_sig.emit(self.progress_label)
            result = self.fn()
            self.finished_sig.emit(result if isinstance(result, dict)
                                   else {"result": str(result)})

        def _error(msg: str) -> None:
            self.finished_sig.emit({"error": _clamp(msg)})

        crashguard.safe_run(self.worker_name(), _body, error_hook=_error)


class ItemActionWorker(QThread):
    """Run a batch of independent actions CONCURRENTLY, reporting per-item
    status so the UI can show live, independent spinners (no single global
    progress bar).  Used for multi-select Restore / Disinfect / Delete.

    Each task is a plain callable returning a dict.  ``item_status`` is emitted
    per key with ``running`` / ``done`` / ``error``; ``finished_sig`` carries
    the ordered results list once every task completed.
    """

    item_status = pyqtSignal(str, dict)   # (key, {"state": "running"|"done"|"error", "detail": ...})
    finished_sig = pyqtSignal(list)

    def __init__(self, tasks, max_workers: int = 4, parent=None) -> None:
        super().__init__(parent)
        self.tasks = list(tasks)                  # list of (key, callable)
        self.max_workers = max(1, min(max_workers or 4, 8))
        self._jobs: list = []

    def worker_name(self) -> str:
        return "item-action-worker"

    def run(self) -> None:
        import concurrent.futures as cf

        def _one(key, fn) -> dict:
            _RLOG.info("RESTORE|worker| start item %s", key)
            try:
                result = self._call(key, fn)
                _RLOG.info("RESTORE|worker| item %s returned: %s", key,
                           (result.get("status") if isinstance(result, dict)
                            else f"?{type(result).__name__}"))
                self.item_status.emit(key, {"state": "done", "detail": result})
                return {"key": key, "result": result}
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                msg = _clamp(str(exc))
                _RLOG.info("RESTORE|worker| item %s crashed: %r", key, msg)
                self.item_status.emit(key, {"state": "error", "detail": msg})
                return {"key": key, "error": msg}

        def _body() -> None:
            _RLOG.info("RESTORE|worker| run() -> ThreadPool %d task(s)",
                       len(self.tasks))
            with cf.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = [pool.submit(_one, key, fn) for key, fn in self.tasks]
                results = [f.result() for f in futures]
            _RLOG.info("RESTORE|worker| emitting finished_sig (%d results)",
                       len(results))
            self.finished_sig.emit(results)

        def _error(msg: str) -> None:
            _RLOG.info("RESTORE|worker| CRASHED via safe_run: %r", msg)
            self.finished_sig.emit([{"error": _clamp(msg)}])

        crashguard.safe_run(self.worker_name(), _body, error_hook=_error)

    def _call(self, key, fn) -> dict:
        """Emit 'running' just before executing so listeners paint the spinner."""
        _RLOG.info("RESTORE|worker| item_status running for %s", key)
        self.item_status.emit(key, {"state": "running", "detail": ""})
        result = fn()
        return result if isinstance(result, dict) else {"result": result}