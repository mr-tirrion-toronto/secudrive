"""crashguard.py - last-resort exception safety net for the SecuDrive GUI.

Two cooperating layers keep a background failure from ever taking the whole
QApplication (or the entire process) down silently:

1.  ``safe_run`` / worker ``finally`` blocks - every QThread worker wraps its
    ``run()`` body and routes full tracebacks through ``report_exception``.

2.  Global handlers - ``install_global_handlers()`` installs ``sys.excepthook``
    (main thread) and ``threading.excepthook`` (any Python thread) so any
    *unhandled* exception is at least logged with its full traceback to
    secudrive_debug.log and surfaced as a non-fatal dialog instead of the
    classic "wall of stderr then silent death".

The GUI connects ``CrashBridge.error`` to a slot that shows a debounced,
non-fatal error dialog; the dialog never blocks the event loop for more than a
moment and can be clicked away - the app keeps running.
"""
from __future__ import annotations

import sys
import threading
import traceback
from typing import Optional

from .logging_utils import get_logger

logger = get_logger("crashguard")

_installed = False


class CrashBridge:
    """Signal holder - a plain QObject-free emitter so this module stays
    importable from the CLI (no QApplication needed).

    The GUI calls ``CrashBridge.instance().error.connect(...)`` once.
    Emission is thread-safe: ``pyqtSignal`` queues delivery onto the thread that
    owns the receiving slot (the GUI thread).
    """

    def __init__(self) -> None:
        try:
            from PyQt6.QtCore import QObject, pyqtSignal

            class _Holder(QObject):
                error = pyqtSignal(str)

            self._holder = _Holder()
            self.error = self._holder.error
        except Exception:  # no Qt (CLI / import-time): no-op emitter
            self.error = _NullSignal()
            self._holder = None


class _NullSignal:
    """Passive stand-in when PyQt6 is unavailable (CLI / unit tests)."""

    def connect(self, *_a, **_k):  # noqa: ANN001
        return None

    def emit(self, *_a, **_k):  # noqa: ANN001
        return None

    def disconnect(self, *_a, **_k):  # noqa: ANN001
        return None


_instance: Optional[CrashBridge] = None


def bridge() -> CrashBridge:
    global _instance
    if _instance is None:
        _instance = CrashBridge()
    return _instance


# --------------------------------------------------------------------------- api


def report_exception(source: str, exc: BaseException,
                     tb=None) -> str:
    """Route one background-thread exception to the debug log + GUI bridge.

    Returns a short human-readable blurb (used by workers as their error
    payload so the UI shows something useful rather than "Exception").
    """
    text = f"{type(exc).__name__}: {exc}"
    logger.error("thread '%s' crashed: %s", source, text)
    if tb is not None:
        logger.error("full traceback:\n%s",
                     "".join(traceback.format_exception(type(exc), exc, tb)))
    else:
        logger.error("full traceback:\n%s", traceback.format_exc())
    bridge().error.emit(f"[{source}] {text}")
    return text


def safe_run(source: str, fn, error_hook=None):
    """Run ``fn``; on any exception log + bridge it and call ``error_hook``.

    ``fn`` must be a callable for a worker thread body.  Used as:

        def run(self):
            crashguard.safe_run(self.worker_name(),
                                self._run_body,
                                error_hook=lambda msg: self.finished_sig.emit({"error": msg}))
    """
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - last-resort safety net
        if isinstance(exc, KeyboardInterrupt):
            raise
        msg = report_exception(source, exc)
        if error_hook is not None:
            try:
                error_hook(msg)
            except Exception:  # noqa: BLE001 - the net itself must not throw
                logger.exception("error_hook itself crashed")
        return False
    return True


# ----------------------------------------------------------------- global hooks


def install_global_handlers() -> None:
    """Install the process-wide excepthooks (idempotent).

    Called at the very top of ``launch_gui`` (and CLI entry) so *any* future
    unhandled exception - main thread or any worker thread - is logged with a
    full traceback and surfaced instead of silently vanishing.
    """
    global _installed
    if _installed:
        return
    _installed = True

    def _main_hook(exc_type, exc, tb):
        if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            sys.__excepthook__(exc_type, exc, tb)
            return
        logger.critical("UNCAUGHT main-thread exception (SecuDrive stays up): "
                        "%s", exc)
        logger.critical("traceback:\n%s",
                        "".join(traceback.format_exception(exc_type, exc, tb)))
        bridge().error.emit(f"{exc_type.__name__}: {exc}")

    def _thread_hook(args):
        exc_type, exc = args.exc_type, args.exc_value
        if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            return
        logger.critical("UNCAUGHT exception in thread '%s': %s",
                        getattr(args, "thread", None) and getattr(args.thread,
                                                                  "name", "?"),
                        exc)
        logger.critical("traceback:\n%s",
                        "".join(traceback.format_exception(
                            exc_type, exc, args.exc_traceback)))
        bridge().error.emit(f"[thread] {exc_type.__name__}: {exc}")

    sys.excepthook = _main_hook
    threading.excepthook = _thread_hook
    logger.debug("crashguard installed (sys.excepthook + threading.excepthook)")