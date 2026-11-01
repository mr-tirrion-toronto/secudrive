"""watcher.py - real-time background service for external media.

Two detection backends, transparently selected:

  1. ``pywin32`` device notification (message-window pump, see the Windows
     platform provider) - sub-second latency, wakes the service the moment
     hardware arrives.
  2. Removable-volume polling (the immunizer ``DriveWatcher`` approach) -
     portable fallback for Linux/macOS and slim builds without pywin32.

The service is GUI/event-loop agnostic: it only calls ``on_attach(drive)``
from its worker thread.  The GUI bridges these callbacks into Qt signals.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Callable, List, Optional

from .immunizer import list_external_drives
from .crashguard import report_exception
from .logging_utils import get_logger
from .platform import get_provider

logger = get_logger("watcher")

provider = get_provider()


class BackgroundWatcher:
    """Detect attached removable drives; invoke ``on_attach`` per new letter.

    Optional auto-immunize: pass ``on_clean`` and the service will invoke it
    (typically enqueuing a background deep-clean via whatever executor the
    embedding app provides).
    """

    def __init__(self, interval: float = 1.5,
                 on_attach: Optional[Callable[[str], None]] = None,
                 on_remove: Optional[Callable[[str], None]] = None) -> None:
        self.interval = max(0.2, interval)
        self.on_attach = on_attach or (lambda _d: None)
        self.on_remove = on_remove
        self._known: set = set()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        if provider.usb_listener_available():
            self._listener = provider.create_usb_listener(
                callback=self._hardware_wake, stop_event=self._stop)
            self.backend = provider.usb_backend_name()
        else:
            self._listener = None
            self.backend = "polling-removable-volumes"

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> "BackgroundWatcher":
        self._known = set(self._list_volumes())
        if self._listener is not None:
            self._listener.start()
            # Give the message pump a moment to register before polling starts.
            time.sleep(0.15)
            logger.info("watcher backend: %s (registered=%s)",
                        self.backend, self._listener.is_available())
        self._thread = threading.Thread(target=self._loop, name="DriveWatcherLoop",
                                        daemon=True)
        self._thread.start()
        logger.info("background watcher started (%s)", self.backend)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.join(timeout=2.0)
        if self._thread is not None:
            self._thread.join(timeout=max(2, self.interval + 1))
        logger.info("background watcher stopped")

    def is_running(self) -> bool:
        """True while the watcher thread (or listener pump) is alive."""
        if self._listener is not None and self._listener.is_alive():
            return True
        return self._thread is not None and self._thread.is_alive()

    def wait_forever(self) -> None:
        """Block until Ctrl+C (CLI mode)."""
        try:
            while not self._stop.is_set():
                time.sleep(1.0)
        except KeyboardInterrupt:
            self.stop()

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _list_volumes() -> List[str]:
        return [provider.volume_root(letter)
                for letter in list_external_drives()]

    def _hardware_wake(self) -> None:
        """Hardware event hit: re-list volumes immediately (fast path).
        Any re-list/diff failure must never kill the service thread."""
        try:
            now = set(self._list_volumes())
            self._diff(now)
        except Exception:
            report_exception("watcher.wake", sys.exc_info()[1],
                             sys.exc_info()[2])

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                now = set(self._list_volumes())
                self._diff(now)
            except Exception:
                report_exception("watcher.loop", sys.exc_info()[1],
                                 sys.exc_info()[2])
            self._stop.wait(self.interval)

    def _diff(self, now: set) -> None:
        attached = now - self._known
        for drive in sorted(attached):
            logger.info("external media attached: %s", drive)
            try:
                self.on_attach(drive)
            except Exception as exc:  # callbacks must never kill the service
                logger.error("on_attach failed for %s: %s", drive, exc)
        detached = self._known - now
        for drive in sorted(detached):
            logger.info("external media removed: %s", drive)
            if self.on_remove:
                try:
                    self.on_remove(drive)
                except Exception as exc:
                    logger.error("on_remove failed for %s: %s", drive, exc)
        self._known = now


class AutoCleanCoordinator:
    """Helper that pairs a watcher with a background cleaner (GUI/CLI reuse).

    Fast path: hardware event -> re-list -> clean newly attached removable drives
    through ``clean_fn(drive_path)`` executed on a worker thread pool.
    """

    def __init__(self, watcher: BackgroundWatcher,
                 clean_fn: Callable[[str], None]) -> None:
        self.watcher = watcher
        self.clean_fn = clean_fn
        self._handling: set = set()

    def start(self) -> None:
        self.watcher.on_attach = self._handle_attach
        self.watcher.start()

    def stop(self) -> None:
        self.watcher.stop()

    def _handle_attach(self, drive: str) -> None:
        if drive in self._handling:
            return
        self._handling.add(drive)
        worker = threading.Thread(
            target=lambda: self._run_clean(drive), name=f"auto-clean-{drive[0]}",
            daemon=True)
        worker.start()

    def _run_clean(self, drive: str) -> None:
        try:
            self.clean_fn(drive)
        finally:
            self._handling.discard(drive)