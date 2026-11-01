"""notifications.py - In-app notification history persisted in secudrive.db.

Every toast / background event is always logged here so the user can catch up
even if they missed the tray popup.  The NotificationStore enforces a cap
(~200 entries) by pruning the oldest rows after each push.

Backend: the existing ``Database`` object (thread-safe, single-writer WAL).
No duplicate SQLite connections.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .database import DatabaseClosedError
from .logging_utils import get_logger

logger = get_logger("notifications")

#: Maximum number of notifications kept after pruning.
CAP = 200

# ---- well-known kind constants (used by payload routing in the GUI) --------
KIND_SCAN = "scan"
KIND_QUARANTINE = "quarantine"
KIND_SIGNATURE = "signature"
KIND_CLEAN = "clean"
KIND_RT = "rt"
KIND_USB = "usb"
KIND_INFO = "info"
KIND_FEEDBACK = "feedback"


class NotificationStore:
    """Thin wrapper around Database for push/list/unread/prune with a cap."""

    def __init__(self, db) -> None:
        self.db = db

    # ---- write
    def push(self, kind: str, title: str, body: str = "",
             payload: Optional[Dict[str, Any]] = None) -> int:
        """Persist one notification and return its id.

        Shutdown-safe: during a scan-cancel / app-quit unwind a queued write
        can arrive after the Database owner has already drained and closed the
        connection.  ``DatabaseClosedError`` is the typed, lifecycle-aware
        signal for exactly that state - we log at debug and skip the persist
        cleanly instead of crashing with sqlite3's "Cannot operate on a closed
        database".  Any OTHER exception propagates (never swallowed).
        """
        try:
            nid = self.db.add_notification(kind, title, body, payload or {})
            self.db.prune_notifications(CAP)
            return nid
        except DatabaseClosedError:
            logger.debug("notification skipped: database shutting down (%s)", title)
            return 0

    # ---- read
    def list(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.db.recent_notifications(limit)

    def get(self, nid: int) -> Optional[Dict[str, Any]]:
        """Fetch a single notification (for detail routing after clicking)."""
        return self.db.notification_by_id(nid)

    def unread_count(self) -> int:
        return self.db.unread_notification_count()

    # ---- mutation
    def mark_read(self, nid: int) -> None:
        self.db.mark_notification_read(nid)

    def mark_all_read(self) -> None:
        self.db.mark_all_notifications_read()

    def remove(self, nid: int) -> None:
        """Dismiss ONE notification permanently."""
        self.db.delete_notification(nid)

    def clear_all(self) -> None:
        """Dismiss every notification permanently."""
        self.db.clear_notifications()
