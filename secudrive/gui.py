"""gui.py - SecuDrive desktop GUI (PyQt6, Windows 11 style, dark mode).

Integrates config.py / scanner.py / recovery.py behind the same runtime seams
the CLI uses.  Layout:

    Dashboard        - system status (Protected/At Risk, admin badge, sig count),
                       Quick Scan / Full Scan, USB auto-clean, Update Signatures,
                       local signature import (CSV/JSON, drag-and-drop too),
                       automatic service policy + "start with Windows",
                       periodic online refresh (default 6 h),
                       LIVE ACTIVITY FEED (bug #5) - real-time signal-driven
                       status line + rolling event list
    Scanner          - live progress (current path, files found, clean speed),
                       findings table, start / stop (button state via Qt signals
                       scan_started/scan_finished/scan_stopped, bug #4),
                       plain-language report + expandable technical details
                       (bug #6) and an actionable post-scan dialog (bug #7)
    Quarantine       - table with Restore Clean File / Permanent Delete,
                       "Last synced" timestamp (bug #8)
    Drive Doctor     - external-drive list (Fixed SSDs/HDDs AND removable flash,
                       system volume excluded), typed labels, one-click clean /
                       reveal / immunize / scan with an unmistakable DRY-RUN banner
    Logs             - disinfect & scan audit viewer + GUI-action debug panel

DRIVE-TARGET CONTRACT  ("fix bug #1 at the root"): no action button ever reads a
cached/default path.  Every click re-reads ``currentData()`` / ``currentText()``
of the combo *at click time*, validates it against ``GetLogicalDriveStrings`` /
``os.path.isdir``, shows a clear on-screen error when invalid, and never falls
back to a home directory.

DRY-RUN CONTRACT  ("fix bug #2 at the root"): ``dry_run`` is (re)read from the
checkbox at every execution - no default ``True`` is ever baked in - and a
persistent red ``DRY RUN MODE ON`` banner is shown whenever it is true.

CRASH CONTRACT  (bug #1): every QThread worker routes exceptions through
``crashguard`` - the full traceback lands in secudrive_debug.log and a
debounced, non-fatal dialog is shown.  ``install_global_handlers()`` covers any
unhandled main-thread or worker-thread exception so the app can never silently
disappear from the tray.  Hot-plug races (drive enumerated while still mounting
or removed mid-scan) are absorbed by the scanner/engine OSError handling and the
crashguard net.

Workers run on QThreads and talk to the UI via signals; the Database object is
thread-safe (RLock + WAL) so the shared engine is usable from any worker.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, QPoint, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon, QPalette
from PyQt6.QtWidgets import (
    QApplication, QAbstractItemView, QCheckBox, QComboBox, QDialog, QFileDialog,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMenu, QMessageBox, QProgressBar, QPushButton,
    QStackedWidget, QSystemTrayIcon, QTableWidget, QTableWidgetItem, QTextEdit,
    QSpinBox, QVBoxLayout, QWidget,
)

from . import crashguard
from .autopilot import DISINFECT, QUARANTINE, SKIP, AutoPilotWorker
from .config import Config
from .database import Database
from .gui_workers import ActionWorker, ItemActionWorker, ScanWorker
from .logging_utils import get_logger
from .notifications import (KIND_CLEAN, KIND_INFO, KIND_QUARANTINE, KIND_RT,
                            KIND_SCAN, KIND_SIGNATURE, NotificationStore)
from .platform import get_provider
from .report_formatter import build_report, finding_to_plain, headline

logger = get_logger("gui")

provider = get_provider()

ACCENT = QColor("#4C8BF5")
BG = QColor("#1B1B1F")
PANEL = QColor("#252529")
TEXT = QColor("#E8E8EA")
MUTED = QColor("#9A9AA0")

APP_TITLE = "SecuDrive - Security & Data Recovery"

_LAST_ERROR_POPUP_TIME = 0.0
_ERROR_POPUP_DEBOUNCE_S = 10.0


def _clamp_text(text: object, limit: int = 96) -> str:
    """Shorten long strings for cell/tooltip widgets (keeps EVIL text in SDL)."""
    s = str(text or "")
    return s if len(s) <= limit else s[: limit - 1] + "\u2026"


def _strip_ics(text: object) -> str:
    """Collapse newlines so a one-line menu label stays on one line."""
    return " ".join((str(text or "")).split())


def make_logo() -> QIcon:
    """Small programmatic shield logo (no external asset needed for 0-asset builds)."""
    from PyQt6.QtGui import QPainter, QPen, QPixmap, QPolygonF
    from PyQt6.QtCore import QPointF

    pix = QPixmap(64, 64)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(ACCENT, 4))
    painter.setBrush(QColor("#20242C"))
    painter.drawRoundedRect(6, 6, 52, 52, 14, 14)          # shield body
    painter.setPen(QPen(QColor("#2ECC71"), 5, Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    painter.drawPolyline(QPolygonF([QPointF(20, 33), QPointF(29, 42), QPointF(46, 22)]))
    painter.end()
    return QIcon(pix)


# --------------------------------------------------------------------------- theme
def apply_dark_theme(app: QApplication) -> None:
    """Fusion-styled dark palette; approximates Windows 11 modern contrast.

    Applied exactly once per process (guard in ``launch_gui``) - re-applying a
    stylesheet is additive and causes duplicated/nested widget styling.
    """
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, BG)
    palette.setColor(QPalette.ColorRole.WindowText, TEXT)
    palette.setColor(QPalette.ColorRole.Base, PANEL)
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#2C2C30"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, PANEL)
    palette.setColor(QPalette.ColorRole.ToolTipText, TEXT)
    palette.setColor(QPalette.ColorRole.Text, TEXT)
    palette.setColor(QPalette.ColorRole.Button, PANEL)
    palette.setColor(QPalette.ColorRole.ButtonText, TEXT)
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, ACCENT)
    palette.setColor(QPalette.ColorRole.Highlight, ACCENT)
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, MUTED)
    app.setPalette(palette)
    app.setStyleSheet("""
        QMainWindow, QDialog { background: #1B1B1F; }
        QListWidget { background: #202024; border: none; border-radius: 8px;
                      padding: 4px; outline: none; }
        QListWidget::item { padding: 8px 14px; border-radius: 6px; color: #E8E8EA; }
        QListWidget::item:selected { background: #2C4F8C; color: #FFFFFF; }
        QListWidget::item:hover:!selected { background: #2A2A2E; }
        QLabel { color: #E8E8EA; }
        QLabel[muted="true"] { color: #9A9AA0; }
        QLabel[warn="true"] { color: #F0A020; }
        QLabel[error="true"] { color: #F05050; }
        QLabel[banner="true"] { background: #8A1A1A; color: #FFFFFF;
                                font-weight: 700; padding: 6px 12px;
                                border-radius: 6px; }
        QPushButton { background: #2E2E34; color: #E8E8EA; border: 1px solid #3A3A40;
                      border-radius: 6px; padding: 7px 16px; }
        QPushButton:hover { background: #38383F; border-color: #4C8BF5; }
        QPushButton:pressed { background: #202024; }
        QPushButton:disabled { background: #232327; color: #6A6A70;
                               border-color: #2E2E34; }
        QPushButton[accent="true"] { background: #2C4F8C; border-color: #4C8BF5; }
        QPushButton[accent="true"]:hover { background: #3A5FA5; }
        QPushButton[primary="true"] { background: #4C8BF5; color: #FFFFFF;
                                      border-color: #4C8BF5; font-weight: 600; }
        QPushButton[primary="true"]:hover { background: #6BA0F7; }
        QPushButton[danger="true"] { background: #5A2A2A; border-color: #8A3A3A; }
        QProgressBar { background: #2A2A2E; border: none; border-radius: 6px;
                       text-align: center; color: #E8E8EA; height: 16px; }
        QProgressBar::chunk { background: #4C8BF5; border-radius: 6px; }
        QTableWidget, QTextEdit, QLineEdit { background: #202024; color: #E8E8EA;
                      border: 1px solid #33333A; border-radius: 6px; }
        QTableWidget::item:selected { background: #2C4F8C; }
        QHeaderView::section { background: #2A2A2E; color: #9A9AA0; border: none;
                      padding: 6px; }
        QComboBox { background: #2E2E34; color: #E8E8EA; border: 1px solid #3A3A40;
                    border-radius: 6px; padding: 4px 10px; }
        QCheckBox { color: #E8E8EA; spacing: 8px; }
        QFrame[card="true"] { background: #252529; border: 1px solid #33333A;
                    border-radius: 10px; }
        QScrollBar:vertical { background: transparent; width: 10px; }
        QScrollBar::handle:vertical { background: #3A3A40; border-radius: 5px; }
        QToolTip { background: #2A2A2E; color: #E8E8EA; border: 1px solid #3A3A40; }
        QListWidget#activityList::item { padding: 4px 6px; }
    """)


# --------------------------------------------------------------------- tiny widgets
class _RTBridge(QObject):
    """Marshals RealtimeMonitor background-thread callbacks onto the Qt
    event loop (cross-thread signal emission is auto-queued by Qt)."""
    event = pyqtSignal(str, str)
    detection = pyqtSignal(dict)
    state = pyqtSignal(dict)


def _card(parent: QWidget) -> QFrame:
    frame = QFrame(parent)
    frame.setProperty("card", True)
    return frame


def _human_bytes(num: int) -> str:
    """Compact human size, e.g. 12.4 MB; '-' for negatives/unset."""
    try:
        num = int(num or 0)
    except (TypeError, ValueError):
        return "-"
    if num < 0:
        return "-"
    if num < 1024:
        return f"{num}B"
    for unit in ("KB", "MB", "GB", "TB"):
        num /= 1024.0
        if num < 1024:
            return f"{num:.1f} {unit}"
    return f"{num:.1f} PB"


def _label(text: str = "", muted: bool = False, bold: bool = False,
           role: Optional[str] = None) -> QLabel:
    label = QLabel(text)
    if muted:
        label.setProperty("muted", True)
    if role:
        label.setProperty(role, True)
    if bold:
        font = label.font()
        font.setBold(True)
        label.setFont(font)
    return label


# --------------------------------------------------------------------- runtime ctx
class RuntimeContext:
    """Bundles Config + Database + RecoveryEngine + watcher for the GUI."""

    def __init__(self, base: Optional[Path] = None) -> None:
        self.cfg = Config(base_dir=base) if base else Config()
        self.cfg.ensure_dirs()
        self.db = Database(self.cfg.db_path)
        self.engine = None
        self.key = None

    def ensure_engine(self):
        if self.engine is None:
            from .crypto import load_or_create_key
            from .recovery import RecoveryEngine

            self.key = load_or_create_key(self.cfg.key_path)
            self.engine = RecoveryEngine(
                db=self.db, backup_dir=self.cfg.backup_dir,
                quarantine_dir=self.cfg.quarantine_dir, key=self.key,
                min_trailing_payload=int(self.cfg.get("min_trailing_payload", 32)),
                head_window=int(self.cfg.get("head_window", 64 * 1024)),
                tail_window=int(self.cfg.get("tail_window", 64 * 1024)),
            )
        return self.engine

    def make_updater(self):
        """Shared OnlineUpdater (multi-feed, cached) for auto + manual syncs."""
        from .updater import OnlineUpdater

        if getattr(self, "_updater", None) is None:
            self._updater = OnlineUpdater(
                self.db, self.cfg,
                timeout=int(self.cfg.get("sigfeed_timeout", 40)))
        return self._updater


# ------------------------------------------------------------------- main window
class _NotificationBell(QPushButton):
    """Bell icon + unread badge.  Click -> dropdown of recent notifications
    (reverse chron); clicking an entry marks it read and routes to its detail
    (findings viewer for scan events, Quarantine page for quarantine events,
    Dashboard otherwise).  Persisted via NotificationStore."""

    _PAGE_INDEX = {"Dashboard": 0, "Scanner": 1, "Quarantine": 2,
                   "Drive Doctor": 3, "Logs": 4}

    def __init__(self, win: "MainWindow") -> None:
        super().__init__("\U0001F514")
        self.win = win
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Notifications")
        self.setFlat(True)
        self.setStyleSheet(
            "QPushButton{font-size:18px; border:none; padding:0 6px;}"
            "QPushButton:hover{background:#24344D;}")

    def refresh(self) -> None:
        unread = 0
        try:
            unread = self.win.notifications.unread_count()
        except Exception:
            pass
        self.setText(f"\U0001F514 {unread}" if unread else "\U0001F514")
        self.setToolTip(f"Notifications - {unread} unread")

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._popover()
        else:
            super().mousePressEvent(event)

    def _popover(self) -> None:
        menu = QMenu(self)
        items = []
        try:
            items = self.win.notifications.list(limit=50)
        except Exception:
            items = []
        if not items:
            menu.addAction("No notifications yet").setEnabled(False)
        else:
            icon_map = {KIND_SCAN: "\U0001F50D", KIND_QUARANTINE: "\U0001F9F9",
                        KIND_CLEAN: "\u2728", KIND_SIGNATURE: "\u21BB",
                        KIND_RT: "\u26A0"}
            for n in items:
                unread = "\u2022 " if not n.get("read") else ""
                label = (f"{icon_map.get(n.get('kind'), '\u2139')} "
                         f"{unread}{n.get('title')}")
                if n.get("body"):
                    label += f" - {_strip_ics(n.get('body'))}"
                act = menu.addAction(label)
                act.triggered.connect(
                    lambda _=False, nid=n.get("id"): self._handle(nid))
                # per-item dismissal (never touches the linked quarantine row -
                # it just drops this notification row)
                rm = menu.addAction(f"\u2715 {label}")
                rm.triggered.connect(
                    lambda _=False, nid=n.get("id"): self._remove_one(nid))
        menu.addSeparator()
        clear = menu.addAction("Mark all as read")
        clear.triggered.connect(self._mark_all)
        menu.addSeparator()
        clear_all = menu.addAction("Clear all notifications")
        clear_all.triggered.connect(self._clear_all)
        menu.addSeparator()
        menu.addAction("Close")
        menu.exec(self.mapToGlobal(self.rect().bottomLeft()))
        self.refresh()

    def _remove_one(self, nid) -> None:
        """Dismiss one notification.  VIEW-ONLY: the linked quarantine row is
        re-read from secudrive.db (never 'reverted') and left untouched."""
        try:
            self.win.notifications.remove(nid)
        except Exception:
            crashguard.report_exception(
                "notif-remove", sys.exc_info()[1], sys.exc_info()[2])
        self._refresh_linked_state()

    def _clear_all(self) -> None:
        """Dismiss every notification.  VIEW-ONLY: no data is mutatated."""
        try:
            self.win.notifications.clear_all()
        except Exception:
            crashguard.report_exception(
                "notif-clear-all", sys.exc_info()[1], sys.exc_info()[2])
        self._refresh_linked_state()

    def _refresh_linked_state(self) -> None:
        # Re-read the LIVE database after any bell action so the Quarantine /
        # Dashboard views can never display a stale status (e.g. the row of a
        # disinfected item flipping back to 'Quarantined').
        self.refresh()
        try:
            self.win.quarantine.refresh()
        except Exception:
            crashguard.report_exception(
                "notif-refresh-linked", sys.exc_info()[1], sys.exc_info()[2])

    def _handle(self, nid) -> None:
        try:
            self.win.notifications.mark_read(nid)
        except Exception:
            crashguard.report_exception(
                "notif-mark-read", sys.exc_info()[1], sys.exc_info()[2])
        self._refresh_linked_state()
        try:
            n = self.win.notifications.get(nid)
        except Exception:
            n = None
        if not n:
            return
        # ``notification_by_id`` already JSON-decodes ``payload`` (see
        # database.notification_by_id) - never json.loads() it again or the
        # TypeError is swallowed and clicking a notification stops navigating.
        payload = n.get("payload") if isinstance(n.get("payload"), dict) else {}
        kind = n.get("kind")
        if kind in (KIND_SCAN, KIND_CLEAN) and payload.get("scan_id"):
            self.win.open_findings(scan_id=payload["scan_id"],
                                   title=f"Findings - {n.get('title')}")
            self.win.stack.setCurrentIndex(1)   # Scanner page
        elif kind == KIND_QUARANTINE:
            self.win.stack.setCurrentIndex(2)   # Quarantine page
            self.win.quarantine.refresh()
        elif kind == KIND_SIGNATURE:
            self.win.stack.setCurrentIndex(0)   # Dashboard
        else:
            self.win.stack.setCurrentIndex(0)

    def _mark_all(self) -> None:
        try:
            self.win.notifications.mark_all_read()
        except Exception:
            crashguard.report_exception(
                "notif-mark-all", sys.exc_info()[1], sys.exc_info()[2])
        self.refresh()


class FindingsResultsDialog(QDialog):
    """Deliverable #1: Findings Results viewer/panel.

    Reuses the Scanner tab's results-table component (FindingsTable) and adds
    an Actions column with per-item Clean / Quarantine / Ignore / Restore (the
    latter only when the file is already quarantined).  Works for manual + auto
    scans; opened from the activity feed line, the Dashboard 'Last scan' card,
    or a notification.  Per-item live state streams via ItemActionWorker.
    """

    def __init__(self, win: "MainWindow", scan_id: str | None = None,
                 rows: list | None = None,
                 title: str = "Findings Results") -> None:
        super().__init__(win)
        self.win = win
        self.setWindowTitle(title)
        self.setMinimumSize(960, 500)
        self._scan_id = scan_id
        self._findings: list = []
        self._workers: List[QThread] = []

        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        head.addWidget(_label(title, muted=True))
        head.addStretch(1)
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        head.addWidget(btn_close)
        lay.addLayout(head)

        if scan_id and not rows:
            try:
                rows = self.win.ctx.db.findings_for_scan(scan_id)
                rows = [
                    {"path": r.get("path", ""), "category": r.get("category", ""),
                     "name": r.get("threat_name", ""),
                     "confidence": float(r.get("confidence", 0) or 0),
                     "evidence": r.get("evidence", "")}
                    for r in rows]
            except Exception:
                crashguard.report_exception(
                    "findings-viewer-load", sys.exc_info()[1],
                    sys.exc_info()[2])
                rows = []
        self._findings = list(rows or [])

        self.table = FindingsTable(self)
        self.table.insertColumn(4)
        self.table.setHorizontalHeaderItem(4, QTableWidgetItem("Actions"))
        self.table.set_findings(self._findings)
        lay.addWidget(self.table, 1)

        count = len(self._findings)
        self.lbl_summary = _label(
            f"{count} finding(s)" + (f" (scan {scan_id})" if scan_id else ""),
            muted=True)
        lay.addWidget(self.lbl_summary)

        self._attach_action_buttons()

    def _attach_action_buttons(self) -> None:
        for row in range(len(self._findings)):
            btn = QPushButton("Act...")
            btn.setFixedWidth(92)
            btn.clicked.connect(lambda _=False, r=row: self._show_actions(r))
            self.table.setCellWidget(row, 4, btn)

    def _show_actions(self, row: int) -> None:
        finding = self._findings[row]
        path = finding.get("path", "")
        btn = self.table.cellWidget(row, 4)
        engine = self.win.ctx.ensure_engine()

        # Route every "Act..." decision through the shared resolve_plan
        # classifier so a directory / drive root / symlink / recovery artifact
        # is never handed to the file-based disinfect/quarantine pipeline (that
        # dead-ends as a false-success "Cleaned" on drive roots).  SKIP plans
        # present a clearly disabled button with the reason, not a dead menu.
        from .recovery import PLAN_REVEAL, PLAN_SKIP, resolve_plan
        plan = resolve_plan(Path(path), self.win.ctx.db, finding)
        if plan.get("plan") == PLAN_SKIP:
            btn.setText("Manual review")
            btn.setEnabled(False)
            reason = str(plan.get("reason", "manual review only"))
            btn.setToolTip(reason)
            self.win._notify(
                "Finding needs manual review",
                f"{_clamp_text(str(path), 80)} - {reason}",
                kind=KIND_INFO, payload={"path": path})
            return

        menu = QMenu(self)
        if plan.get("plan") == PLAN_REVEAL:
            menu.addAction("Reveal (clear attributes)")
        else:
            menu.addAction("Clean (disinfect)")
            menu.addAction("Quarantine")
        act_ignore = menu.addAction("Ignore (keep file)")
        act_restore = None
        uid = self._quarantined_uid(path)
        if uid:
            menu.addSeparator()
            act_restore = menu.addAction("Restore (already quarantined)")
        chosen = menu.exec(btn.mapToGlobal(btn.rect().bottomLeft()))
        if chosen is None:
            return
        if chosen is act_ignore:
            btn.setText("Ignored")
            btn.setEnabled(False)
            self._notify_finding("ignore", path, row)
            return
        if chosen is act_restore and uid:
            self._run_one(row, btn, "Restore", "Restored",
                          lambda: self._apply_restore(engine, uid))
            return
        if plan.get("plan") == PLAN_REVEAL:
            self._run_one(row, btn, "Revealing", "Revealed",
                          lambda: engine.execute_plan(plan, Path(path), finding))
            return
        if chosen.text() == "Quarantine":
            self._run_one(row, btn, "Quarantining", "Quarantined",
                          lambda: self._apply_quarantine(engine, path, finding))
        else:
            self._run_one(row, btn, "Cleaning", "Cleaned",
                          lambda: self._apply_clean(engine, path))

    def _run_one(self, row: int, btn: QPushButton, running: str,
                 done: str, fn) -> None:
        btn.setText(f"{running}...")
        btn.setEnabled(False)
        worker = ItemActionWorker([(str(row), fn)])
        self._workers.append(worker)

        def on_status(key: str, info: dict) -> None:
            state = info.get("state")
            if state == "running":
                btn.setText(f"{running}...")
            elif state == "done":
                detail = info.get("detail") or {}
                status = detail.get("status") if isinstance(detail, dict) else None
                if status in ("ok", "stripped", "quarantined", "revealed",
                              "purged", "ignored"):
                    btn.setText(done)
                    btn.setEnabled(True)
                else:
                    # A returned dict is NOT proof of success - only a genuine
                    # success status is.  Anything else (error / rolled_back /
                    # plan_skip / missing) is painted as the failure it is.
                    reason = (detail.get("reason") if isinstance(detail, dict)
                              else str(detail))
                    btn.setText("Failed")
                    btn.setToolTip(str(reason or "action did not succeed"))
                    btn.setEnabled(True)
            elif state == "error":
                btn.setText("Failed")
                btn.setToolTip(str(info.get("detail", "action failed")))
                btn.setEnabled(True)

        worker.item_status.connect(on_status)
        worker.finished_sig.connect(lambda _results, _r=row: self._on_batch(_r, 1))
        worker.start()

    def _on_batch(self, row: int, total: int) -> None:
        try:
            self.win.quarantine.refresh()
        except Exception:
            pass
        self.win.publish("Findings action finished.")

    def _notify_finding(self, action: str, path: str, row: int) -> None:
        self.win._notify(
            "Finding ignored", f"{_clamp_text(str(path), 80)} - left in place.",
            kind=KIND_INFO, payload={"path": path})
        self.win.publish(f"[findings] {action}: {path}")

    # -- engine operations (each returns dict; run off-thread, no UI import) --
    @staticmethod
    def _apply_restore(engine, uid: str) -> dict:
        return engine.restore_item(uid)

    @staticmethod
    def _apply_quarantine(engine, path: str, finding: dict) -> dict:
        return engine.quarantine_file(Path(path), finding.get("name", "suspicious"))

    @staticmethod
    def _apply_clean(engine, path: str) -> dict:
        return engine.disinfect_file(Path(path), dry_run=False)

    def _quarantined_uid(self, path: str) -> str | None:
        if not path:
            return None
        try:
            for it in self.win.ctx.db.list_quarantine(status="quarantined"):
                if it.get("original_path", "") == path:
                    return it.get("uid")
        except Exception:
            return None
        return None

    def closeEvent(self, event) -> None:
        for w in self._workers:
            if w.isRunning():
                w.requestInterruption()
        self._workers.clear()
        self.win._active_viewer = None
        super().closeEvent(event)

    def reject(self) -> None:
        self.close()


class MainWindow(QMainWindow):
    def __init__(self, ctx: RuntimeContext, base: Optional[Path] = None) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(APP_TITLE)
        self.setWindowIcon(make_logo())
        self.resize(1180, 760)
        self.setMinimumSize(900, 600)       # bug #3: never 3-fixed-size; small ok

        self._workers: List[QThread] = []
        self._busy_workers: set = set()
        self._last_scan_ts: Optional[float] = None
        self.watcher = None
        self.bridge = None
        self.tray = None
        self.auto_worker: Optional[AutoPilotWorker] = None
        self.rt_monitor = None
        self._rt_bridge = None
        self.notifications = NotificationStore(self.ctx.db)
        self._active_viewer = None

        # bug #1: any background crash surfaces as a non-fatal dialog instead
        # of silently killing the QApplication.
        crashguard.bridge().error.connect(self._on_worker_error)

        self._build_ui()
        self._wire_nav()
        self._build_tray()
        self.dashboard.refresh()
        self.quarantine.refresh()

        # Device-change plumbing: the watcher (WM_DEVICECHANGE + polling) is
        # always armed so external drives appear within seconds, no restart.
        self._start_device_monitor()
        self._start_drive_poll_timer()

        # Real-time file-system protection (optional, configurable).
        if bool(self.ctx.cfg.get("rt_enabled", False)):
            QTimer.singleShot(2000, self._start_rt)

        # Live activity headline refresher (bug #5) + "last scan" clock.
        self._idle_timer = QTimer(self)
        self._idle_timer.setInterval(15000)
        self._idle_timer.timeout.connect(self._refresh_idle_line)
        self._idle_timer.start()

        # Launch-time background auto-scan service.
        if (bool(self.ctx.cfg.get("auto_sigs_on_startup", True)) or
                bool(self.ctx.cfg.get("auto_scan_on_startup", True))):
            QTimer.singleShot(1500, self._launch_auto_service)

        # Periodic online signature refresh (default every 6 hours).
        self._schedule_periodic_signatures()

        # Periodic quarantine retention sweep (purge_after_days mode).
        self._schedule_retention_sweep()

    # ------------------------------------------------------------------- chrome
    def _build_ui(self) -> None:
        if hasattr(self, "stack"):
            return   # never rebuild/duplicate the sidebar + stack (bug #2)
        root = QWidget(self)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(12)

        nav = QVBoxLayout()
        nav.setSpacing(6)
        title_row = QHBoxLayout()
        title = _label("SecuDrive", bold=True)
        title.setStyleSheet("font-size: 18px; color: #4C8BF5;")
        title_row.addWidget(title)
        title_row.addStretch(1)
        self.bell = _NotificationBell(self)
        title_row.addWidget(self.bell)
        nav.addLayout(title_row)
        nav.addWidget(_label("Security & Recovery", muted=True))

        # bug #2: predictable nav geometry - fixed item height + spacing, no
        # duplicated rows, single stylesheet application.
        self.nav_list = QListWidget()
        self.nav_list.setObjectName("navList")
        self.nav_list.setFixedWidth(190)
        self.nav_list.setSpacing(2)
        self.nav_list.setUniformItemSizes(True)
        self.nav_list.setVerticalScrollMode(
            QAbstractItemView.ScrollMode.ScrollPerPixel)
        for name in ("Dashboard", "Scanner", "Quarantine", "Drive Doctor", "Logs"):
            self.nav_list.addItem(name)
            self.nav_list.item(self.nav_list.count() - 1).setSizeHint(
                QSize(0, 42))
        nav.addWidget(self.nav_list, 1)

        nav.addWidget(self._make_quit_button())
        outer.addLayout(nav)

        self.stack = QStackedWidget()
        self.dashboard = DashboardPage(self)
        self.scanner_page = ScannerPage(self)
        self.quarantine = QuarantinePage(self)
        self.drive_doctor = DriveDoctorPage(self)
        self.logs = LogsPage(self)
        for page in (self.dashboard, self.scanner_page, self.quarantine,
                     self.drive_doctor, self.logs):
            self.stack.addWidget(page)
        outer.addWidget(self.stack, 1)

        self.setCentralWidget(root)

    def _make_quit_button(self) -> QWidget:
        btn = QPushButton("Quit SecuDrive")
        btn.setProperty("danger", True)
        btn.clicked.connect(self.close)
        return btn

    def _wire_nav(self) -> None:
        self.nav_list.currentRowChanged.connect(self.stack.setCurrentIndex)

    def _build_tray(self) -> None:
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(self)
            self.tray.setIcon(make_logo())
            self.tray.setToolTip(APP_TITLE)
            self.tray.show()

    def _notify(self, title: str, message: str, kind: str = "info",
                payload: object = None) -> None:
        """One funnel for every notification: persisted in-app + OS toast.

        The in-app copy survives restart (NotificationStore, ~200 cap); the
        OS toast is best-effort (tray button or debug log when unavailable).
        """
        try:
            self.notifications.push(kind, title, message, payload)
        except Exception:
            crashguard.report_exception("notification-persist",
                                        sys.exc_info()[1], sys.exc_info()[2])
        if hasattr(self, "bell"):
            self.bell.refresh()
        if self.tray is not None:
            self.tray.showMessage(title, message,
                                  QSystemTrayIcon.MessageIcon.Information, 6000)
        else:
            logger.info("%s - %s", title, message)

    # ------------------------------------------------------- GUI action debug log
    def debug_log(self, event: str, command: str = "", target: object = None,
                  dry_run: object = None) -> None:
        """Every button click lands here: exact command string, exact resolved
        target path, exact dry_run value - written to secudrive_debug.log and
        the on-screen Debug panel so bugs like the old silent-default target or
        a baked-in dry_run=True are instantly visible, never silent."""
        parts = [f"event={event}"]
        if target is not None:
            parts.append(f"target={target!r}")
        if dry_run is not None:
            parts.append(f"dry_run={dry_run!r}")
        if command:
            parts.append(f"command={command}")
        line = " | ".join(parts)
        logger.info("GUI action: %s", line)
        view = getattr(self.logs, "debug_view", None)
        if view is not None:
            view.append(f"[{time.strftime('%H:%M:%S')}] GUI action: {line}")

    # ------------------------------------------------------ crash safety: dialogs
    def _on_worker_error(self, message: str) -> None:
        """Debounced, non-fatal error dialog fed by crashguard.bridge().

        Non-modal on purpose: the process and every other worker keep running;
        the dialog is click-away, never blocks the tray icon or the event loop."
        """
        global _LAST_ERROR_POPUP_TIME
        logger.error("non-fatal error dialog requested: %s", message)
        now = time.time()
        if now - _LAST_ERROR_POPUP_TIME < _ERROR_POPUP_DEBOUNCE_S:
            return
        _LAST_ERROR_POPUP_TIME = now
        box = QMessageBox(self)
        box.setWindowTitle("SecuDrive - background task issue")
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText("SecuDrive hit a snag during a background task.\n"
                    "Your data is safe and the app is still running.")
        box.setInformativeText(str(message)[:500])
        detail = [str(message)]
        try:
            log = self.ctx.cfg.base_dir / "secudrive_debug.log"
            if log.exists():
                tail = "\n".join(log.read_text(encoding="utf-8", errors="replace")
                                 .splitlines()[-25:])
                detail.append("\n\nRecent debug log:\n" + tail)
        except Exception:
            pass
        box.setDetailedText("\n".join(detail))
        box.addButton("OK", QMessageBox.ButtonRole.AcceptRole)
        box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        box.show()

    # ------------------------------------------------- background device monitor
    def _start_device_monitor(self) -> None:
        if self.watcher is not None:
            return
        from .watcher import BackgroundWatcher

        class _Bridge(QObject):
            attached = pyqtSignal(str)
            removed = pyqtSignal(str)

        self.bridge = _Bridge()
        self.bridge.attached.connect(self._on_usb_attach)
        self.bridge.removed.connect(self._on_usb_remove)

        self.watcher = BackgroundWatcher(
            interval=float(self.ctx.cfg.get("poll_interval", 1.5)),
            on_attach=self.bridge.attached.emit,
            on_remove=self.bridge.removed.emit)
        self.watcher.start()

    def _start_drive_poll_timer(self) -> None:
        """Fallback refresh every few seconds (works without pywin32)."""
        interval = int(float(self.ctx.cfg.get("drive_refresh_interval", 3.0)) * 1000)
        self.drive_timer = QTimer(self)
        self.drive_timer.setInterval(max(1000, interval))
        self.drive_timer.timeout.connect(self._refresh_drive_views)
        self.drive_timer.start()

    def _on_drive_change(self, *_args) -> None:
        self._refresh_drive_views()

    def _refresh_drive_views(self) -> None:
        """Re-list external drives everywhere (combo lists + dashboard counts)."""
        try:
            if hasattr(self, "drive_doctor"):
                self.drive_doctor.refresh_drives()
            if hasattr(self, "scanner_page"):
                self.scanner_page._populate_drive_combo()
            if hasattr(self, "dashboard"):
                self.dashboard.refresh()
            if self.rt_monitor is not None and self.rt_monitor.is_enabled():
                self.rt_monitor.sync_roots()
        except Exception:
            crashguard.report_exception("drive-views-refresh",
                                        sys.exc_info()[1], sys.exc_info()[2])

    def _on_usb_attach(self, drive: str) -> None:
        self.debug_log("usb_attach", target=drive)
        self._refresh_drive_views()
        if not os.path.isdir(drive):
            return   # hot-plug race: volume still mounting; next poll sees it
        if bool(self.ctx.cfg.get("usb_auto_clean", False)):
            engine = self.ctx.ensure_engine()
            worker = ActionWorker(
                fn=lambda: engine.clean_external_drive(Path(drive), dry_run=False),
                progress_label=f"Auto-cleaning {drive}...")
            worker.finished_sig.connect(self._auto_clean_done)
            worker.progress_sig.connect(self.publish_current)
            self._track_qt_thread(worker)
            worker.start()

    def _on_usb_remove(self, drive: str) -> None:
        self.debug_log("usb_remove", target=drive)
        self._refresh_drive_views()
        # Remove root from RT monitor if it was watching that drive.
        if self.rt_monitor is not None:
            self.rt_monitor.remove_root(drive)

    # --------------------------------------------- real-time protection lifecycle
    def _start_rt(self) -> None:
        if self.rt_monitor is not None and self.rt_monitor.is_enabled():
            return
        from .realtime_monitor import RealtimeMonitor
        self._rt_bridge = _RTBridge()
        self._rt_bridge.event.connect(self._on_rt_event)
        self._rt_bridge.detection.connect(self._on_rt_detection)
        self._rt_bridge.state.connect(self._on_rt_state)
        self.rt_monitor = RealtimeMonitor(
            self.ctx,
            on_event=self._rt_bridge.event.emit,
            on_detection=self._rt_bridge.detection.emit,
            on_state=self._rt_bridge.state.emit,
        )
        self.rt_monitor.start()
        self.ctx.cfg.set("rt_enabled", True)
        self.ctx.cfg.save()

    def _stop_rt(self) -> None:
        if self.rt_monitor is None:
            return
        self.rt_monitor.stop()
        self.ctx.cfg.set("rt_enabled", False)
        self.ctx.cfg.save()

    def _on_rt_event(self, text: str, kind: str) -> None:
        try:
            if kind == "info":
                self.publish_current(text, "rt")
            else:
                self.publish(text, "rt")
        except Exception:
            crashguard.report_exception(
                "rt-gui-event", sys.exc_info()[1], sys.exc_info()[2])

    def _on_rt_detection(self, info: dict) -> None:
        try:
            action = info.get("action", "reported")
            path = info.get("path", "?")
            threat = info.get("name", "Unknown")
            line = f"REAL-TIME: '{threat}' {action} - {path}"
            self.publish(line, "rt")
            self._notify("Real-time protection",
                         f"{threat} ({action}) - {path}")
            if hasattr(self, "quarantine"):
                self.quarantine.refresh()
        except Exception:
            crashguard.report_exception(
                "rt-gui-detect", sys.exc_info()[1], sys.exc_info()[2])

    def _on_rt_state(self, state: dict) -> None:
        try:
            key = state.get("key")
            if hasattr(self, "dashboard"):
                self.dashboard.refresh_rt()
        except Exception:
            crashguard.report_exception(
                "rt-gui-state", sys.exc_info()[1], sys.exc_info()[2])

    def _auto_clean_done(self, rec) -> None:
        n = "?"
        if isinstance(rec, dict):
            phases = rec.get("phases", {})
            n = str(len(phases.get("strip_shortcuts", {}).get("quarantined", [])) +
                    len(phases.get("clean_autorun", {}).get("quarantined", [])))
        if isinstance(rec, dict) and rec.get("error"):
            self._notify("Auto-clean finished", f"with errors: {rec['error']}")
        else:
            self._notify("Auto-clean finished", f"Quarantined {n} malicious item(s).")
        self.publish(f"Auto-clean finished on external drive - {n} item(s).")
        self.quarantine.refresh()

    # -------------------------------------------------------- live activity feed
    def publish(self, text: str, source: str = "engine",
                payload: object = None) -> None:
        """Append a plain-language event to the live activity feed + status."""
        self._bump_activity()
        feed = getattr(self.dashboard, "activity", None)
        if feed is not None:
            feed.add_event(f"[{source}] {text}", payload=payload)

    def publish_current(self, text: str, source: str = "engine") -> None:
        """Update the live status headline (cheap - called per progress tick)."""
        self._bump_activity()
        feed = getattr(self.dashboard, "activity", None)
        if feed is not None:
            feed.set_current(f"[{source}] {text}")

    def _bump_activity(self) -> None:
        """Fresh activity anywhere -> working headline refreshes immediately."""
        active = feed = getattr(self.dashboard, "activity", None)
        if active is not None and self._busy_workers:
            active.set_current_live()

    def _refresh_idle_line(self) -> None:
        """Idle line: 'Idle - last scan 14 min ago' when nothing is running."""
        feed = getattr(self.dashboard, "activity", None)
        if feed is None:
            return
        if self._busy_workers:
            feed.set_current_live()
            return
        if self._last_scan_ts is None:
            feed.set_idle("Idle - waiting for work")
        else:
            minutes = max(1, int((time.time() - self._last_scan_ts) / 60))
            feed.set_idle(f"Idle - last scan {minutes} min ago")

    def _mark_scan_finished(self) -> None:
        self._last_scan_ts = time.time()
        self._refresh_idle_line()

    def save_scan_summary(self, summary: dict) -> None:
        """Persist the last-completed scan for the Dashboard 'last scan' card.

        Accepts either a ScanWorker-style payload dict or an AutoPilot-style
        stats dict; both carry enough to reconstruct a scan_summaries row
        (scan_id / started / duration_s / files / dirs / bytes / errors /
        findings / targets).
        """
        try:
            scan = summary.get("scan") or summary
            scan_id = scan.get("scan_id")
            if not scan_id:
                return
            _summary_err = summary.get("errors")
            _scan_err = scan.get("errors")
            _err = _scan_err if _summary_err is None else _summary_err
            if isinstance(_err, (list, tuple, dict, set)):
                errors = len(_err)
            else:
                errors = int(_err or 0)
            self.ctx.db.save_scan_summary(
                scan_id=scan_id,
                started=scan.get("started",
                                 summary.get("started",
                                             time.strftime("%Y-%m-%d %H:%M:%S"))),
                duration_s=float(scan.get("duration_s",
                                          summary.get("duration_s", 0)) or 0),
                files=int(scan.get("files", 0) or 0),
                dirs=int(scan.get("dirs", 0) or 0),
                bytes_scanned=int(scan.get("bytes",
                                           scan.get("bytes_scanned",
                                                    summary.get("bytes", 0))) or 0),
                errors=errors,
                findings=int(scan.get("findings", 0) or 0),
                targets=summary.get("targets", scan.get("targets")) or None)
            if hasattr(self, "dashboard"):
                self.dashboard.refresh()
        except Exception:
            crashguard.report_exception("save-scan-summary",
                                        sys.exc_info()[1], sys.exc_info()[2])

    def open_findings(self, scan_id: str | None = None,
                      rows: list | None = None,
                      title: str = "Findings Results") -> None:
        """Open the Findings Results viewer (reuses ScannerPage's table)."""
        try:
            self._active_viewer = FindingsResultsDialog(
                self, scan_id=scan_id, rows=rows, title=title)
            self._active_viewer.show()
            return self._active_viewer
        except Exception:
            crashguard.report_exception("open-findings",
                                        sys.exc_info()[1], sys.exc_info()[2])
            self._notify("Findings", "Could not open the results viewer.",
                         kind="info")
            return None

    def _open_feed_findings(self, payload: dict) -> None:
        """Feed line 'Click to view details' -> Findings viewer (manual+auto)."""
        scan_id = payload.get("scan_id") if isinstance(payload, dict) else None
        self.open_findings(scan_id=scan_id)

    # ------------------------------------------- launch-time auto scan service
    def _launch_auto_service(self) -> None:
        """Kick off the background AutoPilotWorker (sigs -> scan -> repair)."""
        if self.auto_worker is not None:
            try:
                if self.auto_worker.isRunning():
                    return
            except RuntimeError:
                self.auto_worker = None
        from .scanner import ScanOptions
        from .systemutils import auto_scan_targets

        targets = auto_scan_targets()
        run_scan = bool(self.ctx.cfg.get("auto_scan_on_startup", True))
        run_sigs = bool(self.ctx.cfg.get("auto_sigs_on_startup", True))
        policy = str(self.ctx.cfg.get("auto_action_policy", "auto"))
        repair_enabled = bool(self.ctx.cfg.get("auto_repair", True))
        if not repair_enabled:
            policy = "off"                        # cautious: report only
        updater = self.ctx.make_updater() if run_sigs else None

        options = ScanOptions()
        options.max_depth = int(self.ctx.cfg.get("auto_scan_max_depth", 6))
        options.max_hash_size = int(self.ctx.cfg.get("auto_scan_max_hash_size",
                                                     256 * 1024 * 1024))
        options.threads = int(self.ctx.cfg.get("scan_threads", 0))
        if not run_scan:
            targets = []                          # sig-only run: nothing to walk

        worker = AutoPilotWorker(self.ctx, updater, targets, options, policy=policy)
        worker.progress_sig.connect(self.scanner_page.log_notice)
        worker.progress_sig.connect(self.publish_current)
        worker.waiting_sig.connect(self._on_autopilot_waiting)
        worker.finished_sig.connect(self._on_auto_finished)
        self.auto_worker = worker
        self._busy_workers.add(worker)
        worker.finished.connect(lambda: self._busy_workers.discard(worker))
        self.ctx.db.audit("autopilot_launch",
                          f"policy={policy} targets={len(targets)} run_sigs={run_sigs}")
        self.debug_log("autopilot_launch",
                       command=f"AutoPilotWorker(policy={policy})",
                       target="; ".join(targets))
        self.scanner_page.log_notice("Background service: signing, scanning, "
                                     "repairing (silent). See Logs page.")
        self._track_qt_thread(worker)
        worker.start()

    def _on_autopilot_waiting(self, info: dict) -> None:
        """Prompt policy: ask the user before the worker touches a file."""
        if self.auto_worker is None:
            return
        msg = QMessageBox(self)
        msg.setWindowTitle("SecuDrive - action required")
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText(f"Finding: {info.get('threat', '?')} "
                    f"({info.get('confidence', 0):.0%} confidence)")
        msg.setInformativeText(str(info.get("path", "")))
        msg.setDetailedText(
            "Automatic mode is DISABLED (cautious). Choose what SecuDrive should "
            "do with this file. Disinfect/Quarantine both create an encrypted "
            "backup first (Zero Data Loss).")
        btn_d = msg.addButton("Disinfect", QMessageBox.ButtonRole.AcceptRole)
        btn_q = msg.addButton("Quarantine", QMessageBox.ButtonRole.ActionRole)
        btn_s = msg.addButton("Skip", QMessageBox.ButtonRole.RejectRole)
        btn_d.setDefault(True)
        msg.exec()
        decision = {btn_d: DISINFECT, btn_q: QUARANTINE, btn_s: SKIP}.get(
            msg.clickedButton(), SKIP)
        self.debug_log("autopilot_decision",
                       command=f"respond({decision})",
                       target=info.get("path"))
        if self.auto_worker is not None:
            try:
                self.auto_worker.respond(decision)
            except RuntimeError:
                pass

    def _on_auto_finished(self, stats: dict) -> None:
        self.auto_worker = None
        scan = stats.get("scan") or {}
        errors = stats.get("errors") or []
        from .report_formatter import unresolved_findings
        attention = (int(stats.get("quarantined", 0))
                     + int(stats.get("rolled_back", 0))
                     + int(stats.get("requires_manual_review", 0))
                     + int(stats.get("skipped_actions", 0))
                     + int(stats.get("error", 0))
                     + int(stats.get("failed", 0))
                     + unresolved_findings(stats.get("finding_rows")))
        body = headline(int(scan.get("files") or 0),
                        int(scan.get("findings") or 0),
                        int(stats.get("disinfected", 0)),
                        int(stats.get("auto_purged", 0)), attention)
        extras = []
        if stats.get("attribs_fixed"):
            extras.append(f"{stats.get('attribs_fixed')} attributes restored")
        if stats.get("freed_bytes"):
            extras.append(f"{stats.get('freed_bytes'):,} bytes freed")
        if errors:
            extras.append(f"{len(errors)} warning(s)")
        if extras:
            body = f"{body} ({'; '.join(extras)})"
        title = "SecuDrive scan complete"
        if errors:
            title = f"{title} - {len(errors)} warning(s)"
        self._notify(title, body, kind=KIND_SCAN,
                     payload={"scan_id": scan.get("scan_id"),
                              "findings": scan.get("findings", 0),
                              "files": scan.get("files", 0)})
        self.debug_log("autopilot_finished", command=body)

        self.scanner_page.log_notice(f"Auto-scan finished: {body}")
        if errors:
            for err in errors[:5]:
                self.scanner_page.log_notice(f"  warning: {err}")
        self.publish(f"Auto-scan finished: {body}",
                     payload={"scan_id": scan.get("scan_id"),
                              "findings": scan.get("findings", 0),
                              "files": scan.get("files", 0)})
        self.save_scan_summary(stats)
        self.dashboard.refresh()
        self.quarantine.refresh()
        self.logs.refresh()
        self._mark_scan_finished()

        # bug #7: auto-mode is NEVER fully silent - a summary surfaces (non-
        # modal so the tray/event loop keep working).
        plain = build_report(
            {"files": scan.get("files", 0), "findings": scan.get("findings", 0),
             "errors": scan.get("errors", 0)},
            actions={k: stats.get(k) for k in
                     ("disinfected", "quarantined", "rolled_back", "revealed",
                      "attribs_fixed", "auto_purged", "freed_bytes",
                      "requires_manual_review", "skipped_actions")}).get("plain", body)
        summary = ScanSummaryDialog(self, plain, body,
                                    findings=int(scan.get("findings") or 0))
        summary.show()

    # ------------------------------------------------- periodic signature refresh
    def _schedule_periodic_signatures(self) -> None:
        hours = float(self.ctx.cfg.get("auto_update_interval_hours", 6) or 0)
        if hours <= 0:
            return
        QTimer.singleShot(int(hours * 3600 * 1000), self._periodic_signatures)

    def _periodic_signatures(self) -> None:
        self.debug_log("periodic_sig_refresh")
        self.dashboard._update_sigs()
        self._schedule_periodic_signatures()

    # ----------------------------------------------- quarantine retention sweep
    def _schedule_retention_sweep(self) -> None:
        """Run the 'purge_after_days' sweep shortly after launch, then once a
        day.  Harmless no-op when the mode is not 'purge_after_days'."""
        mode = str(self.ctx.cfg.get("quarantine_retention_mode", "auto_purge_verified"))
        if mode == "purge_after_days":
            QTimer.singleShot(30000, self._retention_sweep)
        QTimer.singleShot(24 * 3600 * 1000, self._schedule_retention_sweep)

    def _retention_sweep(self) -> None:
        if str(self.ctx.cfg.get("quarantine_retention_mode", "auto_purge_verified")) \
                != "purge_after_days":
            return
        days = int(self.ctx.cfg.get("purge_after_days", 30) or 0)
        if days <= 0:
            return
        uid_due = [row["uid"] for row in self.ctx.db.purge_due(days)]
        if not uid_due:
            self.debug_log("retention_sweep", command="nothing due")
            return
        self.debug_log("retention_sweep",
                       command=f"purging {len(uid_due)} item(s) older than {days}d")
        engine = self.ctx.ensure_engine()

        def _sweep() -> dict:
            purged, errors = 0, []
            for uid in uid_due:
                rec = engine.purge_item(uid)
                if rec.get("status") == "purged":
                    purged += 1
                else:
                    errors.append(f"{uid}: {rec.get('reason')}")
            return {"purged": purged, "errors": errors}

        worker = ActionWorker(_sweep, progress_label="Purge overdue quarantine items...")
        worker.finished_sig.connect(self._on_retention_sweep_done)
        self._track_qt_thread(worker)
        worker.start()

    def _on_retention_sweep_done(self, result: dict) -> None:
        purged = int(result.get("purged") or 0)
        errors = result.get("errors") or []
        self.ctx.db.audit("retention_sweep",
                          f"purged={purged} errors={len(errors)}")
        if purged:
            self.quarantine.refresh()
            self.dashboard.refresh()
            self.publish(f"Quarantine sweep: {purged} item(s) purged after "
                         "retention window")
            self.debug_log("retention_sweep_done", command=f"purged={purged}")
        if errors:
            for err in errors[:5]:
                self.scanner_page.log_notice(f"  retention sweep warning: {err}")

    # ----------------------------------------------------- post-scan actions (7)
    def _offer_post_scan_actions(self, summary: dict) -> None:
        """Scan finished with findings -> never act silently.  Ask first."""
        findings = summary.get("finding_rows") or []
        if not findings:
            return
        dlg = PostScanActionsDialog(self, summary)
        decision = dlg.exec()
        if decision not in ("clean", "quarantine", "review"):
            self.publish("Findings left untouched (you chose to ignore).")
            return
        self.publish("Acting on scan findings...")
        if decision == "review":
            self._review_actions(summary, findings)
        else:
            self._bulk_action(summary, findings, decision)

    def _bulk_action(self, summary: dict, findings: List[dict],
                     decision: str) -> None:
        engine = self.ctx.ensure_engine()
        paths = [f["path"] for f in findings]

        def _run():
            counts = {"disinfected": 0, "quarantined": 0, "skipped": 0,
                      "errors": []}
            for path in paths:
                try:
                    p = Path(path)
                except Exception:
                    continue
                try:
                    if not p.exists():
                        counts["skipped"] += 1
                        continue
                    if decision == "clean":
                        row = next((f for f in findings
                                    if str(f.get("path")) == str(p)), {})
                        from .recovery import resolve_plan
                        plan = resolve_plan(p, self.ctx.db, row,
                                            config=self.ctx.cfg)
                        rec = engine.execute_plan(plan, p, row)
                        outcome = rec.get("outcome") or rec.get("status")
                        if (outcome == "resolved_in_place"
                                or rec.get("status") in ("disinfected", "stripped")):
                            counts["disinfected"] += 1
                        elif (outcome in ("quarantined_removed",
                                          "fell_back_to_quarantine",
                                          "quarantined_after_attempts")
                                or rec.get("status") == "quarantined"):
                            counts["quarantined"] += 1
                        elif rec.get("status") == "error":
                            counts["errors"].append(str(rec.get("reason")))
                        else:
                            counts["skipped"] += 1
                    else:
                        row = next((f for f in findings
                                    if str(f.get("path")) == str(p)), {})
                        rec = engine.quarantine_file(p, threat=row.get("name"))
                        if rec.get("status") == "quarantined":
                            counts["quarantined"] += 1
                        else:
                            counts["errors"].append(str(rec.get("reason")))
                except Exception as exc:
                    counts["errors"].append(str(exc))
            return counts

        worker = ActionWorker(_run,
                              progress_label=f"Applying '{decision}' to "
                                             f"{len(paths)} finding(s)...")
        worker.finished_sig.connect(
            lambda rep: self._post_scan_actions_done(summary, rep))
        worker.progress_sig.connect(self.publish_current)
        self._track_qt_thread(worker)
        worker.start()

    def _review_actions(self, summary: dict, findings: List[dict]) -> None:
        """Review Individually: loop each finding through a yes/no dialog."""
        counts = {"disinfected": 0, "quarantined": 0, "skipped": 0, "errors": []}
        engine = self.ctx.ensure_engine()
        for f in findings:
            path_str = str(f.get("path") or "")
            box = QMessageBox(self)
            box.setWindowTitle("SecuDrive - review finding")
            box.setIcon(QMessageBox.Icon.Warning)
            box.setText(finding_to_plain(f))
            box.setInformativeText(
                "Disinfect/Quarantine both create an encrypted backup first "
                "(Zero Data Loss).  Keep leaves the file untouched.")
            b_d = box.addButton("Disinfect", QMessageBox.ButtonRole.AcceptRole)
            b_q = box.addButton("Quarantine", QMessageBox.ButtonRole.ActionRole)
            b_k = box.addButton("Keep", QMessageBox.ButtonRole.RejectRole)
            b_d.setDefault(True)
            box.exec()
            choice = {b_d: "clean", b_q: "quarantine", b_k: "skip"}.get(
                box.clickedButton(), "skip")
            try:
                p = Path(path_str)
                if not p.exists():
                    counts["skipped"] += 1
                    continue
                if choice == "clean":
                    rec = engine.execute_outcome_a(p)
                    if rec.get("status") in ("disinfected", "stripped"):
                        counts["disinfected"] += 1
                    elif rec.get("status") == "quarantined":
                        counts["quarantined"] += 1
                    else:
                        counts["errors"].append(str(rec.get("reason")))
                elif choice == "quarantine":
                    rec = engine.quarantine_file(p, threat=f.get("name"))
                    if rec.get("status") == "quarantined":
                        counts["quarantined"] += 1
                    else:
                        counts["errors"].append(str(rec.get("reason")))
                else:
                    counts["skipped"] += 1
            except Exception as exc:
                counts["errors"].append(str(exc))
        self._post_scan_actions_done(summary, counts)

    def _post_scan_actions_done(self, summary: dict, counts: dict) -> None:
        self.quarantine.refresh()
        self.logs.refresh()
        if isinstance(counts, dict) and counts.get("error"):
            self.publish(f"Post-scan action failed: {counts['error']}")
            return
        if not isinstance(counts, dict):
            return
        done = (int(counts.get("disinfected") or 0)
                + int(counts.get("quarantined") or 0))
        body = (f"Disinfected {counts.get('disinfected', 0)}, "
                f"quarantined {counts.get('quarantined', 0)}, "
                f"kept {counts.get('skipped', 0)}.")
        if counts.get("errors"):
            body += f" {len(counts['errors'])} error(s)."
        self.publish(f"Post-scan actions complete: {body}")
        self._notify("Cleanup finished", f"{done} finding(s) handled. {body}")
        plain = build_report(summary, finding_rows=summary.get("finding_rows"),
                             actions={k: counts.get(k) for k in
                                      ("disinfected", "quarantined")}
                             | {"skipped_actions": counts.get("skipped")}
                             ).get("plain", body)
        self._mark_scan_finished()
        summary_box = ScanSummaryDialog(self, plain, body,
                                        findings=int(summary.get("findings") or 0))
        summary_box.show()

    # --------------------------------------------------------------- worker mgmt
    def _track_qt_thread(self, thread) -> None:
        """Generic QThread lifecycle tracking (Qt workers).

        The finished handler is a bound slot so PyQt delivers it queued on the
        GUI thread (a plain lambda would run on the worker thread).  Deletion
        is OWNED by the worker-owning widget: its own ``finished`` handler
        MUST set the wrapper reference to ``None`` FIRST and only then call
        ``deleteLater()`` (never the reverse - a stale wrapper is the C++-is-
        deleted crash).  Tracked bookkeeping here only mirrors membership so
        ``_workers``/``_busy_workers`` never outlive a worker object.
        """
        if thread not in self._workers:
            self._workers.append(thread)
            self._busy_workers.add(thread)
            thread.finished.connect(self._qt_thread_finished)

    def _qt_thread_finished(self) -> None:
        """Invoked on the GUI thread when a tracked QThread fully returns."""
        self._forget_qt_thread(self.sender())

    def _forget_qt_thread(self, thread) -> None:
        """Idempotent membership bookkeeping for a finished/wrapper-dropped
        QThread.  Called BOTH by the tracked ``finished`` slot and by the
        owning widget's own finished handler, so ``_workers``/``_busy_workers``
        never leak even when a nested event loop settles ``deleteLater()``
        before the queued ``finished`` delivery arrives."""
        if thread is None:
            return
        try:
            if thread in self._workers:
                self._workers.remove(thread)
        except (RuntimeError, ValueError):
            pass
        try:
            self._busy_workers.discard(thread)
        except RuntimeError:
            pass

    # ------------------------------------------------------------- close / dots
    def closeEvent(self, event) -> None:
        if self.auto_worker is not None:
            try:
                if self.auto_worker.isRunning():
                    self.auto_worker.cancel()
                    self.auto_worker.wait(3000)
            except RuntimeError:
                self.auto_worker = None
        if self.rt_monitor is not None:
            self._stop_rt()
        if hasattr(self, "drive_timer"):
            self.drive_timer.stop()
        if hasattr(self, "_idle_timer"):
            self._idle_timer.stop()
        if self.watcher is not None:
            self.watcher.stop()
        if self.tray is not None:
            self.tray.hide()
        for worker in list(self._workers):
            try:
                if hasattr(worker, "isRunning") and worker.isRunning():
                    worker.wait(2000)
            except RuntimeError:
                continue   # finished worker already released - nothing to wait
        self.ctx.db.close()
        super().closeEvent(event)


# ---------------------------------------------------------------- activity feed
class ActivityFeed(QWidget):
    """Bug #5: live, signal-driven status headline + rolling event list.

    Updated ONLY from Qt signals (worker progress / finished), never by
    polling log files.  ``set_current`` is cheap and called per progress tick;
    ``add_event`` is throttled so a million-file scan does not flood the list.

    Events may carry an optional payload (e.g. ``{"scan_id": ...}``) stored in
    the item's UserRole; clicking a payload-carrying event emits
    ``view_requested`` so destinations (findings viewer, quarantine page) can
    jump straight to the detail.
    """

    _EVENT_CAP = 60
    _THROTTLE_S = 1.2

    view_requested = pyqtSignal(dict)

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        card = _card(self)
        lay = QVBoxLayout(card)
        head = QHBoxLayout()
        head.addWidget(_label("Live activity", bold=True))
        head.addStretch(1)
        self.lbl_live = _label("\u25cf", muted=True)
        head.addWidget(self.lbl_live)
        lay.addLayout(head)

        self.lbl_current = _label("Idle - waiting for work", muted=False)
        self.lbl_current.setWordWrap(True)
        self.lbl_current.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.lbl_current)

        self.listw = QListWidget()
        self.listw.setObjectName("activityList")
        self.listw.setMaximumHeight(140)
        self.listw.itemClicked.connect(self._on_item_clicked)
        lay.addWidget(self.listw)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)
        self._last_event_ts = 0.0

    def _on_item_clicked(self, item) -> None:
        data = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(data, dict) and data.get("scan_id"):
            self.view_requested.emit(data)

    def set_current(self, text: str) -> None:
        self.lbl_current.setText(text)

    def set_current_live(self) -> None:
        """Mark the headline as 'working now' without changing its text."""
        self.lbl_live.setStyleSheet("color: #2ECC71; font-size: 12px;")

    def set_idle(self, text: str) -> None:
        self.lbl_current.setText(text)
        self.lbl_live.setStyleSheet("color: #9A9AA0; font-size: 12px;")

    def add_event(self, text: str, payload: object = None) -> None:
        now = time.time()
        if now - self._last_event_ts < self._THROTTLE_S and payload is None:
            return
        self._last_event_ts = now
        stamp = time.strftime("%H:%M:%S")
        item = QListWidgetItem(f"{stamp}  {text}")
        if isinstance(payload, dict):
            item.setData(Qt.ItemDataRole.UserRole, payload)
            item.setToolTip("Click to view details")
        self.listw.insertItem(0, item)
        while self.listw.count() > self._EVENT_CAP:
            self.listw.takeItem(self.listw.count() - 1)


# ------------------------------------------------------------------ dashboard
class DashboardPage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        self.setAcceptDrops(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(14)

        banner = _card(self)
        blay = QHBoxLayout(banner)
        self.status_dot = QLabel("\u25CF")
        self.status_dot.setStyleSheet("color: #F0A020; font-size: 34px;")
        blay.addWidget(self.status_dot)
        stats = QVBoxLayout()
        self.status_label = _label("Checking system status...", bold=True)
        stats.addWidget(self.status_label)
        self.status_detail = _label("", muted=True)
        stats.addWidget(self.status_detail)
        blay.addLayout(stats, 1)
        lay.addWidget(banner)

        action_row = QWidget()
        alay = QHBoxLayout(action_row)
        alay.setContentsMargins(0, 0, 0, 0)
        self.btn_quick = QPushButton("Quick Scan")
        self.btn_quick.setProperty("primary", True)
        self.btn_full = QPushButton("Full Scan")
        self.btn_import_sigs = QPushButton("Import Signatures...")
        self.btn_update_sigs = QPushButton("Update Signatures")
        self.chk_auto_clean = QCheckBox("USB auto-clean")
        self.chk_auto_clean.setChecked(bool(self.win.ctx.cfg.get("usb_auto_clean", False)))
        self.chk_rt = QCheckBox("Real-time protection")
        self.chk_rt.setChecked(bool(self.win.ctx.cfg.get("rt_enabled", False)))
        self.drive_combo = QComboBox()
        self.drive_combo.setMinimumWidth(200)
        self.drive_combo.setToolTip("Restrict this scan to one drive (default: all drives)")
        self.drive_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._populate_drive_combo()
        alay.addWidget(self.btn_quick)
        alay.addWidget(self.btn_full)
        alay.addWidget(self.drive_combo)
        alay.addWidget(self.btn_import_sigs)
        alay.addWidget(self.btn_update_sigs)
        alay.addStretch(1)
        alay.addWidget(self.chk_auto_clean)
        alay.addWidget(self.chk_rt)
        lay.addWidget(action_row)

        auto_row = QWidget()
        zlay = QHBoxLayout(auto_row)
        zlay.setContentsMargins(0, 0, 0, 0)
        zlay.addWidget(_label("Automatic service:", muted=True))
        self.chk_auto_sigs = QCheckBox("Update signatures on launch")
        self.chk_auto_sigs.setChecked(bool(self.win.ctx.cfg.get("auto_sigs_on_startup", True)))
        self.chk_auto_scan = QCheckBox("Auto scan / repair on launch")
        self.chk_auto_scan.setChecked(bool(self.win.ctx.cfg.get("auto_scan_on_startup", True)))
        self.chk_auto_repair = QCheckBox("Repair & quarantine findings")
        self.chk_auto_repair.setChecked(bool(self.win.ctx.cfg.get("auto_repair", True)))
        self.cmb_policy = QComboBox()
        for label, value in (("Auto (recommended)", "auto"),
                             ("Prompt before acting", "prompt"),
                             ("Scan only - never touch", "off")):
            self.cmb_policy.addItem(label, value)
        current_policy = str(self.win.ctx.cfg.get("auto_action_policy", "auto"))
        idx = self.cmb_policy.findData(current_policy)
        if idx >= 0:
            self.cmb_policy.setCurrentIndex(idx)
        self.chk_autostart = QCheckBox("Start at login")
        self.chk_autostart.setChecked(_autostart_enabled())
        zlay.addWidget(self.chk_auto_sigs)
        zlay.addWidget(self.chk_auto_scan)
        zlay.addWidget(self.chk_auto_repair)
        zlay.addWidget(_label("Policy:", muted=True))
        zlay.addWidget(self.cmb_policy)
        zlay.addWidget(self.chk_autostart)
        zlay.addStretch(1)
        lay.addWidget(auto_row)

        # Auto-Purge retention policy (quarantine_retention_mode).
        retention_row = QWidget()
        rlay = QHBoxLayout(retention_row)
        rlay.setContentsMargins(0, 0, 0, 0)
        rlay.addWidget(_label("Quarantine retention:", muted=True))
        self.cmb_retention = QComboBox()
        self.cmb_retention.setToolTip(
            "How long verified threat artifacts are kept.\n\n"
            "'Keep forever': no automatic deletion; every artifact stays\n"
            "for manual review - safest.\n\n"
            "'Auto-purge verified malware' (default): ONLY pure-malware files\n"
            "(confident signature hit + non-container type, re-verified) are\n"
            "deleted and their short-lived encrypted backup is purged,\n"
            "freeing storage. Any doubt or verify failure is sent to\n"
            "Quarantine instead. Trades a small safety window for lower\n"
            "storage.\n\n"
            "'Purge quarantine after N days': the background sweep deletes\n"
            "quarantined items older than the chosen window.")
        for label, value in (("Keep forever", "keep_forever"),
                             ("Auto-purge verified malware (default)", "auto_purge_verified"),
                             ("Purge quarantine after...", "purge_after_days")):
            self.cmb_retention.addItem(label, value)
        current_mode = str(self.win.ctx.cfg.get("quarantine_retention_mode",
                                                "auto_purge_verified"))
        idx = self.cmb_retention.findData(current_mode)
        if idx >= 0:
            self.cmb_retention.setCurrentIndex(idx)
        self.spin_purge_days = QSpinBox()
        self.spin_purge_days.setRange(1, 365)
        self.spin_purge_days.setValue(int(self.win.ctx.cfg.get("purge_after_days", 30))
                                      or 30)
        self.spin_purge_days.setSuffix(" days")
        self.spin_purge_days.setToolTip(
            "Quarantined items older than this are permanently deleted by the\n"
            "background sweep (blob + encrypted backup). The audit trail row\n"
            "is retained with status 'purged'.")
        self.spin_purge_days.setEnabled(current_mode == "purge_after_days")
        rlay.addWidget(self.cmb_retention)
        rlay.addWidget(self.spin_purge_days)
        rlay.addStretch(1)
        lay.addWidget(retention_row)

        # Default action on findings (on_detection): resolve-in-place default;
        # always-quarantine is the opt-in legacy behavior.
        detect_row = QWidget()
        dlay = QHBoxLayout(detect_row)
        dlay.setContentsMargins(0, 0, 0, 0)
        dlay.addWidget(_label("If a finding can't be fixed in place:", muted=True))
        self.cmb_on_detection = QComboBox()
        self.cmb_on_detection.setToolTip(
            "How SecuDrive handles a finding by default.\n\n"
            "'Resolve in place' (default): appended malicious payloads are\n"
            "stripped on the spot from an encrypted backup, so the fixed file\n"
            "stays where it belongs. Only files that cannot be fixed safely\n"
            "in place are moved to the Quarantine store.\n\n"
            "'Always quarantine (old)': the old behavior - every finding is\n"
            "moved to the encrypted Quarantine store for manual review and\n"
            "nothing is ever resolved in place.")
        for label, value in (("Resolve in place (default)", "resolve"),
                             ("Always quarantine (old)", "quarantine")):
            self.cmb_on_detection.addItem(label, value)
        current_action = str(self.win.ctx.cfg.get("on_detection", "resolve"))
        idx = self.cmb_on_detection.findData(current_action)
        if idx >= 0:
            self.cmb_on_detection.setCurrentIndex(idx)
        dlay.addWidget(self.cmb_on_detection)
        dlay.addStretch(1)
        lay.addWidget(detect_row)

        self.activity = ActivityFeed(self)
        lay.addWidget(self.activity)
        self.activity.view_requested.connect(self.win._open_feed_findings)

        last_card = _card(self)
        llast = QHBoxLayout(last_card)
        self.last_scan_meta = _label("Last scan: -", muted=True)
        llast.addWidget(self.last_scan_meta)
        llast.addStretch(1)
        self.btn_view_results = QPushButton("View Results")
        self.btn_view_results.setEnabled(False)
        self.btn_view_results.clicked.connect(self._open_last_scan)
        llast.addWidget(self.btn_view_results)
        self._last_scan_meta: Tuple[str, str, int] | None = None
        lay.addWidget(last_card)

        info_card = _card(self)
        ilay = QVBoxLayout(info_card)
        ilay.addWidget(_label("System overview", bold=True))
        self.info_labels: Dict[str, QLabel] = {}
        for key, text in (("signatures", "Signatures loaded"),
                          ("drives_fixed", "Local drives"),
                          ("drives_removable", "Removable drives"),
                          ("drives_external", "External drives (SSD/HDD/flash)"),
                          ("last_update", "Last signature update"),
("update_interval", "Auto signature refresh"),
                           ("backend", "USB watcher backend"),
                           ("watching", "USB watcher state"),
                           ("realtime", "Real-time protection"),
                           ("auto_purged_freed", "Storage freed by auto-purge")):
            row = QHBoxLayout()
            row.addWidget(_label(text, muted=True))
            row.addStretch(1)
            value = _label("-")
            self.info_labels[key] = value
            row.addWidget(value)
            ilay.addLayout(row)
        self.drop_hint = _label(
            "Tip: drag & drop a CSV/JSON signature file anywhere on this page "
            "to import it (offline-friendly).", role="warn")
        ilay.addWidget(self.drop_hint)
        lay.addWidget(info_card)
        lay.addStretch(1)

        self.btn_quick.clicked.connect(lambda: self._start_scan("quick"))
        self.btn_full.clicked.connect(lambda: self._start_scan("full"))
        self.btn_update_sigs.clicked.connect(self._update_sigs)
        self.btn_import_sigs.clicked.connect(self._import_sigs)
        self.chk_auto_clean.toggled.connect(self._toggle_auto_clean)
        self.chk_rt.toggled.connect(self._toggle_rt)
        self.chk_auto_sigs.toggled.connect(self._toggle_auto_sigs)
        self.chk_auto_scan.toggled.connect(self._toggle_auto_scan)
        self.chk_auto_repair.toggled.connect(self._toggle_auto_repair)
        self.cmb_policy.activated.connect(self._on_policy_changed)
        self.chk_autostart.toggled.connect(self._on_autostart_toggled)
        self.cmb_retention.activated.connect(self._on_retention_changed)
        self.spin_purge_days.valueChanged.connect(self._on_purge_days_changed)
        self.cmb_on_detection.activated.connect(self._on_on_detection_changed)

    # ------------------------------------------------------------ drag & drop
    def dragEnterEvent(self, event) -> None:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if any(str(u.toLocalFile()).lower().endswith((".csv", ".json", ".txt"))
               for u in urls):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        paths = [u.toLocalFile() for u in urls
                 if u.toLocalFile().lower().endswith((".csv", ".json", ".txt"))]
        if paths:
            self._run_import(paths)

    # ------------------------------------------------------------------- state
    def refresh(self) -> None:
        from . import systemutils

        has_sigs = self.win.ctx.db.count_signatures() > 0
        watcher_active = bool(self.win.watcher is not None and self.win.watcher.is_running())
        protected = has_sigs and watcher_active

        self.status_dot.setStyleSheet(
            "color: #2ECC71; font-size: 34px;" if protected
            else "color: #F0A020; font-size: 34px;")
        self.status_label.setText("Protected" if protected else "At Risk")
        self.status_detail.setText(
            "Signatures loaded and USB watcher armed." if protected
            else "Load signatures (Update Signatures) and the watcher is armed.")

        self.info_labels["signatures"].setText(
            str(self.win.ctx.db.count_signatures()))
        self.info_labels["drives_fixed"].setText(str(len(systemutils.fixed_drive_paths())))
        self.info_labels["drives_removable"].setText(str(len(systemutils.removable_drive_paths())))
        self.info_labels["drives_external"].setText(str(len(systemutils.external_drive_paths())))
        last = self.win.ctx.cfg.get("sig_last_update")
        self.info_labels["last_update"].setText(str(last or "never"))
        hours = float(self.win.ctx.cfg.get("auto_update_interval_hours", 6) or 0)
        self.info_labels["update_interval"].setText(
            f"every {hours:g} h" if hours > 0 else "off")
        self.info_labels["backend"].setText(self._watcher_backend())
        self.info_labels["watching"].setText("Armed" if watcher_active else "Idle")
        try:
            purge = self.win.ctx.db.auto_purge_stats()
            self.info_labels["auto_purged_freed"].setText(
                f"{purge.get('files', 0)} file(s), {_human_bytes(purge.get('bytes', 0))}")
        except Exception:
            self.info_labels["auto_purged_freed"].setText("-")
        self.refresh_last_scan()
        self.refresh_rt()

    def refresh_last_scan(self) -> None:
        """Persistent 'Last scan' card: survives navigation + restart."""
        try:
            row = self.win.ctx.db.last_scan_summary()
        except Exception:
            crashguard.report_exception(
                "dash-last-scan", sys.exc_info()[1], sys.exc_info()[2])
            row = None
        fresh = bool(row)
        findings = int(row.get("findings", 0) or 0) if fresh else 0
        started = str(row.get("started", "")) if fresh else ""
        self.last_scan_meta.setText(
            f"Last scan: {findings} finding(s)" +
            (f" - {started}" if started else ""))
        # keep the payload so 'View Results' can repoen the same browser
        self._last_scan_meta = (row.get("scan_id"), started, findings) if fresh else None
        self.btn_view_results.setEnabled(fresh)
        if fresh:
            self.btn_view_results.setToolTip(
                f"View finding results for scan {row.get('scan_id')}")

    def _open_last_scan(self) -> None:
        meta = self._last_scan_meta
        if meta is None:
            return
        scan_id = meta[0]
        if scan_id:
            self.win.open_findings(scan_id=scan_id,
                                   title=f"Last Scan Results ({scan_id})")
        else:
            self.win.publish("Last scan has no recorded findings to view.")

    def refresh_rt(self) -> None:
        rt = self.win.rt_monitor
        cfg_on = bool(self.win.ctx.cfg.get("rt_enabled", False))
        rt_on = bool(rt is not None and rt.is_enabled())
        self.chk_rt.blockSignals(True)
        self.chk_rt.setChecked(rt_on or cfg_on)
        self.chk_rt.blockSignals(False)
        if not rt_on:
            self.info_labels["realtime"].setText(
                "Pending" if cfg_on else "Off (not enabled)")
            return
        try:
            st = rt.status()
            roots = st.get("roots_watched") or []
            paused = bool(st.get("paused"))
            detail = "Active"
            if roots:
                detail += f" - watching {len(roots)} root(s): {', '.join(roots[:3])}"
            if paused:
                detail += " (throttled)"
            self.info_labels["realtime"].setText(detail)
        except Exception:
            crashguard.report_exception(
                "rt-dash-refresh", sys.exc_info()[1], sys.exc_info()[2])

    def set_rt_active(self, active: bool) -> None:
        self.chk_rt.blockSignals(True)
        self.chk_rt.setChecked(bool(active))
        self.chk_rt.blockSignals(False)
        self.refresh_rt()

    def set_rt_detected(self, text: str) -> None:
        self.status_detail.setText(text)
        self.status_label.setText("Real-time flag")

    def _watcher_backend(self) -> str:
        try:
            return provider.usb_backend_name()
        except Exception:
            return "unknown"

    def _populate_drive_combo(self) -> None:
        from .systemutils import drive_display, drive_volume_label, external_drive_paths

        current = self._current_drive_combo()
        block = self.drive_combo.signalsBlocked()
        self.drive_combo.blockSignals(True)
        self.drive_combo.clear()
        self.drive_combo.addItem("All drives")
        for path in external_drive_paths():
            self.drive_combo.addItem(drive_display(path), str(path))
            index = self.drive_combo.count() - 1
            tip = f"{path} - volume '{drive_volume_label(path) or '?'}' ({drive_display(path).split(' - ', 1)[-1]})"
            self.drive_combo.setItemData(index, tip, Qt.ItemDataRole.ToolTipRole)
        if current is not None:
            current_index = self.drive_combo.findData(current)
            if current_index >= 0:
                self.drive_combo.setCurrentIndex(current_index)
            else:
                self.drive_combo.setCurrentIndex(0)
        self.drive_combo.blockSignals(block)

    def _current_drive_combo(self) -> Optional[str]:
        idx = self.drive_combo.currentIndex()
        if idx > 0 and self.drive_combo.itemData(idx):
            return str(self.drive_combo.itemData(idx))
        return None

    # ------------------------------------------------------------------- actions
    def _start_scan(self, kind: str) -> None:
        from .scanner import ScanOptions

        picked = self._current_drive_combo()
        if picked:
            targets = [picked]
        elif kind == "quick":
            from .systemutils import quick_scan_targets
            targets = quick_scan_targets()
        else:
            from .systemutils import full_scan_targets
            targets = full_scan_targets()
        options = ScanOptions().with_overrides(max_depth=0)
        options.threads = int(self.win.ctx.cfg.get("scan_threads", 0))
        self.win.publish(f"Starting {kind} scan...")
        self.win.stack.setCurrentWidget(self.win.scanner_page)
        self.win.scanner_page.start_scan(targets, options, label=f"{kind.title()} scan")

    def _toggle_auto_clean(self, checked: bool) -> None:
        self.win.ctx.cfg.set("usb_auto_clean", bool(checked))
        self.win.ctx.cfg.save()
        self.win.debug_log("toggle_usb_auto_clean", command=f"checked={bool(checked)}")
        self.win._notify("USB auto-clean",
                         "Armed: new USB drives will be scanned and cleaned automatically."
                         if checked else "Disabled.")
        self.refresh()

    def _toggle_rt(self, checked: bool) -> None:
        self.win.debug_log("toggle_rt", command=f"rt_enabled={bool(checked)}")
        if checked:
            self.win._start_rt()
        else:
            self.win._stop_rt()
        self.win._notify("Real-time protection",
                         "Armed: files will be scanned the instant they change."
                         if checked else "Disabled.")
        self.refresh_rt()

    def _toggle_auto_sigs(self, checked: bool) -> None:
        self.win.ctx.cfg.set("auto_sigs_on_startup", bool(checked))
        self.win.ctx.cfg.save()
        self.refresh()

    def _toggle_auto_scan(self, checked: bool) -> None:
        self.win.ctx.cfg.set("auto_scan_on_startup", bool(checked))
        self.win.ctx.cfg.save()
        self.refresh()

    def _toggle_auto_repair(self, checked: bool) -> None:
        self.win.ctx.cfg.set("auto_repair", bool(checked))
        self.win.ctx.cfg.save()
        self.refresh()

    def _on_policy_changed(self, index: int) -> None:
        value = str(self.cmb_policy.itemData(index))
        self.win.ctx.cfg.set("auto_action_policy", value)
        self.win.ctx.cfg.save()
        self.win.debug_log("toggle_policy", command=f"auto_action_policy={value!r}")
        self.win._notify("Automatic service",
                         {"auto": "Full auto mode: disinfect / quarantine silently.",
                          "prompt": "Prompt mode: you will be asked before anything "
                                    "is changed.",
                          "off": "Scan-only mode: findings reported, never touched."}[value])

    def _on_retention_changed(self, index: int) -> None:
        value = str(self.cmb_retention.itemData(index))
        self.win.ctx.cfg.set("quarantine_retention_mode", value)
        self.win.ctx.cfg.save()
        self.spin_purge_days.setEnabled(value == "purge_after_days")
        self.win.debug_log("toggle_retention",
                           command=f"quarantine_retention_mode={value!r}")
        self.win._notify(
            "Quarantine retention",
            {"keep_forever": "Threat artifacts are kept indefinitely for manual "
                             "review (no automatic deletion).",
             "auto_purge_verified": "Pure-malware files (the default setting) "
                                   "are deleted and their verified backups "
                                   "auto-purged; anything doubtful falls back "
                                   "to Quarantine.",
             "purge_after_days": f"Quarantined items older than "
                                 f"{self.spin_purge_days.value()} days are purged "
                                 "by the background sweep."}[value])

    def _on_on_detection_changed(self, index: int) -> None:
        value = str(self.cmb_on_detection.itemData(index))
        self.win.ctx.cfg.set("on_detection", value)
        self.win.ctx.cfg.save()
        self.win.debug_log("toggle_on_detection",
                           command=f"on_detection={value!r}")
        self.win._notify(
            "Default finding action",
            {"resolve": "Findings are resolved in place when a safe strip point "
                        "exists; the rest goes to Quarantine.",
             "quarantine": "Old behavior: every finding is moved to Quarantine "
                           "for review - never resolved in place."}[value])

    def _on_purge_days_changed(self, value: int) -> None:
        self.win.ctx.cfg.set("purge_after_days", int(value))
        self.win.ctx.cfg.save()

    def _on_autostart_toggled(self, checked: bool) -> None:
        ok = set_autostart(bool(checked))
        self.win.ctx.cfg.set("start_with_windows", bool(checked))
        self.win.ctx.cfg.save()
        self.win.debug_log("toggle_autostart",
                           command=f"start_with_windows={bool(checked)} ok={ok}")
        if not ok:
            self.chk_autostart.blockSignals(True)
            self.chk_autostart.setChecked(not checked)
            self.chk_autostart.blockSignals(False)
            self.win._notify("Start with Windows",
                             "Could not update the registry Run key (needs no admin "
                             "for HKCU - check logging).")

    def _update_sigs(self) -> None:
        self.win.scanner_page.log_notice("Updating malware signatures (online feeds)...")
        self.win.debug_log("update_signatures",
                           command="OnlineUpdater.update_all()")
        updater = self.win.ctx.make_updater()
        worker = ActionWorker(
            fn=lambda: updater.update_all(),
            progress_label="Fetching signature feeds...")
        worker.finished_sig.connect(self._on_sig_update_done)
        worker.progress_sig.connect(self.win.publish_current)
        self.win._track_qt_thread(worker)
        worker.start()

    def _on_sig_update_done(self, stats: dict) -> None:
        if stats.get("error"):
            self.win._notify("Signature update", f"Update failed: {stats['error']}",
                             kind=KIND_SIGNATURE)
        elif stats.get("status") == "ok":
            self.win._notify("Signature update",
                             f"Added {stats['added']} of {stats['sig_offered']} "
                             f"signatures across {stats['feeds']} feed(s).",
                             kind=KIND_SIGNATURE)
            self.win.publish(f"Signature update: {stats['added']} new hashes added.")
        elif stats.get("status") == "degraded":
            self.win._notify("Signature update",
                             f"Partial: +{stats['added']} from {stats['feeds']} feed(s), "
                             f"{len(stats['errors'])} error(s).",
                             kind=KIND_SIGNATURE)
            self.win.publish(f"Signature update (partial): +{stats['added']} hashes.")
        else:
            detail = (stats.get("feeds_detail") or [{}])[0]
            self.win._notify("Signature update",
                             f"{detail.get('status', 'failed')}: "
                             f"{detail.get('errors', ['unknown'])[0] if isinstance(detail.get('errors'), list) else 'no data'}",
                             kind=KIND_SIGNATURE)
        self.refresh()

    def _import_sigs(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self, "Import signature files (offline)", "",
            "Signature files (*.csv *.json *.txt);;All files (*)")
        if files:
            self._run_import(files)

    def _run_import(self, files: List[str]) -> None:
        paths = [str(Path(p)) for p in files]
        self.win.debug_log("import_signatures",
                           command="OnlineUpdater.import_files()",
                           target=paths, dry_run=False)
        updater = self.win.ctx.make_updater()
        worker = ActionWorker(
            fn=lambda: updater.import_files(paths),
            progress_label=f"Importing {len(paths)} signature file(s)...")
        worker.finished_sig.connect(self._on_import_done)
        worker.progress_sig.connect(self.win.publish_current)
        self.win._track_qt_thread(worker)
        worker.start()

    def _on_import_done(self, stats: dict) -> None:
        if stats.get("error"):
            self.win._notify("Signature import", f"Import failed: {stats['error']}",
                             kind=KIND_SIGNATURE)
        elif stats.get("status") == "ok":
            self.win._notify("Signature import",
                             f"Added {stats['added']} of {stats['sig_offered']} "
                             f"signatures from {stats['feeds']} file(s).",
                             kind=KIND_SIGNATURE)
            self.win.publish(f"Signature import: +{stats['added']} hashes.")
        elif stats.get("status") == "degraded":
            self.win._notify("Signature import",
                             f"Partial: +{stats['added']} from {stats['feeds']} file(s), "
                             f"{len(stats['errors'])} error(s).",
                             kind=KIND_SIGNATURE)
        self.refresh()


# ------------------------------------------------------------------ scanner page
class FindingsTable(QTableWidget):
    """Reusable findings results-table component (Scanner tab + Findings
    Results viewer + Notification-center jumps).

    Columns: Confidence | Category | Threat | File.  ``set_findings`` accepts
    the same dict rows the scanner produces (path / category / name /
    confidence / evidence) so every surface renders identically.
    """

    def __init__(self, parent: QWidget = None) -> None:
        super().__init__(0, 4, parent)
        self.setHorizontalHeaderLabels(
            ["Confidence", "Category", "Threat", "File"])
        self.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch)
        self.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

    def set_findings(self, rows: List[dict]) -> None:
        self.setRowCount(0)
        for row_idx, f in enumerate(rows or []):
            self.insertRow(row_idx)
            self._fill_cell(row_idx, 0, f"{f.get('confidence', 0):.2f}",
                            center=True)
            self._fill_cell(row_idx, 1, f.get("category", ""))
            self._fill_cell(row_idx, 2, f.get("name", f.get("threat_name", "")))
            self._fill_cell(row_idx, 3, str(f.get("path", "")))
            if f.get("evidence"):
                item = self.item(row_idx, 3)
                if item is not None:
                    item.setToolTip(str(f["evidence"]))

    def _fill_cell(self, row: int, col: int, text: str,
                   center: bool = False) -> None:
        item = QTableWidgetItem(text)
        if center:
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(row, col, item)


class ScannerPage(QWidget):
    """Scan button state is driven purely by worker signals (bug #4):
    ``scan_started`` -> "Scanning..." disabled + Stop enabled,
    ``scan_finished`` / ``scan_stopped`` -> back to "Start Scan"."""

    scan_started = pyqtSignal()
    scan_finished = pyqtSignal(dict)
    scan_stopped = pyqtSignal(dict)

    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        self.worker = None
        self._pending_scans: list = []   # queue-on-conflict; drained on finish
        self._run_started = 0.0

        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        target_row = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Folders or drive root to scan (e.g. F:\\)")
        self.target_combo = QComboBox()
        self.target_combo.setMinimumWidth(230)
        self.target_combo.setToolTip("Quick pick an external drive (SSD/HDD/flash)")
        self.target_combo.currentIndexChanged.connect(self._drive_picked)
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._browse)
        self.btn_start = QPushButton("Start Scan")
        self.btn_start.setProperty("primary", True)
        self.btn_start.clicked.connect(lambda: self._start_selected())
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setProperty("danger", True)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        target_row.addWidget(self.target_combo)
        target_row.addWidget(self.target_edit, 1)
        target_row.addWidget(btn_browse)
        target_row.addWidget(self.btn_start)
        target_row.addWidget(self.btn_stop)
        lay.addLayout(target_row)

        self._populate_drive_combo()

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        lay.addWidget(self.progress)

        info_row = QHBoxLayout()
        self.lbl_current = _label("No scan running", muted=True)
        self.lbl_stats = _label("0 files", muted=True)
        info_row.addWidget(self.lbl_current, 1)
        info_row.addWidget(self.lbl_stats)
        lay.addLayout(info_row)

        self.findings_table = FindingsTable()
        lay.addWidget(self.findings_table, 2)

        # Plain-language report + expandable technical details (bug #6).
        self.report_card = _card(self)
        rlay = QVBoxLayout(self.report_card)
        self.summary_view = QTextEdit()
        self.summary_view.setReadOnly(True)
        self.summary_view.setMaximumHeight(110)
        self.summary_view.setPlaceholderText(
            "A plain-language report of the last scan appears here.")
        rlay.addWidget(self.summary_view)
        btn_row = QHBoxLayout()
        self.btn_details = QPushButton("Show Technical Details")
        self.btn_details.setCheckable(True)
        self.btn_details.toggled.connect(self._toggle_details)
        btn_row.addWidget(self.btn_details)
        btn_row.addStretch(1)
        rlay.addLayout(btn_row)
        self.details_view = QTextEdit()
        self.details_view.setReadOnly(True)
        self.details_view.setVisible(False)
        self.details_view.setMaximumHeight(180)
        rlay.addWidget(self.details_view)
        lay.addWidget(self.report_card, 1)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(90)
        self.log_view.setPlaceholderText("Event log for this console-less build.")
        lay.addWidget(self.log_view)

        # Worker signals drive EVERYTHING about the button state.
        self.scan_started.connect(lambda: self._apply_scan_state(True))
        self.scan_finished.connect(self._on_done)
        self.scan_stopped.connect(self._on_stopped)

    # ------------------------------------------------------------------ state
    def _apply_scan_state(self, running: bool) -> None:
        """Single place that flips the scan/stop buttons (bug #4)."""
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)
        self.btn_start.setText("Scanning..." if running else "Start Scan")

    def _toggle_details(self, checked: bool) -> None:
        self.details_view.setVisible(checked)
        self.btn_details.setText("Hide Technical Details" if checked
                                 else "Show Technical Details")

    # ------------------------------------------------------------------- controls
    def start_scan(self, targets: List[str], options, label: str) -> None:
        # Queue-on-conflict: a scan request arriving while one is running is
        # queued (never coalesced onto or interrupting the in-flight worker);
        # it starts automatically once the current worker fully finishes and
        # its wrapper reference has been dropped.
        if self._scan_busy():
            self._pending_scans.append([list(targets), options, label or "scan"])
            self.log_notice(
                f"A scan is already running - queued {label or 'scan'} on "
                f"{len(targets)} target(s); it will start when the current "
                f"scan finishes.")
            self.win.publish_current("Waiting for the current scan to finish")
            return
        self._launch_scan(targets, options, label)

    def _scan_busy(self) -> bool:
        """Defensive isRunning() read: a finished/GC'd C++ wrapper must read
        as not-busy, never raise RuntimeError from a GUI-thread read site."""
        w = self.worker
        if w is None:
            return False
        try:
            return w.isRunning()
        except RuntimeError:   # wrapped C/C++ object of type ScanWorker deleted
            self.worker = None  # drop the stale wrapper entirely
            return False

    def _launch_scan(self, targets: List[str], options, label: str) -> None:
        from .scanner import ScanOptions

        self._reset_scan_state()
        self._run_started = time.time()
        self.log_notice(f"Starting {label or 'scan'} on {len(targets)} target(s): "
                        f"{', '.join(targets)}")
        self.win.debug_log("scan_start", command="Scanner.scan()",
                           target=targets)
        worker = ScanWorker(self.win.ctx.db, options, targets)
        worker.progress_sig.connect(self._on_progress)
        worker.scan_started.connect(self.scan_started)
        worker.scan_finished.connect(self.scan_finished)
        worker.scan_stopped.connect(self.scan_stopped)
        worker.finished.connect(self._scan_worker_thread_finished)
        self.win._track_qt_thread(worker)
        self.worker = worker
        worker.start()

    def _reset_scan_state(self) -> None:
        """Drive-switch safety: explicitly reset ALL per-scan state so a new
        target never shows the previous drive's findings / progress / target
        label / activity-feed references."""
        try:
            self.findings_table.setRowCount(0)
        except Exception:
            pass
        self.summary_view.clear()
        self.details_view.clear()
        try:
            self.btn_details.setChecked(False)
        except Exception:
            pass
        try:
            self.progress.setRange(0, 0)   # indeterminate: total size unknown
            self.progress.reset()
        except Exception:
            pass
        try:
            self.lbl_current.setText("Scanning: ...")
            self.lbl_stats.clear()
        except Exception:
            pass
        self.win.publish_current("Starting a new scan...")

    def _scan_worker_thread_finished(self) -> None:
        """QThread finished -> GUI thread (queued).  DROP the wrapper FIRST so
        no later read can touch a deleted C++ object, THEN deleteLater() the
        finished QThread (canonical Qt pattern).  After cleanup, auto-start
        any scan that was queued while this one was running."""
        q = self.sender()
        if self.worker is q:
            self.worker = None      # (1) drop the reference FIRST
            if q is not None:
                q.deleteLater()     # (2) then release the finished C++ object
        if q is not None:
            self.win._forget_qt_thread(q)
        self._drain_pending_scan()

    def _drain_pending_scan(self) -> None:
        if not self._pending_scans:
            return
        targets, options, label = self._pending_scans.pop(0)
        self.log_notice(f"Auto-starting queued scan: {label or 'scan'}")
        self._launch_scan(targets, options, label)

    def _drive_picked(self, index: int) -> None:
        path = self.target_combo.itemData(index)
        if path:
            self.target_edit.setText(str(path))

    def _populate_drive_combo(self) -> None:
        from .systemutils import drive_display, drive_volume_label, external_drive_paths

        current = self._current_drive_combo()
        block = self.target_combo.signalsBlocked()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self.target_combo.addItem("Drives...")
        for path in external_drive_paths():
            self.target_combo.addItem(drive_display(path), str(path))
            index = self.target_combo.count() - 1
            label = drive_volume_label(path)
            tip = f"{path} - volume '{label or '?'}' ({drive_display(path).split(' - ', 1)[-1]})"
            self.target_combo.setItemData(
                index, tip, Qt.ItemDataRole.ToolTipRole)
        if current is not None:
            target_index = self.target_combo.findData(current)
            if target_index >= 0:
                self.target_combo.setCurrentIndex(target_index)
            else:
                self.target_combo.setCurrentIndex(0)
        self.target_combo.blockSignals(block)

    def _current_drive_combo(self) -> Optional[str]:
        idx = self.target_combo.currentIndex()
        if idx > 0 and self.target_combo.itemData(idx):
            return str(self.target_combo.itemData(idx))
        return None

    def _start_selected(self) -> None:
        raw = self.target_edit.text().strip().strip('"')
        if not raw:
            self.log_notice("Pick a folder/drive first (or use Quick/Full Scan).")
            self.win.debug_log("scan_aborted", command="no target")
            return
        from .scanner import ScanOptions
        from .systemutils import is_valid_drive_root, logical_drive_strings

        options = ScanOptions().with_overrides(max_depth=0)
        options.threads = int(self.win.ctx.cfg.get("scan_threads", 0))
        if not os.path.isdir(raw) and not is_valid_drive_root(raw):
            self.log_notice(f"Invalid target: {raw!r} is not a mounted drive. "
                            f"Drives: {', '.join(logical_drive_strings())}")
            self.win.debug_log("scan_invalid_target", target=raw)
            return
        self.win.debug_log("scan_custom_target", target=raw)
        self.start_scan([raw], options, label="custom-target")

    def _browse(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Choose folder or drive root")
        if selected:
            self.target_edit.setText(selected)

    def _stop(self) -> None:
        w = self.worker
        if w is None:
            return
        try:
            if not w.isRunning():
                return
            w.cancel()
            w.wait(1500)
            self.log_notice("Scan stop requested.")
        except RuntimeError:      # wrapper already deleted - nothing to stop
            self.worker = None

    # ------------------------------------------------------------------- signals
    def _on_progress(self, info: dict) -> None:
        self.lbl_current.setText(f"Scanning: {info.get('path', '')}")
        files = info.get("files_seen", 0)
        elapsed = info.get("elapsed_s", 0.0)
        speed = (files / elapsed) if elapsed > 0 else 0.0
        mb = info.get("bytes_scanned", 0) / (1024 * 1024)
        self.lbl_stats.setText(
            f"{files} files | {mb:.1f} MB | {speed:.0f} files/s "
            f"| {info.get('findings', 0)} findings")
        self.win.publish_current(
            f"Scanning {info.get('path', '?')} - "
            f"{files:,}/{max(files, 1)} files, {info.get('findings', 0)} finding(s)")

    def _on_done(self, summary: dict) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self._apply_scan_state(False)
        if summary.get("cancelled"):
            self.scan_stopped.emit(summary)
            self.log_notice("Scan cancelled.")
            return
        if summary.get("error"):
            self.log_notice(f"Scan error: {summary['error']}")
            return
        self.lbl_stats.setText(f"{summary['files']} files | "
                               f"{summary['bytes'] / 1e6:.1f} MB | "
                               f"{summary['duration_s']:.1f}s | "
                               f"{summary['findings']} findings")
        self.findings_table.set_findings(summary.get("finding_rows", []))
        self.log_notice(f"Scan {summary.get('scan_id', '?')} complete - "
                        f"{summary['findings']} finding(s), "
                        f"{summary.get('persisted', 0)} persisted.")
        self.win.dashboard.refresh()

        report = build_report(summary, finding_rows=summary.get("finding_rows"),
                              scan_id=summary.get("scan_id"))
        self.summary_view.setPlainText(report["plain"])
        self.details_view.setPlainText(report["detailed"])
        self.win.publish(report["plain"],
                         payload={"scan_id": summary.get("scan_id"),
                                  "findings": summary.get("findings", 0),
                                  "files": summary.get("files", 0)})
        self.win.save_scan_summary(summary)
        self.win._notify(
            "Scan complete",
            f"{summary.get('files', 0)} files, "
            f"{summary.get('findings', 0)} finding(s)",
            kind=KIND_SCAN,
            payload={"scan_id": summary.get("scan_id"),
                     "findings": summary.get("findings", 0)})
        self.win._mark_scan_finished()
        # bug #7: never act on findings without asking (even in auto flow the
        # auto-worker already surfaced its own summary on completion).
        QTimer.singleShot(0, lambda: self.win._offer_post_scan_actions(summary))

    def _on_stopped(self, summary: dict) -> None:
        self._apply_scan_state(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.log_notice("Scan stopped.")
        self.win.publish("Scan stopped by the user.")
        self.win._mark_scan_finished()

    def log_notice(self, text: str) -> None:
        self.log_view.append(f"[{time.strftime('%H:%M:%S')}] {text}")


# ------------------------------------------------- post-scan dialog (bug #7)
class PostScanActionsDialog(QDialog):
    """Modal choice right when a scan finds something - no silent actions.

    Returns ('clean' | 'quarantine' | 'ignore' | 'review') via ``exec()``.
    """

    def __init__(self, win: MainWindow, summary: dict) -> None:
        super().__init__(win)
        self.win = win
        self._decision = "ignore"
        self.setWindowTitle("SecuDrive - scan finished with findings")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        report = build_report(summary, finding_rows=summary.get("finding_rows"),
                              scan_id=summary.get("scan_id"))
        head = _label("What should SecuDrive do with these findings?",
                      bold=True)
        lay.addWidget(head)

        body = QTextEdit()
        body.setReadOnly(True)
        body.setPlainText(report["plain"])
        body.setMaximumHeight(120)
        lay.addWidget(body)

        btn_row = QHBoxLayout()
        b_clean = QPushButton("Clean All")
        b_clean.setProperty("primary", True)
        b_quar = QPushButton("Quarantine All")
        b_quar.setProperty("accent", True)
        b_review = QPushButton("Review Individually")
        b_ign = QPushButton("Ignore (keep files)")
        for btn, val in ((b_clean, "clean"), (b_quar, "quarantine"),
                         (b_review, "review"), (b_ign, "ignore")):
            btn.clicked.connect(lambda _c=False, v=val: self._choose(v))
            btn_row.addWidget(btn)
        btn_row.addStretch(1)
        lay.addLayout(btn_row)
        lay.addWidget(_label(
            "Everything happens through an encrypted backup first "
            "(Zero Data Loss) - nothing is ever deleted before a verified "
            "copy exists.", muted=True))

    def _choose(self, decision: str) -> None:
        self._decision = decision
        self.accept()

    def exec(self) -> str:  # noqa: A003 - Qt API name
        super().exec()
        return self._decision


class ScanSummaryDialog(QDialog):
    """Non-modal summary surfaced after auto-mode or post-scan actions (bug #7)
    - auto-mode is never fully silent.  Includes an Open Quarantine button."""

    def __init__(self, win: MainWindow, plain: str, body: str = "",
                 findings: int = 0) -> None:
        super().__init__(win)
        self.win = win
        self.setWindowTitle("SecuDrive - summary")
        self.setModal(False)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(_label("Scan summary", bold=True))
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setPlainText(plain or body or "Done.")
        txt.setMaximumHeight(130)
        lay.addWidget(txt)
        row = QHBoxLayout()
        if findings > 0:
            b_open = QPushButton("Open Quarantine")
            b_open.clicked.connect(self._open_quarantine)
            row.addWidget(b_open)
        row.addStretch(1)
        b_close = QPushButton("Close")
        b_close.clicked.connect(self.close)
        row.addWidget(b_close)
        lay.addLayout(row)

    def _open_quarantine(self) -> None:
        self.win.quarantine.refresh()
        self.win.stack.setCurrentWidget(self.win.quarantine)


# -------------------------------------------------- quarantine restore tracing
_RLOG = get_logger("restore")


def _rlog(tag: str, *parts, **kw) -> None:
    """Tagged debug trace for the quarantine action chain (click -> worker ->
    item_status -> finished_sig -> refresh).  Grep console output for RESTORE|."""
    bits = [f"{k}={v}" for k, v in kw.items()]
    _RLOG.info("RESTORE|%s| %s", tag, " | ".join([str(parts[0])] + bits
                                                 if parts else bits))


# ------------------------------------------------------------------ quarantine
def _disinfect_quarantined(engine, uid: str) -> dict:
    """Restore a quarantined blob to its original path, then strip its appended
    payload via the disinfect path (backup + verify), in one user action."""
    rec = engine.restore_item(uid)
    if rec.get("status") != "restored":
        return {**rec, "status": "error",
                "reason": rec.get("reason", "restore failed before disinfect")}
    orig = rec.get("path") or rec.get("original_path")
    if not orig:
        return {**rec, "status": "error",
                "reason": "disinfect: restored item has no original path"}
    return engine.disinfect_file(Path(orig), dry_run=False)


class QuarantinePage(QWidget):
    """Quarantine & Recovery Manager with live, per-item action status.

    Deliverable #3: the Status column transitions Quarantined ->
    Restoring.../Disinfecting.../Deleting... (per-item spinner) -> Restored /
    Disinfected / Deleted, or a failure reason tooltip.  Multi-select runs each
    AND- indepdently via ItemActionWorker (concurrent, no single global
    spinner).  Rows that are already fully restored / deleted / disinfected can
    be dropped for the session with 'Remove from list' / 'Clear finished'.
    """

    COL_STATUS = 3
    COL_THREAT = 2

    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        self._state: Dict[str, dict] = {}      # uid -> {status, err}
        self._busy: Dict[str, str] = {}        # uid -> running verb; tombstone of spinner cells
        self._worker: Optional[ItemActionWorker] = None
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._spin_cycle)
        self._spins: Dict[str, float] = {}
        self._finished_filter: set = set()

        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(_label("Quarantine & Recovery Manager", bold=True))
        row.addStretch(1)
        btn_restore = QPushButton("Restore Clean File")
        btn_restore.setProperty("primary", True)
        btn_disinfect = QPushButton("Disinfect")
        btn_purge = QPushButton("Permanent Delete")
        btn_purge.setProperty("danger", True)
        btn_refresh = QPushButton("Refresh")
        btn_remove_finished = QPushButton("Remove finished from list")
        btn_clear_finished = QPushButton("Clear finished rows")
        btn_remove_finished.setToolTip(
            "Hides the SELECTED rows whose status is restored/deleted/"
            "disinfected/purged for this session only - nothing is deleted"
            " from the database or backups.")
        btn_clear_finished.setToolTip(
            "Hides EVERY row with a finished status (restored/deleted/"
            "disinfected/purged) for this session only - quarantined and"
            " failed rows are kept.  VIEW-ONLY: no data is deleted.")
        btn_restore.clicked.connect(lambda: self._run_verb("restore", "Restore"))
        btn_disinfect.clicked.connect(lambda: self._run_verb("disinfect", "Disinfect"))
        btn_purge.clicked.connect(lambda: self._run_verb("purge", "Delete"))
        btn_refresh.clicked.connect(self.refresh)
        btn_remove_finished.clicked.connect(self._remove_selected_finished)
        btn_clear_finished.clicked.connect(self._clear_finished_rows)
        row.addWidget(btn_restore)
        row.addWidget(btn_disinfect)
        row.addWidget(btn_purge)
        row.addWidget(btn_refresh)
        lay.addLayout(row)

        frow = QHBoxLayout()
        frow.addWidget(_label("Finished rows (restored/deleted/disinfected) can "
                              "be dropped for this session:", muted=True))
        frow.addWidget(btn_remove_finished)
        frow.addWidget(btn_clear_finished)
        frow.addStretch(1)
        lay.addLayout(frow)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["UID", "Original Path", "Threat", "Status", "Size (B)", "Created"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(self.table, 1)

        self.status_label = _label("", muted=True)
        lay.addWidget(self.status_label)
        # bug #8: "Last synced" - history always reloaded from secudrive.db here,
        # never a stale in-memory cache; this stamp proves the refresh happened.
        self.lbl_last_synced = _label("Last synced: never", muted=True)
        lay.addWidget(self.lbl_last_synced)

    # ------------------------------------------------------------------ refresh
    def refresh(self) -> None:
        items = self.win.ctx.db.list_quarantine()
        seen_uids: set = set()
        deduped: List[dict] = []
        for it in items:
            uid = str(it.get("uid") or "")
            if uid in seen_uids:
                continue   # defensive: never render duplicate rows (bug #8)
            seen_uids.add(uid)
            # running actions keep their transient UI state; everything else
            # reflects what secudrive.db actually contains right now.
            deduped.append(it)
        self.table.setRowCount(0)
        shown = 0
        for current, it in enumerate(deduped):
            uid = str(it.get("uid") or "")
            if self._finished_filter and uid in self._finished_filter:
                continue   # user asked to drop this finished row for the session
            # insert at the RUNNING visible index, not the enumerated one -
            # insertRow() with an index beyond rowCount() is a silent no-op,
            # so skipped rows would otherwise eat/mangle the visible rows.
            self.table.insertRow(shown)
            self._render_row(shown, it)
            if uid in self._busy:
                self._spin_row(uid)
            shown += 1
        self.status_label.setText(
            f"{self.table.rowCount()} item(s) shown of {len(deduped)} total.")
        self.lbl_last_synced.setText(
            f"Last synced: {time.strftime('%H:%M:%S')} - read live from "
            f"secudrive.db")
        self._spins = {}
        if self._busy and not self._refresh_timer.isActive():
            self._refresh_timer.start(180)
        elif not self._busy and self._refresh_timer.isActive():
            self._refresh_timer.stop()

    _finished_verbs = ("restored", "deleted", "disinfected", "purged")

    @classmethod
    def _is_finished_status(cls, status: str) -> bool:
        """True only for TERMINAL statuses (row's action is over and done).
        quarantined / failed / error rows are never 'finished' - they still
        need the user, so they can never be dropped by the clear actions."""
        return str(status or "").strip().lower() in cls._finished_verbs

    def _render_row(self, row_idx: int, it: dict) -> None:
        uid = str(it.get("uid") or "")
        status = str(it.get("status") or "quarantined")
        display = status.title() if status in ("quarantined", "restored") else status
        # NOTE: full uid rides in UserRole (the visible column shows its
        # 10-char prefix); recovery keys are the FULL 32-hex uid - truncating
        # what we SELECT later is exactly the bug this page used to have.
        cell_uid = QTableWidgetItem(uid[:10])
        cell_uid.setData(Qt.ItemDataRole.UserRole, uid)
        cell_uid.setToolTip(f"Quarantine uid: {uid}")
        self.table.setItem(row_idx, 0, cell_uid)
        for col, val in enumerate((it.get("original_path") or "",
                                   it.get("threat_name") or "-",
                                   display,
                                   str(it["size"]) if it.get("size") else "-",
                                   it.get("created") or ""), start=1):
            i = QTableWidgetItem(val)
            if col == self.COL_THREAT:
                notes = str(it.get("notes") or "").strip()
                if notes:
                    i.setToolTip(notes)   # resolve attempt chain / analyst notes
            if col == self.COL_STATUS:
                i.setData(Qt.ItemDataRole.UserRole, uid)
                i.setForeground(self._status_color(status))
            self.table.setItem(row_idx, col, i)

    @staticmethod
    def _status_color(status: str) -> QColor:
        if status in ("restored", "deleted", "disinfected", "purged"):
            return QColor("#2ECC71")
        if status == "quarantined":
            return QColor("#F0A020")
        return QColor("#E74C3C")

    # ------------------------------------------------------------------ actions
    def _selected_rows(self) -> List[str]:
        """Read the FULL uid from UserRole (never the truncated display text)."""
        uids = []
        for idx in self.table.selectionModel().selectedRows():
            item = self.table.item(idx.row(), 0)
            if item is None:
                continue
            full = item.data(Qt.ItemDataRole.UserRole)
            uids.append(str(full) if full else item.text())
        return uids

    def _run_verb(self, verb: str, display: str) -> None:
        uids = self._selected_rows()
        _rlog("click->_run_verb", verb=verb, display=display,
              selected_count=len(uids), uids=uids)
        if not uids:
            _rlog("abort", "no selection", verb=verb)
            return self._warn(f"select a quarantined item to {display.lower()}.")
        if verb == "purge":
            if not self._confirm_purge(len(uids)):
                _rlog("abort", "purge not confirmed", verb=verb)
                return
        if self._worker is not None:
            try:
                if self._worker.isRunning():
                    _rlog("abort", "existing worker busy", worker=self._worker)
                    return self._warn(
                        "An action batch is already running - wait for it "
                        "to finish before starting another.")
            except RuntimeError:     # previous worker already released
                _rlog("cleanup", "stale worker wrapper dropped")
                self._worker = None
        engine = self.win.ctx.ensure_engine()
        tasks = [(uid, self._task_fn(engine, verb, uid)) for uid in uids]
        _rlog("tasks", count=len(tasks), verb=verb)
        self._worker = ItemActionWorker(tasks)
        self._worker.item_status.connect(self._on_item_status)
        self._worker.finished_sig.connect(self._actions_done)
        # QThread's OWN finished (queued after the true thread exit) drops the
        # wrapper FIRST then deleteLater()s the worker - same discipline as the
        # ScanWorker lifecycle so no stale C++ reference can ever be read.
        self._worker.finished.connect(self._batch_thread_finished)
        _rlog("signals", "item_status / finished_sig / QThread.finished wired")
        for uid in uids:
            self._busy[uid] = display
        self.refresh()
        _rlog("busy", busy=dict(self._busy))
        self.status_label.setText(
            f"{len(uids)} item(s): {display}ing... (per-item progress)")
        self.win.publish(f"Starting {display.lower()} of {len(uids)} item(s)...")
        _rlog("dispatch", "calling worker.start()")
        self._worker.start()
        _rlog("dispatch", "worker.start() returned without raising",
              worker=self._worker)

    def _batch_thread_finished(self) -> None:
        """QThread.finished for the action batch (GUI thread, guaranteed to run
        after the worker's run() has fully returned)."""
        q = self.sender()
        _rlog("QThread.finished->_batch_thread_finished", "sender", q=q,
              is_current=(self._worker is q))
        if self._worker is q:
            self._worker = None      # (1) drop the reference FIRST when current
        if q is not None:
            q.deleteLater()          # (2) finished C++ object is always safe to release
            self.win._forget_qt_thread(q)

    @staticmethod
    def _task_fn(engine, verb: str, uid: str):
        def _wrapped() -> dict:
            if verb == "restore":
                return engine.restore_item(uid)
            if verb == "disinfect":
                return _disinfect_quarantined(engine, uid)
            return engine.purge_item(uid)
        return _wrapped

    def _on_item_status(self, uid: str, info: dict) -> None:
        state = info.get("state")
        detail = info.get("detail", "")
        _rlog("item_status", uid=uid, state=state,
              detail=str(detail if not isinstance(detail, dict)
                         else detail.get("status", ""))[:160])
        # The worker reports "done" for every call that completed WITHOUT a
        # worker crash - but an engine-level failure (corrupt blob, missing
        # store, verify mismatch) still carries status == "error" in the rec.
        # That MUST paint the row as a red Failed with its reason, not a
        # generic green Done.
        if state == "done" and isinstance(detail, dict) \
                and detail.get("status") == "error":
            state = "error"
            detail = detail.get("reason") or detail.get("status") \
                or "action failed"
        self._state[uid] = {"status": state, "err": detail}
        if state == "done":
            self._busy.pop(uid, None)
        self._spin_row(uid)

    def _spin_cycle(self) -> None:
        for uid in list(self._busy):
            self._spins[uid] = self._spins.get(uid, 0) + 1
            self._spin_row(uid)

    def _spin_row(self, uid: str) -> None:
        for row in range(self.table.rowCount()):
            item = self.table.item(row, self.COL_STATUS)
            if item is None or item.data(Qt.ItemDataRole.UserRole) != uid:
                continue
            busy = self._busy.get(uid, "")
            if busy:
                verb = busy.lower()
                frame = r"\|/-"[int(self._spins.get(uid, 0) % 4)]
                item.setText(f"{verb}... {frame}")
                item.setForeground(QColor("#4C8BF5"))
                item.setToolTip(f"{verb} in progress...")
            elif self._state.get(uid, {}).get("status") == "error":
                err = self._state[uid].get("err", "action failed")
                item.setText("Failed")
                item.setForeground(QColor("#E74C3C"))
                item.setToolTip(_clamp_text(err, 200))
            elif self._state.get(uid, {}).get("status") == "done":
                item.setText("Done")
                item.setForeground(QColor("#2ECC71"))
                item.setToolTip("Action completed.")
        return

    def _actions_done(self, results) -> None:
        _rlog("finished_sig->_actions_done", results_count=len(results))
        self._busy.clear()
        self._spins.clear()
        if self._refresh_timer.isActive():
            self._refresh_timer.stop()
        errors = 0
        for r in results:
            res = r.get("result", {}) if isinstance(r, dict) else {}
            if isinstance(r, dict) and r.get("error"):
                errors += 1
                _rlog("result", "error", uid=r.get("key", "?"))
                self._warn(_clamp_text(r["error"], 220))
            elif isinstance(res, dict) and res.get("status") == "error":
                errors += 1
                _rlog("result", "engine-error",
                      uid=r.get("key", "?"), reason=res.get("reason", ""))
                self._warn(_clamp_text(
                    f"{res.get('status')}: {res.get('reason', '')}", 220))
            else:
                _rlog("result", "ok", uid=r.get("key", "?"),
                      status=res.get("status", "?"))
        total = len(results)
        ok = max(0, total - errors)
        # The dedicated QThread.finished handler (_batch_thread_finished) nulls
        # + deleteLater()s the worker after run() has truly returned; we do NOT
        # touch it here or the custom finished_sig (emitted a moment earlier,
        # inside run()) would race that cleanup on the GUI thread.
        self._state.clear()
        self.refresh()
        self.status_label.setText(
            f"{ok}/{total} succeeded." + (" All actions failed." if ok == 0 else ""))
        self.win.publish(f"Quarantine actions finished: {ok}/{total} succeeded.")
        _rlog("done", ok=ok, total=total,
              status_label=self.status_label.text())
        self._notify_done(ok, total)

    def _notify_done(self, ok: int, total: int) -> None:
        if total <= 0:
            return
        title = "Quarantine actions complete"
        body = f"{ok}/{total} succeeded."
        self.win._notify(title, body, kind=KIND_QUARANTINE)

    @staticmethod
    def _confirm_purge(count: int) -> bool:
        answer = QMessageBox.question(
            None, "Permanent delete",
            "This decrypts nothing - it erases the quarantined blob and its "
            "encrypted backup forever."
            + (f" ({count} item(s).)" if count > 1 else "") + " Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def _remove_selected_finished(self) -> None:
        """Drop the SELECTED rows from this session's view - only rows whose
        LIVE DB status is genuinely finished (restored/deleted/disinfected/
        purged).  Quarantined / failed rows are never hidden: they still need
        the user's attention."""
        hidden = skipped = 0
        by_uid = {str(it.get("uid") or ""):
                  str(it.get("status") or "quarantined")
                  for it in self.win.ctx.db.list_quarantine()}
        for idx in self.table.selectionModel().selectedRows():
            item = self.table.item(idx.row(), 0)
            if item is None:
                continue
            uid = str(item.data(Qt.ItemDataRole.UserRole) or "")
            if uid and self._is_finished_status(by_uid.get(uid, "")):
                self._finished_filter.add(uid)
                hidden += 1
            elif uid:
                skipped += 1
        self.refresh()
        if skipped:
            self._warn(f"{skipped} selected row(s) are not finished and were "
                       "kept - only restored/deleted/disinfected/purged rows "
                       "can be dropped.")
        if hidden:
            self.status_label.setText(
                f"Dropped {hidden} finished row(s) for this session.")

    def _clear_finished_rows(self) -> None:
        """Clear ALL finished rows from this session's list, using the LIVE DB
        statuses and ONLY the terminal set.  This is a VIEW-ONLY operation: the
        rows stay in secudrive.db and the encrypted backups / audit history
        remain intact - nothing is deleted from disk."""
        hidden = 0
        for it in self.win.ctx.db.list_quarantine():
            uid = str(it.get("uid") or "")
            if uid and self._is_finished_status(str(it.get("status") or "")):
                self._finished_filter.add(uid)
                hidden += 1
        self.refresh()
        self.status_label.setText(
            f"Hidden {hidden} finished row(s) for this session "
            "(rows stay in the DB; nothing deleted).")

    def _warn(self, message: str) -> None:
        QMessageBox.information(self, "Quarantine", message)


# ------------------------------------------------------------------ drive doctor
class DriveDoctorPage(QWidget):
    """Target binding is *strict*: every button re-reads the combo at click
    time, validates the drive, and surfaces any failure on-screen."""

    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win

        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        head.addWidget(_label("External Drive Doctor", bold=True))
        head.addStretch(1)
        self.cmb_drive = QComboBox()
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_drives)
        head.addWidget(_label("Target:", muted=True))
        head.addWidget(self.cmb_drive)
        head.addWidget(btn_refresh)
        lay.addLayout(head)
        self.lbl_volume = _label("", muted=False)
        self.lbl_volume.setWordWrap(True)
        lay.addWidget(self.lbl_volume)

        # Persistent DRY-RUN banner - unmistakable while set.
        self.lbl_dry = _label("  \u26a0  DRY RUN MODE ON  ", role="banner")
        self.lbl_dry.setVisible(False)
        lay.addWidget(self.lbl_dry)

        # On-screen error surface (never a silent fallback).
        self.lbl_err = _label("", role="error")
        self.lbl_err.setWordWrap(True)
        self.lbl_err.setVisible(False)
        lay.addWidget(self.lbl_err)

        actions = QHBoxLayout()
        btn_clean = QPushButton("Deep Clean")
        btn_clean.setProperty("primary", True)
        btn_reveal = QPushButton("Reveal Hidden Files")
        btn_immunize = QPushButton("Immunize")
        btn_scan = QPushButton("Quick Scan This Drive")
        btn_clean.clicked.connect(lambda: self._run("clean"))
        btn_reveal.clicked.connect(lambda: self._run("reveal"))
        btn_immunize.clicked.connect(lambda: self._run("immunize"))
        btn_scan.clicked.connect(lambda: self._run("scan-this"))
        actions.addWidget(btn_clean)
        actions.addWidget(btn_reveal)
        actions.addWidget(btn_immunize)
        actions.addWidget(btn_scan)
        actions.addStretch(1)
        self.chk_dry = QCheckBox("Dry run (no changes)")
        self.chk_dry.toggled.connect(lambda _c: self._sync_dry_banner())
        actions.addWidget(self.chk_dry)
        lay.addLayout(actions)

        self.result = QTextEdit()
        self.result.setReadOnly(True)
        self.result.setPlaceholderText("Drive Doctor reports appear here.")
        lay.addWidget(self.result, 1)

        self.refresh_drives()
        self.cmb_drive.currentIndexChanged.connect(self._update_target_label)

    # ------------------------------------------------------------------ drives
    def refresh_drives(self) -> None:
        from .systemutils import (drive_display, drive_volume_label,
                                  external_drive_paths)

        drives = external_drive_paths()
        keep = self._selected_target()

        self.cmb_drive.blockSignals(True)
        self.cmb_drive.clear()
        self.cmb_drive.setEnabled(True)
        if drives:
            for path in drives:
                idx = self.cmb_drive.count()
                self.cmb_drive.addItem(drive_display(path), str(path))
                label = drive_volume_label(path)
                if label:
                    self.cmb_drive.setItemData(
                        idx, f"{path} - volume '{label}'",
                        Qt.ItemDataRole.ToolTipRole)
            if keep and str(keep) in drives:
                t = self.cmb_drive.findData(str(keep))
                if t >= 0:
                    self.cmb_drive.setCurrentIndex(t)
                else:
                    self.cmb_drive.setCurrentIndex(0)
            else:
                self.cmb_drive.setCurrentIndex(0)
        else:
            self.cmb_drive.addItem("<no external drive detected>")
            self.cmb_drive.setEnabled(False)
        self.cmb_drive.blockSignals(False)
        self._sync_dry_banner()
        self._update_target_label()

    # ------------------------------------------------------------------ target
    def _selected_target(self) -> Optional[Path]:
        """The exact drive the combo holds - validated. None == invalid.

        Root fix for the old 'defaults to C:/Users/<user>' bug: there is no
        fallback path anywhere below; an invalid read aborts visibly."""
        idx = self.cmb_drive.currentIndex()
        if idx < 0 or not self.cmb_drive.isEnabled():
            return None
        path = self.cmb_drive.itemData(idx)
        if not path:
            return None
        from .systemutils import is_valid_drive_root
        if not is_valid_drive_root(str(path)):
            return None
        return Path(str(path))

    def _update_target_label(self) -> None:
        target = self._selected_target()
        if target is None:
            from .systemutils import logical_drive_strings
            self.lbl_volume.setText(
                "No valid target selected."
                + (f"  Mounted drives: {', '.join(logical_drive_strings())}"
                   if logical_drive_strings() else ""))
            return
        from .systemutils import drive_kind, drive_volume_label
        label = drive_volume_label(str(target))
        self.lbl_volume.setText(
            f"Target: {target}  -  {drive_kind(str(target))}"
            + (f"  (volume '{label}')" if label else ""))

    def _sync_dry_banner(self) -> None:
        dry = self.chk_dry.isChecked()
        self.lbl_dry.setVisible(dry)
        self.lbl_dry.setToolTip(
            "Dry run is ON: no file will be modified - actions are simulated only.")

    # ------------------------------------------------------------------ actions
    def _run(self, kind: str) -> None:
        engine = self.win.ctx.ensure_engine()

        # Bug #2 root fix: dry-run is READ from the toggle at click time, every
        # single execution - never a default True baked into the backend call.
        dry = self.chk_dry.isChecked()
        self._sync_dry_banner()

        # Bug #1 root fix: target re-read from the combo at click time.
        target = self._selected_target()
        if target is None:
            self.lbl_err.setText(
                "ERROR: no valid drive selected. Pick a drive from the list "
                "above - SecuDrive will never silently fall back to your home "
                "folder or any other default path.")
            self.lbl_err.setVisible(True)
            self.win.debug_log("drive_doctor_aborted",
                               command=f"{kind}()", target=None, dry_run=dry)
            return
        self.lbl_err.setVisible(False)

        if kind == "scan-this":
            from .scanner import ScanOptions
            options = ScanOptions().with_overrides(max_depth=0)
            options.threads = int(self.win.ctx.cfg.get("scan_threads", 0))
            self.win.debug_log("drive_doctor_action",
                               command="Scanner.scan(list={target})",
                               target=str(target), dry_run=dry)
            self.win.stack.setCurrentWidget(self.win.scanner_page)
            self.win.scanner_page.start_scan([str(target)], options,
                                             label="drive-scan")
            return

        command_by_kind = {
            "clean": f"RecoveryEngine.clean_external_drive({target}, dry_run={dry})",
            "reveal": f"RecoveryEngine.reveal_hidden({target}, dry_run={dry})",
            "immunize": f"immunizer.immunize({target})   [dry_run n/a - only creates "
                        f"a vaccinating autorun.inf DIRECTORY; never deletes]",
        }
        self.win.debug_log("drive_doctor_action",
                           command=command_by_kind[kind],
                           target=str(target), dry_run=dry)

        if kind == "reveal":
            fn = lambda: engine.reveal_hidden(target, dry_run=dry)
        elif kind == "clean":
            fn = lambda: engine.clean_external_drive(target, dry_run=dry)
        else:  # immunize
            from .immunizer import immunize
            fn = lambda: immunize(target)

        worker = ActionWorker(fn, progress_label=f"Drive Doctor: {kind} on {target}...")
        worker.finished_sig.connect(self._result_done)
        worker.progress_sig.connect(self.win.publish_current)
        self.win._track_qt_thread(worker)
        worker.start()

    def _result_done(self, rec) -> None:
        import json
        self.result.append(json.dumps(rec, indent=2, default=str)[:4000])
        self.win.quarantine.refresh()
        if isinstance(rec, dict) and rec.get("dry_run") is True:
            self.result.append("(dry run - nothing was modified)")
        self.win.publish("Drive Doctor action finished.")


# --------------------------------------------------------------------- logs
class LogsPage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        head.addWidget(_label("Logs & Audit Viewer", bold=True))
        head.addStretch(1)
        btn = QPushButton("Refresh")
        btn.clicked.connect(self.refresh)
        head.addWidget(btn)
        lay.addLayout(head)

        self.tabs = QStackedWidget()
        self.disinfect_table = QTableWidget(0, 6)
        self.disinfect_table.setHorizontalHeaderLabels(
            ["Time", "Action", "Status", "Path", "Size \u2192 Size", "Backup"])
        self.disinfect_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch)
        self.scan_table = QTableWidget(0, 5)
        self.scan_table.setHorizontalHeaderLabels(
            ["Time", "Category", "Threat", "Confidence", "File"])
        self.scan_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch)
        self.debug_view = QTextEdit()
        self.debug_view.setReadOnly(True)
        self.debug_view.setPlaceholderText(
            "Every GUI action is logged here and to secudrive_debug.log: the exact "
            "command constructed, the exact target path resolved, and the exact "
            "dry_run value.")
        for table in (self.disinfect_table, self.scan_table):
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tabs.addWidget(self.disinfect_table)
        self.tabs.addWidget(self.scan_table)
        self.tabs.addWidget(self.debug_view)
        lay.addWidget(self.tabs, 1)

        tabrow = QHBoxLayout()
        btn_d = QCheckBox("Disinfect log")
        btn_d.setChecked(True)
        btn_s = QCheckBox("Scan findings")
        btn_s.setChecked(True)
        btn_db = QCheckBox("GUI action debug")
        btn_db.setChecked(True)
        for check, target in ((btn_d, 0), (btn_s, 1), (btn_db, 2)):
            check.toggled.connect(lambda v, t=target: self._toggle_tab(t, v))
        tabrow.addWidget(btn_d)
        tabrow.addWidget(btn_s)
        tabrow.addWidget(btn_db)
        lay.addLayout(tabrow)

    def _toggle_tab(self, index: int, visible: bool) -> None:
        widget = self.tabs.widget(index)
        widget.setVisible(visible)

    def refresh(self) -> None:
        history = self.win.ctx.db.disinfect_history(500)
        self.disinfect_table.setRowCount(0)
        for row_idx, h in enumerate(history):
            self.disinfect_table.insertRow(row_idx)
            size_arrow = f"{h.get('size_before') or '-'} \u2192 {h.get('size_after') or '-'}"
            for col, val in enumerate((h["created"], h["action"], h["status"],
                                       h["path"], size_arrow,
                                       (h.get("backup_uid") or "-")[:10])):
                self.disinfect_table.setItem(row_idx, col, QTableWidgetItem(str(val)))

        findings = self.win.ctx.db.recent_findings(500)
        self.scan_table.setRowCount(0)
        for row_idx, f in enumerate(findings):
            self.scan_table.insertRow(row_idx)
            for col, val in enumerate((f["first_seen"], f["category"], f["threat_name"],
                                       f"{f['confidence']:.2f}", f["path"])):
                self.scan_table.setItem(row_idx, col, QTableWidgetItem(str(val)))


# -------------------------------------------------------------------- launcher
def launch_gui(base: Optional[Path] = None, argv: Optional[List[str]] = None) -> int:
    from .logging_utils import setup_logging

    ctx = RuntimeContext(base=base)
    debug_log = ctx.cfg.base_dir / "secudrive_debug.log"
    try:
        setup_logging(log_file=debug_log)
    except Exception:
        setup_logging()

    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("SecuDrive")

    # bug #1: install the process-wide crash nets BEFORE any worker thread can
    # start, so nothing can ever take the app down silently.
    crashguard.install_global_handlers()

    apply_dark_theme(app)

    window = MainWindow(ctx, base=base)
    window.show()
    window.debug_log("app_start", command="launch_gui",
                     target=ctx.cfg.base_dir)
    return app.exec()


# ------------------------------------------------------------------ helpers
def _autostart_enabled() -> bool:
    """True when SecuDrive is registered to run at login (via the provider)."""
    return provider.autostart_enabled()


def set_autostart(enabled: bool) -> bool:
    """Register/unregister SecuDrive at login (delegates to the provider)."""
    return provider.set_autostart(enabled)