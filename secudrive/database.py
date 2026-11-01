"""SQLite persistence layer - signatures, scan findings, quarantine, disinfect audit.

Thread-safe single-writer wrapper.  WAL mode + busy timeout keep concurrent
scanner / recovery components (and a future GUI thread) from dead-locking.

Schema overview:
    signatures       - SHA-256 / MD-5 malware signature table (seeded from vendor CSV)
    scan_findings    - every finding emitted by a scan (immutable audit trail)
    quarantine_items - original-file metadata + backup/encrypted store paths
    disinfect_log    - history of every strip / attribute / restore action
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .logging_utils import get_logger

logger = get_logger("database")


class DatabaseClosedError(RuntimeError):
    """Raised by the writer/reader helpers once ``Database.close()`` has been
    called (or begun) so callers that fire background / queued notification or
    audit writes after shutdown can distinguish "the DB is intentionally
    closing" from a real SQL failure and skip cleanly instead of surfacing
    sqlite3's raw ``ProgrammingError: Cannot operate on a closed database``."""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures (
    hash        TEXT NOT NULL,
    hash_type   TEXT NOT NULL DEFAULT 'sha256',
    threat_name TEXT NOT NULL,
    category    TEXT DEFAULT 'generic',
    source      TEXT DEFAULT '',
    first_seen  TEXT DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sig_hash ON signatures(hash, hash_type);

CREATE TABLE IF NOT EXISTS scan_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    path        TEXT NOT NULL,
    category    TEXT NOT NULL,          -- 'signature' | 'heuristic'
    threat_name TEXT NOT NULL,
    confidence  REAL NOT NULL DEFAULT 1.0,
    size        INTEGER,
    sha256      TEXT,
    evidence    TEXT,
    first_seen  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS quarantine_items (
    uid           TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    store_path    TEXT,
    backup_path   TEXT,
    size          INTEGER,
    sha256        TEXT,
    threat_name   TEXT,
    status        TEXT DEFAULT 'quarantined',  -- quarantined | restored | purged
    created       TEXT DEFAULT (datetime('now')),
    restored_at   TEXT,
    notes         TEXT DEFAULT ''              -- resolve attempt history etc.
);

CREATE TABLE IF NOT EXISTS disinfect_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    path         TEXT NOT NULL,
    action       TEXT NOT NULL,         -- strip | truncate | reveal | shortcut_remove | purge | auto_purge
    size_before  INTEGER,
    size_after   INTEGER,
    sha_before   TEXT,
    sha_after    TEXT,
    backup_uid   TEXT,
    status       TEXT NOT NULL,         -- ok | rolled_back | error
    created      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT DEFAULT (datetime('now')),
    event    TEXT NOT NULL,             -- signature_update | signature_import | service_start
    detail   TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scan_summaries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT UNIQUE,
    started      TEXT,
    duration_s   REAL DEFAULT 0,
    files        INTEGER DEFAULT 0,
    dirs         INTEGER DEFAULT 0,
    bytes_scanned INTEGER DEFAULT 0,
    errors       INTEGER DEFAULT 0,
    findings     INTEGER DEFAULT 0,
    targets      TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notifications (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    created  TEXT DEFAULT (datetime('now')),
    kind     TEXT DEFAULT 'info',        -- scan | quarantine | signature | clean | rt | feedback
    title    TEXT NOT NULL,
    body     TEXT DEFAULT '',
    payload  TEXT DEFAULT '',
    read     INTEGER DEFAULT 0
);
"""


class Database:
    """Connection holder and thin query API.  One writer via an RLock."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate_schema()
        logger.debug("opened database %s", self.db_path)

    def _migrate_schema(self) -> None:
        """Idempotent in-place migrations for databases created by older builds.

        CRITICAL: the scan/recovery features are permanently exercised across
        upgrades, so a fresh build must never drop or rebuild user data - only
        additive columns are introduced here.
        """
        cols = {row["name"] for row in self._query("PRAGMA table_info(quarantine_items)")}
        if "notes" not in cols:
            self._execute("ALTER TABLE quarantine_items ADD COLUMN notes TEXT DEFAULT ''")

    # ------------------------------------------------------------------ internals
    def _execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            if self._closed:
                raise DatabaseClosedError("database is already closed")
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: Iterable[Any] = ()) -> List[sqlite3.Row]:
        with self._lock:
            if self._closed:
                raise DatabaseClosedError("database is already closed")
            return self._conn.execute(sql, tuple(params)).fetchall()

    def _query_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        rows = self._query(sql, params)
        return dict(rows[0]) if rows else None

    def close(self) -> None:
        """Gracdully shut the connection down.

        Ordering contract (this is what makes scan-cancel / app-quit safe):
        1.  every writer / query goes through the SAME ``RLock`` as this method;
        2.  we flip ``self._closed`` to True *whilst holding that lock* BEFORE
            touching the connection;
        3.  therefore any write that was already in flight holds the lock, so
            its transaction commits and releases BEFORE we get here - in-flight
            writes are DRAINED, never interrupted;
        4.  any write that starts AFTER the flip acquires the lock, sees
            ``_closed`` and raises :class:`DatabaseClosedError` *instead* of
            surfacing sqlite3's raw "Cannot operate on a closed database" from
            a half-closed connection.

        Callers that keep a reference to the Database object after shutdown
        (e.g. a queued notification push during cancel) rely on point 4.
        """
        with self._lock:
            if self._closed:      # idempotent - repeated close is a no-op
                return
            self._closed = True
            self._conn.close()

    # --------------------------------------------------------------- signatures
    def upsert_signature(self, hash_value: str, hash_type: str, threat_name: str,
                         category: str = "generic", source: str = "") -> None:
        self._execute(
            "INSERT INTO signatures(hash, hash_type, threat_name, category, source) "
            "VALUES(?,?,?,?,?) "
            "ON CONFLICT(hash, hash_type) DO UPDATE SET threat_name=excluded.threat_name",
            (hash_value, hash_type, threat_name, category, source),
        )

    def seed_signatures_csv(self, csv_path: Path) -> int:
        """Bulk-load signatures from CSV: ``sha256,type,threat_name[,category[,source]]``."""
        import csv as _csv

        count = 0
        with open(csv_path, newline="", encoding="utf-8-sig") as fh:
            for row in _csv.reader(fh):
                if not row or not row[0].strip() or row[0].startswith("#"):
                    continue
                row = [cell.strip() for cell in row]
                if len(row) < 3:
                    logger.warning("skipping malformed signature row: %s", row)
                    continue
                hash_value, hash_type, threat = row[0], (row[1] or "sha256").lower(), row[2]
                category = row[3] if len(row) > 3 else "generic"
                source = row[4] if len(row) > 4 else "seed-csv"
                self.upsert_signature(hash_value, hash_type, threat, category, source)
                count += 1
        logger.info("seeded %d signatures from %s", count, csv_path)
        return count

    def lookup(self, hash_value: str, hash_type: str = "sha256") -> Optional[Dict[str, Any]]:
        return self._query_one(
            "SELECT hash, hash_type, threat_name, category, source FROM signatures "
            "WHERE hash=? AND hash_type=?",
            (hash_value.lower(), hash_type),
        )

    def count_signatures(self) -> int:
        row = self._query_one("SELECT COUNT(*) AS n FROM signatures")
        return int(row["n"]) if row else 0

    # --------------------------------------------------------------- findings
    def record_findings(self, scan_id: str, findings: Iterable[Dict[str, Any]]) -> int:
        count = 0
        for f in findings:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO scan_findings(scan_id, path, category, threat_name, "
                    "confidence, size, sha256, evidence) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        scan_id,
                        str(f["path"]),
                        f["category"],
                        f["name"],
                        f.get("confidence", 1.0),
                        f.get("size"),
                        f.get("sha256"),
                        f.get("evidence", ""),
                    ),
                )
            count += 1
        if count:
            with self._lock:
                self._conn.commit()
        return count

    def recent_findings(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT * FROM scan_findings ORDER BY id DESC LIMIT ?", (limit,))]

    # --------------------------------------------------------------- quarantine
    def add_quarantine(self, uid: str, original_path: str, store_path: str,
                       backup_path: str, size: int, sha256: Optional[str],
                       threat_name: str, notes: str = "") -> None:
        self._execute(
            "INSERT INTO quarantine_items(uid, original_path, store_path, backup_path, "
            "size, sha256, threat_name, notes) VALUES(?,?,?,?,?,?,?,?)",
            (uid, str(original_path), str(store_path), str(backup_path),
             size, sha256, threat_name, notes),
        )

    def get_quarantine(self, uid: str) -> Optional[Dict[str, Any]]:
        return self._query_one("SELECT * FROM quarantine_items WHERE uid=?", (uid,))

    def set_quarantine_status(self, uid: str, status: str) -> None:
        if status == "restored":
            self._execute(
                "UPDATE quarantine_items SET status=?, restored_at=datetime('now') "
                "WHERE uid=?",
                (status, uid),
            )
        else:
            # purged / quarantined transit states never stamp restored_at
            self._execute(
                "UPDATE quarantine_items SET status=? WHERE uid=?", (status, uid))

    def list_quarantine(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status:
            return [dict(r) for r in self._query(
                "SELECT * FROM quarantine_items WHERE status=? ORDER BY created DESC",
                (status,))]
        return [dict(r) for r in self._query(
            "SELECT * FROM quarantine_items ORDER BY created DESC")]

    def purge_due(self, min_age_days: int) -> List[Dict[str, Any]]:
        """Quarantined items whose age is >= min_age_days (retention sweep)."""
        return [dict(r) for r in self._query(
            "SELECT * FROM quarantine_items WHERE status='quarantined' "
            "AND created <= datetime('now', ?) ORDER BY created ASC",
            (f"-{int(min_age_days)} days",))]

    def auto_purge_stats(self) -> Dict[str, Any]:
        """Cumulative 'Storage freed by auto-purge' over the audit trail."""
        row = self._query_one(
            "SELECT COUNT(*) AS files, COALESCE(SUM(size_before), 0) AS bytes "
            "FROM disinfect_log WHERE action='auto_purge' AND status='purged'")
        return {"files": int((row or {}).get("files") or 0),
                "bytes": int((row or {}).get("bytes") or 0)}

    # ----------------------------------------------------------- disinfect audit
    def log_disinfection(self, path: str, action: str, size_before: Optional[int],
                         size_after: Optional[int], sha_before: Optional[str],
                         sha_after: Optional[str], backup_uid: Optional[str],
                         status: str) -> None:
        self._execute(
            "INSERT INTO disinfect_log(path, action, size_before, size_after, "
            "sha_before, sha_after, backup_uid, status) VALUES(?,?,?,?,?,?,?,?)",
            (str(path), action, size_before, size_after, sha_before, sha_after,
             backup_uid, status),
        )

    def disinfect_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT * FROM disinfect_log ORDER BY id DESC LIMIT ?", (limit,))]

    # ------------------------------------------------------------------ audit log
    def audit(self, event: str, detail: str = "") -> None:
        """Append an immutable audit-trail row (signature updates, auto-service,
        GUI actions...).  Never rewritten; keeps a full history of everything."""
        self._execute("INSERT INTO audit_log(event, detail) VALUES(?,?)",
                      (str(event), str(detail)))

    def recent_audit(self, limit: int = 200) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    # -------------------------------------------------------- scan summaries
    def save_scan_summary(self, scan_id: str, started: str, duration_s: float,
                          files: int, dirs: int, bytes_scanned: int,
                          errors: int, findings: int, targets: object = None) -> None:
        """Persist the *latest* scan summary (upsert by scan_id) so the Dashboard
        "Last scan" card and the Findings Results viewer survive navigation and
        restarts."""
        import json as _json
        try:
            targets_txt = _json.dumps(list(targets or []))
        except (TypeError, ValueError):
            targets_txt = ""
        self._execute(
            "INSERT INTO scan_summaries(scan_id, started, duration_s, files, dirs, "
            "bytes_scanned, errors, findings, targets) "
            "VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(scan_id) DO UPDATE SET "
            "started=excluded.started, duration_s=excluded.duration_s, "
            "files=excluded.files, dirs=excluded.dirs, "
            "bytes_scanned=excluded.bytes_scanned, errors=excluded.errors, "
            "findings=excluded.findings, targets=excluded.targets",
            (scan_id, started, duration_s, files, dirs, bytes_scanned,
             errors, findings, targets_txt),
        )

    def last_scan_summary(self) -> Optional[Dict[str, Any]]:
        return self._query_one("SELECT * FROM scan_summaries ORDER BY id DESC LIMIT 1")

    def scan_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self._query_one("SELECT * FROM scan_summaries WHERE scan_id=?", (scan_id,))

    def findings_for_scan(self, scan_id: str, limit: int = 5000) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT * FROM scan_findings WHERE scan_id=? ORDER BY id ASC LIMIT ?",
            (scan_id, limit))]

    # ---------------------------------------------------------- notifications
    def add_notification(self, kind: str, title: str, body: str = "",
                         payload: object = None) -> int:
        import json as _json
        payload_txt = _json.dumps(payload) if payload is not None else ""
        cur = self._execute(
            "INSERT INTO notifications(kind, title, body, payload) "
            "VALUES(?,?,?,?)",
            (kind, title, body, payload_txt),
        )
        return int(cur.lastrowid)

    def recent_notifications(self, limit: int = 200) -> List[Dict[str, Any]]:
        import json as _json
        rows = []
        for r in self._query(
                "SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)):
            row = dict(r)
            if row.get("payload"):
                try:
                    row["payload"] = _json.loads(row["payload"])
                except (ValueError, TypeError):
                    row["payload"] = None
            rows.append(row)
        return rows

    def unread_notification_count(self) -> int:
        row = self._query_one(
            "SELECT COUNT(*) AS n FROM notifications WHERE read=0")
        return int(row["n"]) if row else 0

    def prune_notifications(self, keep: int = 200) -> None:
        """Drop old rows until at most ``keep`` remain (newest kept)."""
        self._execute(
            "DELETE FROM notifications WHERE id NOT IN "
            "(SELECT id FROM notifications ORDER BY id DESC LIMIT ?)",
            (keep,))

    def mark_notification_read(self, nid: int) -> None:
        self._execute("UPDATE notifications SET read=1 WHERE id=?", (nid,))

    def notification_by_id(self, nid: int) -> Optional[Dict[str, Any]]:
        import json as _json
        row = self._query_one(
            "SELECT * FROM notifications WHERE id=?", (nid,))
        if row is None:
            return None
        row = dict(row)
        if row.get("payload"):
            try:
                row["payload"] = _json.loads(row["payload"])
            except (ValueError, TypeError):
                row["payload"] = None
        return row

    def mark_all_notifications_read(self) -> None:
        self._execute("UPDATE notifications SET read=1 WHERE read=0")

    def delete_notification(self, nid: int) -> None:
        """Remove ONE notification row (user dismissed it in the bell)."""
        self._execute("DELETE FROM notifications WHERE id=?", (nid,))

    def clear_notifications(self) -> None:
        """Remove every notification row (user cleared the bell)."""
        self._execute("DELETE FROM notifications")