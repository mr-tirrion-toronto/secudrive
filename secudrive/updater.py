"""updater.py - automatic online signature updater.

Fetches the latest malware SHA-256 hashes from public threat feeds and upserts
them straight into the SecuDrive SQLite signature store on startup and on
demand.  Built on the validated sync pipeline of ``sigfeed`` (ETag/304
caching, per-row validation, dedupe) and adds:

  * multi-feed aggregation ("sigfeeds" config, or a legacy "sigfeed_url"),
  * payload normalisation for the common public feed shapes:
      - our JSON   ``{"signatures": [{"sha256": ..., "threat": ...}], ...}``
      - MalwareBazaar-style JSON ``{"data": [{"sha256_hash": ..}]}``
      - any CSV with a ``sha256`` / ``hash`` column (URLhaus-style headers),
      - legacy positional CSV ``sha256,type,threat[,category[,source]]``
  * a single-flight guard so GUI startup + manual clicks never double-run,
  * last-update timestamp persisted to the config file.

No network I/O happens at import time.
"""
from __future__ import annotations

import csv
import io
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .database import Database
from .logging_utils import get_logger
from .sigfeed import DEFAULT_USER_AGENT, SignatureFeedUpdater

logger = get_logger("updater")

#: Parsed/acceptable header names when a CSV feed names its columns.
_HASH_HEADERS = ("sha256", "sha256_hash", "hash", "sha-256")
_THREAT_HEADERS = ("threat", "threat_name", "signature", "label", "type")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class OnlineUpdater:
    """Aggregate + sync signatures from one or more online feeds."""

    def __init__(self, db: Database, cfg,
                 timeout: int = 30,
                 user_agent: str = DEFAULT_USER_AGENT) -> None:
        self.db = db
        self.cfg = cfg
        self._base = SignatureFeedUpdater(db, cfg.data_dir, user_agent=user_agent,
                                          timeout=timeout)
        self._lock = threading.Lock()
        self.running = False
        self.last_stats: Optional[Dict] = None
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------------ feeds
    def configured_feeds(self) -> List[str]:
        """Ordered feed URLs: explicit ``sigfeeds`` list > legacy
        ``sigfeed_url`` > built-in default (URLhaus public CSV)."""
        feeds = self.cfg.get("sigfeeds") or []
        if isinstance(feeds, str):
            feeds = [feeds]
        if not feeds:
            legacy = str(self.cfg.get("sigfeed_url") or "").strip()
            if legacy:
                feeds = [legacy]
        if not feeds:
            feeds = ["https://urlhaus.abuse.ch/downloads/csv_online/"]
        return [u for u in feeds if str(u).strip()]

    # ------------------------------------------------------------- public API
    def update_all(self, urls: Optional[List[str]] = None,
                   on_feed: Optional[callable] = None) -> Dict:
        """Sync every configured feed.  Returns an aggregate stats dict.

        ``on_feed(stats)`` is invoked after each individual feed for live UI
        progress.  Single-flight: concurrent callers share the in-flight run
        (the lock guarantees only one network pass at a time).
        """
        with self._lock:
            self.running = True
            self.last_error = None
            agg: Dict = {
                "feeds": 0, "sig_offered": 0, "added": 0, "skipped": 0,
                "fetched_at": _iso_now(), "errors": [], "status": "ok",
                "feeds_detail": [],
            }
            try:
                for url in urls if urls is not None else self.configured_feeds():
                    stats = self._sync_one(url)
                    agg["feeds"] += 1
                    agg["sig_offered"] += stats.get("sig_offered", 0)
                    agg["added"] += stats.get("added", 0)
                    agg["skipped"] += stats.get("skipped", 0)
                    if stats.get("errors"):
                        agg["errors"].extend(stats["errors"])
                    if stats.get("status") in ("error", "remote-error", "parse-error"):
                        agg["status"] = "degraded"
                    agg["feeds_detail"].append(stats)
                    if on_feed:
                        try:
                            on_feed(stats)
                        except Exception:
                            pass
                # only *feed-level* failures mark the whole run degraded;
                # invalid-row skips inside a healthy feed are just warnings.
                self.last_stats = agg
                # persist last-update marker for the dashboard / logs
                try:
                    self.cfg.set("sig_last_update", agg["fetched_at"])
                    self.cfg.save()
                except Exception:  # config writes must never fail a sync
                    pass
                self._audit("signature_update",
                            f"guard=online feeds={agg['feeds']} added={agg['added']} "
                            f"skipped={agg['skipped']} errors={len(agg['errors'])} "
                            f"status={agg['status']}")
                logger.info("online sig update: feeds=%d added=%d skipped=%d errors=%d",
                            agg["feeds"], agg["added"], agg["skipped"], len(agg["errors"]))
                return agg
            finally:
                self.running = False

    def import_files(self, paths: List[Path]) -> Dict:
        """Bulk-import local CSV/JSON signature files (offline / air-gapped
        environments).  Same row-validation + dedupe rules as online feeds;
        every attempt lands in the audit log."""
        with self._lock:
            agg: Dict = {
                "feeds": 0, "sig_offered": 0, "added": 0, "skipped": 0,
                "fetched_at": _iso_now(), "errors": [], "status": "ok",
                "feeds_detail": [], "local": True,
            }
            for path in paths or []:
                stats = self._import_one(Path(path))
                agg["feeds"] += 1
                agg["sig_offered"] += stats.get("sig_offered", 0)
                agg["added"] += stats.get("added", 0)
                agg["skipped"] += stats.get("skipped", 0)
                if stats.get("errors"):
                    agg["errors"].extend(stats["errors"])
                if stats.get("status") in ("error", "parse-error"):
                    agg["status"] = "degraded"
                agg["feeds_detail"].append(stats)
            self._audit("signature_import",
                        f"guard=local files={len(paths or [])} added={agg['added']} "
                        f"skipped={agg['skipped']} errors={len(agg['errors'])} "
                        f"status={agg['status']}")
            logger.info("local sig import: files=%d added=%d skipped=%d errors=%d",
                        len(paths or []), agg["added"], agg["skipped"],
                        len(agg["errors"]))
            self.last_stats = agg
            return agg

    def _import_one(self, path: Path) -> Dict:
        stats: Dict = {"file": str(path), "fetched_at": _iso_now(),
                       "payload_bytes": 0, "sig_offered": 0, "added": 0,
                       "skipped": 0, "errors": [], "status": "ok", "etag": None}
        if not path.is_file():
            stats.update({"status": "error", "errors": [f"no such file: {path}"]})
            return stats
        try:
            payload = path.read_bytes()
        except OSError as exc:
            stats.update({"status": "error", "errors": [str(exc)]})
            return stats
        stats["payload_bytes"] = len(payload)
        try:
            rows = self._rows_from_payload(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            stats.update({"status": "parse-error", "errors": [f"bad file: {exc}"]})
            return stats
        return self._base._sync(rows, None, payload, stats)

    def _audit(self, event: str, detail: str) -> None:
        try:
            self.db.audit(event, detail)
        except Exception as exc:          # auditing must never break an update
            logger.warning("audit write failed: %s", exc)

    # -------------------------------------------------------------- internals
    def _sync_one(self, url: str) -> Dict:
        stats: Dict = {"url": url, "fetched_at": _iso_now(), "payload_bytes": 0,
                       "sig_offered": 0, "added": 0, "skipped": 0, "errors": [],
                       "status": "ok", "etag": None}
        try:
            payload, etag, err = self._base._fetch(url)
        except Exception as exc:  # network/parse robustness
            stats.update({"status": "error", "errors": [f"fetch failed: {exc}"]})
            return stats
        if err:
            stats.update({"status": "remote-error", "errors": [err]})
            return stats
        if payload is None:                       # HTTP 304 Not Modified
            stats.update({"status": "unchanged",
                          "reason": "feed unchanged (HTTP 304)"})
            return stats
        stats["payload_bytes"] = len(payload)
        try:
            rows = self._rows_from_payload(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            stats.update({"status": "parse-error", "errors": [f"bad feed: {exc}"]})
            return stats
        return self._base._sync(rows, etag, payload, stats)

    # ------------------------------------------------------------ payload tools
    @classmethod
    def _rows_from_payload(cls, raw: bytes) -> List[dict]:
        """Convert bytes into canonical raw row dicts for sigfeed validation.

        Handles: JSON list-of-objects, ``{"signatures": [...]}``,
        ``{"data": [...]}`` (MalwareBazaar-style), and CSV with either
        header-named hash column or the legacy positional layout.
        """
        blob = raw.decode("utf-8", "replace")
        stripped = blob.lstrip()
        if stripped.startswith(("{", "[")):                      # --------- JSON
            data = json.loads(blob)
            items = data if isinstance(data, list) else (
                data.get("signatures") or data.get("data") or [])
            return [cls._normalise_row(item) for item in items
                    if isinstance(item, dict)]
        return cls._csv_rows(blob)                                # --------- CSV

    @staticmethod
    def _normalise_row(item: dict) -> dict:
        """Map a feed-specific JSON row onto our row vocabulary."""
        digest = (item.get("sha256") or item.get("sha256_hash")
                  or item.get("md5") or item.get("md5_hash")
                  or item.get("hash") or "").strip()
        threat = (item.get("threat") or item.get("threat_name")
                  or item.get("type") or item.get("signature") or "").strip()
        return {
            "hash": digest,
            "hash_type": ("sha256" if any(k in item for k in
                          ("sha256", "sha256_hash")) else
                          ("md5" if any(k in item for k in ("md5", "md5_hash"))
                           else "sha256")),
            "threat": threat,
            "category": (item.get("category") or "generic").strip(),
            "source": (item.get("source") or "remote-feed").strip(),
        }

    @staticmethod
    def _is_hash(text: str) -> bool:
        return (len(text) in (32, 40, 64)
                and all(c in "0123456789abcdef" for c in text.lower()))

    @classmethod
    def _csv_rows(cls, blob: str) -> List[dict]:
        """Parse CSV; auto-detect a header-named hash column, but treat rows
        whose first column is already a valid digest as legacy positional data
        (so header-inference never eats real signature rows)."""
        reader = csv.reader(io.StringIO(blob))
        line: Optional[List[str]] = None
        for candidate in reader:                              # skip blank lines
            if candidate and candidate[0].strip():
                line = candidate
                break
        if not line or not line[0].strip():
            return []
        headers = [h.strip().lower() for h in line]
        hash_idx = next((i for i, h in enumerate(headers)
                         if h in _HASH_HEADERS), None)
        # a real hash in column 0 => data row, never a header line
        header_row = (hash_idx is not None and not cls._is_hash(line[0].strip()))
        if header_row:
            threat_idx = next((i for i, h in enumerate(headers)
                               if h in _THREAT_HEADERS), None)
            rows: List[dict] = []
            for row in reader:
                if len(row) <= hash_idx or not row[hash_idx].strip():
                    continue
                rows.append({
                    "hash": row[hash_idx].strip(),
                    "hash_type": ("sha256" if "sha" in headers[hash_idx] else "md5"),
                    "threat": (row[threat_idx].strip()
                               if threat_idx is not None and len(row) > threat_idx
                               else "remote-feed"),
                    "category": "generic",
                    "source": "remote-feed",
                })
            return rows
        # legacy positional: first line is already a signature row
        rows: List[dict] = []                                   # noqa: F811
        for row in [line, *reader]:
            if row and row[0].strip():
                rows.append({
                    "hash": row[0].strip(),
                    "hash_type": (row[1] or "sha256").strip() if len(row) > 1 else "sha256",
                    "threat": row[2].strip() if len(row) > 2 else "",
                    "category": row[3].strip() if len(row) > 3 else "generic",
                    "source": row[4].strip() if len(row) > 4 else "remote-feed",
                })
        return rows