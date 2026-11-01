"""sigfeed.py - automated SHA-256 signature feed sync.

Fetches a remote JSON/CSV signature payload (over TLS, with a bounded timeout,
optional ETag caching), validates every row, and upserts into ``signatures``.
No unexpected network calls happen at import time - only explicit
``update()`` / ``import_file()`` invocations move bytes.

Endpoints are polled with If-None-Match / ETag so unchanged feeds cost one
round-trip.  Feed payload shape (JSON):

    {"signatures": [{"sha256": "...", "threat": "Trojan.X", "category": "..."}, ...]}
or CSV (already supported by ``seed-sigs``):
    sha256,sha256,Trojan.X,category,source
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .database import Database
from .logging_utils import get_logger

logger = get_logger("sigfeed")

DEFAULT_USER_AGENT = "SecuDrive/0.1 (+local signature syncer)"
_HASH_LENGTHS = {"sha256": 64, "md5": 32, "sha1": 40}
_CACHE_FILE = "sigfeed_cache.json"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SignatureFeedUpdater:
    """Validate + persist signature rows from a feed URL or local file."""

    def __init__(self, db: Database, cache_dir: Path,
                 user_agent: str = DEFAULT_USER_AGENT, timeout: int = 30) -> None:
        self.db = db
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / _CACHE_FILE
        self._user_agent = user_agent
        self._timeout = timeout

    # ------------------------------------------------------------------ fetching
    def _read_etag(self) -> Optional[str]:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as fh:
                return json.load(fh).get("etag")
        except (OSError, ValueError):
            return None

    def _write_etag(self, etag: str, payload_hash: str) -> None:
        try:
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                json.dump({"etag": etag, "payload_sha256": payload_hash,
                           "fetched_at": _iso_now()}, fh)
        except OSError:
            pass

    def _fetch(self, url: str) -> tuple[Optional[bytes], Optional[str], Optional[str]]:
        """Return (payload, etag, error). 304/None payload == unchanged."""
        req = urllib.request.Request(
            url, headers={"User-Agent": self._user_agent,
                          "Accept": "application/json, text/csv;q=0.9, */*;q=0.1"})
        etag = self._read_etag()
        if etag:
            req.add_header("If-None-Match", etag)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read()
                return body, resp.headers.get("ETag"), None
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return None, etag, None          # unchanged
            return None, None, f"HTTP {exc.code} {exc.reason}"
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return None, None, str(exc)

    # ------------------------------------------------------------------ parsing
    @staticmethod
    def _validate_row(row: dict) -> Optional[dict]:
        """Return a cleaned row dict or None if it fails validation."""
        digest = (row.get("hash") or row.get("sha256") or row.get("md5") or "").strip().lower()
        hash_type = (row.get("hash_type") or row.get("type") or "sha256").strip().lower()
        threat = (row.get("threat") or row.get("threat_name") or "").strip()
        if not digest or not threat:
            return None
        expected = _HASH_LENGTHS.get(hash_type)
        if not expected or len(digest) != expected or any(c not in "0123456789abcdef" for c in digest):
            return None
        return {
            "hash": digest, "hash_type": hash_type, "threat": threat[:128],
            "category": (row.get("category") or "generic").strip()[:64],
            "source": (row.get("source") or "remote-feed").strip()[:128],
        }

    @staticmethod
    def _parse_payload(raw: bytes) -> List[dict]:
        """Parse the feed bytes into validated row dicts (JSON or CSV)."""
        rows: List[dict] = []
        blob = raw.decode("utf-8", "replace")
        stripped = blob.lstrip()
        if stripped.startswith(("{", "[")):
            data = json.loads(blob)
            candidates = data if isinstance(data, list) else data.get("signatures", [])
            for item in candidates:
                if isinstance(item, dict):
                    rows.append(item)
        else:
            for line in csv.reader(io.StringIO(blob)):
                if line and line[0].strip() and not line[0].lstrip().startswith("#"):
                    rows.append({
                        "hash": line[0].strip(), "hash_type": (line[1] or "sha256").strip()
                        if len(line) > 1 else "sha256",
                        "threat": line[2].strip() if len(line) > 2 else "",
                        "category": line[3].strip() if len(line) > 3 else "generic",
                        "source": line[4].strip() if len(line) > 4 else "remote-feed",
                    })
        return rows

    # ------------------------------------------------------------------ sync API
    def update(self, url: str) -> Dict:
        """Fetch + sync a remote feed.  Returns a stats dict for the GUI/CLI."""
        stats = {"url": url, "fetched_at": _iso_now(), "payload_bytes": 0,
                 "sig_offered": 0, "added": 0, "skipped": 0, "errors": [],
                 "status": "ok", "etag": None}
        try:
            payload, etag, err = self._fetch(url)
        except Exception as exc:  # network/parse robustness
            stats.update({"status": "error",
                          "errors": [f"fetch failed: {exc}"]})
            return stats
        if err:
            stats.update({"status": "remote-error", "errors": [err]})
            return stats
        if payload is None:                       # HTTP 304 Not Modified
            stats.update({"status": "unchanged",
                          "reason": "server responded 304 (feed unchanged)"})
            return stats
        stats["payload_bytes"] = len(payload)
        try:
            rows = self._parse_payload(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            stats.update({"status": "parse-error", "errors": [f"bad feed: {exc}"]})
            return stats
        return self._sync(rows, etag, payload, stats)

    def import_file(self, path: Path) -> Dict:
        """Sync from a local .json/.csv file (offline air-gap workflow)."""
        path = Path(path)
        stats = {"file": str(path), "fetched_at": _iso_now(), "payload_bytes": 0,
                 "sig_offered": 0, "added": 0, "skipped": 0, "errors": [],
                 "status": "ok", "etag": None}
        try:
            payload = path.read_bytes()
        except OSError as exc:
            return {**stats, "status": "error", "errors": [str(exc)]}
        stats["payload_bytes"] = len(payload)
        try:
            rows = self._parse_payload(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            return {**stats, "status": "parse-error", "errors": [str(exc)]}
        return self._sync(rows, None, payload, stats)

    def _sync(self, rows: List[dict], etag: Optional[str], payload: bytes,
              stats: Dict) -> Dict:
        seen: set = set()
        for row in rows:
            clean = self._validate_row(row)
            if clean is None:
                stats["errors"].append(f"skipped invalid row sample: {str(row)[:80]}")
                continue
            stats["sig_offered"] += 1
            key = (clean["hash"], clean["hash_type"])
            if key in seen:
                continue
            seen.add(key)
            if self._upsert(clean):
                stats["added"] += 1
            else:
                stats["skipped"] += 1
        if etag:
            payload_hash = hashlib.sha256(payload).hexdigest()
            self._write_etag(etag, payload_hash)
            stats["etag"] = etag
        logger.info("sigfeed sync: offered=%d added=%d skipped=%d errors=%d",
                    stats["sig_offered"], stats["added"], stats["skipped"],
                    len(stats["errors"]))
        return stats

    def _upsert(self, clean: dict) -> bool:
        """True if a brand-new row was inserted, False if it already existed."""
        row = self.db.lookup(clean["hash"], clean["hash_type"])
        if row:
            return False
        self.db.upsert_signature(clean["hash"], clean["hash_type"], clean["threat"],
                                 clean["category"], clean["source"])
        return True

    # ------------------------------------------------------------------- demo
    def demo(self) -> Dict:
        """Offline self-test: write a sample JSON feed to a temp file and sync
        it via ``file://``` (no network).  Used by `sigupdate --demo` and CI."""
        rows = [
            {"hash": "a" * 64, "threat": "Demo.Duplicate", "category": "test"},
            {"hash": "b" * 64, "threat": "Demo.Trojan", "category": "trojan"},
            {"hash": "zz-not-a-hash", "threat": "Demo.Invalid", "category": "test"},
        ]
        payload = json.dumps({"signatures": rows}).encode()
        fd, name = tempfile.mkstemp(prefix="secudrive_demo_", suffix=".json")
        with open(name, "wb") as fh:
            fh.write(payload)
        url = Path(name).as_uri()
        try:
            return self.update(url)
        finally:
            try:
                import os
                os.close(fd)
                Path(name).unlink()
            except OSError:
                pass