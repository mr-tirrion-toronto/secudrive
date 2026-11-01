"""Configuration defaults and lightweight JSON settings store.

Every tuned knob lives here so the CLI core can later be wrapped unchanged in
a PyQt6/Tauri shell - the GUI reads / writes the same JSON file.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional


def _default_base_dir() -> Path:
    """Writable home for config/data/backups.

    Dev runs: the repo next to this package.  PyInstaller frozen apps: the
    onefile temp dir (`_MEIPASS`) is read-only, so we fall back to a
    per-user store.  secudrive_debug.log, secudrive.db and the encrypted
    backups all hang off this base.
    """
    if getattr(sys, "frozen", False):
        local = (os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
                 or str(Path.home()))
        return Path(local) / "SecuDrive"
    return Path(__file__).resolve().parents[1]


DEFAULT_CONFIG: Dict[str, Any] = {
    # ---- Scanner -----------------------------------------------------------
    "max_hash_size": 512 * 1024 * 1024,      # Files larger than this are NOT hashed
    "max_depth": 0,                           # 0 == unlimited directory recursion
    "follow_symlinks": False,
    "hash_md5": True,                          # MD5 kept for legacy signature tables
    "exclude_dirs": [
        "$RECYCLE.BIN",
        "System Volume Information",
        "Windows",
        "System32",
        "WinSxS",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "$SysReset",
        "Recovery",
        "boot",
        "AppData",
        "node_modules",
        ".git",
        "venv",
        ".venv",
    ],
    # ---- Recovery / Disinfection -------------------------------------------
    "min_trailing_payload": 32,               # Bytes of junk after EOF marker to auto-strip
    "tail_window": 64 * 1024,                 # Bytes read from file end for EOF/payload scan
    "head_window": 64 * 1024,                 # Bytes read from file start for magic/sniffing
    "backup_max_batch": 64,                   # Max items held in one dry-run report
    # ---- External drive immunizer -------------------------------------------
    "poll_interval": 2.0,                     # Seconds between removable-drive polls
    "immunize_autorun_inf": True,             # Create vaccinating "autorun.inf" directory
    "sanitize_registry": True,                # Strip autostart values pointing at cleaned drive
    # ---- Online signature updater -------------------------------------------
    "sigfeeds": [],                           # Ordered feed URLs; empty -> defaults + legacy sigfeed_url
    "sigfeed_url": "",                        # Legacy single-feed override (kept for compat)
    "sigfeed_timeout": 40,                    # Seconds per feed before giving up
    "sig_last_update": None,                  # ISO timestamp of the last successful sync
    # ---- Automatic background service (launch-time) -------------------------
    "auto_sigs_on_startup": True,             # Pull latest hashes before the launch scan
    "auto_scan_on_startup": True,             # Silent quick scan on C:\ + external drives
    "auto_repair": True,                      # Auto disinfect / quarantine / reveal findings
    "auto_scan_max_depth": 6,                 # Depth bound keeps the silent scan "quick"
    "auto_scan_max_hash_size": 256 * 1024 * 1024,  # Files above this skip hashing
    "scan_threads": 0,                        # Compiled-engine hash workers (0 = auto/cpu)
    "auto_update_interval_hours": 6,          # Periodic online signature refresh (0 = off)
    "auto_action_policy": "auto",             # 'auto' | 'prompt' | 'off' (cautious users)
    "on_detection": "resolve",
        # Default course of action when a finding cannot be ignored.
        # 'resolve' (default)  - findings are RESOLVED IN PLACE when a safe
        #                        EOF-marker strip point exists (jpg/png/gif/
        #                        pdf/zip containers): appended malicious payloads
        #                        are stripped from an encrypted backup and the
        #                        fixed file stays where it belongs.  Files with
        #                        no safe in-place fix (pure-malware executables,
        #                        whole-file malware) are moved to Quarantine.
        # 'quarantine' (opt-in) - the OLD always-quarantine behavior: every
        #                        finding is moved to the quarantine store for
        #                        review, never resolved in place.
    "drive_refresh_interval": 3.0,            # Seconds between GUI drive-list re-lists
    "start_with_windows": False,              # HKCU\...\Run registration (registry Run key)
    # ---- Real-Time File-System Protection ------------------------------------
    "rt_enabled": False,                      # Enable continuous real-time watch (off by default)
    "rt_action": "quarantine",                # Action on detection: 'quarantine' | 'disinfect' | 'report'
    "rt_max_concurrent": 2,                   # Max concurrent single-file scans in thread pool
    "rt_debounce_ms": 500,                    # Quiet period (ms) before scanning a settled file
    "rt_buffer_bytes": 1048576,               # ReadDirectoryChangesW buffer (1 MiB)
    "rt_cpu_threshold": 55.0,                 # Pause dispatches when SecuDrive CPU% exceeds this
    "rt_cpu_sample_s": 1.0,                   # Seconds between CPU sampling
    "rt_queue_cap": 1500,                     # Max pending files before oldest are dropped
    "rt_exclude_paths": [],                   # Substring or prefix match; these paths are never scanned
    "rt_exclude_exts": [],                    # File extensions to ignore (e.g. [".log", ".tmp"])
    "rt_watch_system_drive": True,            # Also watch C:\ (False = external drives only)
    "usb_auto_clean": True,                  # Auto-clean + backup on new USB drive attach
    # ---- Quarantine retention / Auto-Purge ---------------------------------
    "quarantine_retention_mode": "auto_purge_verified",
        # 'keep_forever'                  - no automatic deletion; every
        #                                   artifact stays for manual review,
        #                                   exactly like the original design.
        # 'auto_purge_verified' (default) - PURE-MALWARE files only (a confident
        #                                 full-file signature hit + non-container
        #                                 extension, re-verified at purge time)
        #                                 are backup->deleted->verified and their
        #                                 short-lived encrypted backup is purged.
        #                                 Any doubt or verify failure falls back
        #                                 to long-term Quarantine (never deleted).
        #                                 Trades a small safety window for lower
        #                                 storage; see the Settings tooltip.
        # 'purge_after_days'            - quarantined items older than
        #                                 purge_after_days days are purged by the
        #                                 background sweep (blob + backup gone).
        #                                 The audit row is retained as 'purged'.
    "purge_after_days": 30,             # Retention window for 'purge_after_days'
}

_PATH_DEFAULTS = {
    "data_dir": "data",
    "db_file": "secudrive.db",
    "backup_dir": "backups",
    "quarantine_dir": "quarantine",
    "key_file": ".secudrive.key",
    "config_file": "secudrive.json",
}


class Config:
    """Merge defaults < json file < explicit overrides."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else _default_base_dir()
        self.data_dir = self.base_dir / _PATH_DEFAULTS["data_dir"]
        self.db_path = self.data_dir / _PATH_DEFAULTS["db_file"]
        self.backup_dir = self.data_dir / _PATH_DEFAULTS["backup_dir"]
        self.quarantine_dir = self.data_dir / _PATH_DEFAULTS["quarantine_dir"]
        self.key_path = self.data_dir / _PATH_DEFAULTS["key_file"]
        self.config_path = self.base_dir / _PATH_DEFAULTS["config_file"]

        self._values: Dict[str, Any] = dict(DEFAULT_CONFIG)
        self._load_file()

    def _load_file(self) -> None:
        """Layer a user JSON config over the built-in defaults (best-effort)."""
        try:
            if self.config_path.exists() and self.config_path.is_file():
                with open(self.config_path, "r", encoding="utf-8") as fh:
                    user = json.load(fh)
                if isinstance(user, dict):
                    self._values.update(user)
        except (OSError, ValueError) as exc:
            # Never let a bad user config break the tool; log and continue.
            print(f"[config] could not load {self.config_path}: {exc}")

    def get(self, key: str, default: Any = None) -> Any:
        return self._values.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set an override (in memory + persisted by save())."""
        self._values[key] = value

    def save(self) -> None:
        """Persist the effective config to the JSON file so GUI preferences
        (USB auto-clean, feed URL, theme) survive restarts."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as fh:
                json.dump(self._values, fh, indent=2)
        except OSError as exc:
            print(f"[config] could not save {self.config_path}: {exc}")

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._values)

    def ensure_dirs(self) -> None:
        """Create data, backup, and quarantine dirs up front with PEP-20 clarity."""
        for path in (self.data_dir, self.backup_dir, self.quarantine_dir):
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise RuntimeError(f"cannot create data directory {path}: {exc}") from exc