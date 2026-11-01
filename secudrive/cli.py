"""CLI entry point - argparse-driven, GUI-agnostic surface for the core logic."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .config import Config
from .database import Database
from .logging_utils import get_logger, setup_logging

logger = get_logger("cli")


def _build_engine(args: argparse.Namespace):
    """Assemble Config + Database + RecoveryEngine from CLI flags."""
    cfg = Config(base_dir=Path(args.base) if getattr(args, "base", None) else None)
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    if getattr(args, "seed_sigs", None):
        db.seed_signatures_csv(Path(args.seed_sigs))

    from .crypto import load_or_create_key
    key = load_or_create_key(cfg.key_path, passphrase=args.passphrase)

    from .recovery import RecoveryEngine
    engine = RecoveryEngine(
        db=db, backup_dir=cfg.backup_dir, quarantine_dir=cfg.quarantine_dir,
        key=key,
        min_trailing_payload=int(cfg.get("min_trailing_payload", 32)),
        head_window=int(cfg.get("head_window", 64 * 1024)),
        tail_window=int(cfg.get("tail_window", 64 * 1024)),
    )
    return cfg, db, engine


# ------------------------------------------------------------------ handlers
def _cmd_scan(args: argparse.Namespace) -> int:
    from .scanner import ScanOptions, Scanner

    cfg, db, _engine = _build_engine(args)
    print(f"[db] {db.count_signatures()} signatures loaded from {cfg.db_path.name}")

    opts = ScanOptions().with_overrides(
        max_hash_size=int(args.max_size) * 1024 * 1024 if args.max_size else None,
        max_depth=args.depth,
        follow_symlinks=True if args.follow_symlinks else False,
        hash_md5=not args.no_md5,
        check_heuristics=not args.no_heuristics,
        threads=args.threads,
        use_rust=not args.no_rust,
    )
    scanner = Scanner(db, opts)
    report = scanner.scan(args.path)
    scanner.persist()

    if args.json:
        payload = {
            "scan_id": report.scan_id,
            "duration_s": report.finished - report.started,
            "dirs": report.dirs_seen, "files": report.files_seen,
            "bytes": report.bytes_scanned, "errors": report.errors,
            "findings": [
                {"path": str(f.path), "category": f.category, "name": f.name,
                 "confidence": f.confidence, "evidence": f.evidence}
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        report.print_summary()
    db.close()
    return 0


def _cmd_reveal(args: argparse.Namespace) -> int:
    _, db, engine = _build_engine(args)
    rec = engine.reveal_hidden(Path(args.path), recursive=args.recursive,
                               dry_run=args.dry_run)
    _print_action(rec)
    db.close()
    return 0


def _cmd_strip(args: argparse.Namespace) -> int:
    _, db, engine = _build_engine(args)
    rec = engine.strip_fake_shortcuts(Path(args.path), recursive=args.recursive,
                                      dry_run=args.dry_run)
    _print_action(rec)
    db.close()
    return 0


def _cmd_clean_drive(args: argparse.Namespace) -> int:
    _, db, engine = _build_engine(args)
    rec = engine.clean_external_drive(Path(args.path), dry_run=args.dry_run)
    _print_action(rec)
    if args.registry and os_name_is_windows():
        from .immunizer import sanitize_registry_autostarts
        for letter in _drive_letters(str(args.path)):
            r = sanitize_registry_autostarts(letter[0], dry_run=args.dry_run)
            _print_action(r)
    db.close()
    return 0


def _cmd_disinfect(args: argparse.Namespace) -> int:
    _, db, engine = _build_engine(args)
    for target in args.files:
        rec = engine.disinfect_file(Path(target), dry_run=args.dry_run,
                                    verify=not args.no_verify)
        _print_action(rec)
    db.close()
    return 0


def _cmd_quarantine(args: argparse.Namespace) -> int:
    _, db, engine = _build_engine(args)
    for target in args.files:
        rec = engine.quarantine_file(Path(target), threat=args.threat or "user-requested")
        _print_action(rec)
    db.close()
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    _, db, engine = _build_engine(args)
    failures = 0
    if args.all:
        for row in db.list_quarantine():
            if row["status"] != "quarantined":
                continue
            rec = engine.restore_item(row["uid"])
            _print_action(rec)
            if rec.get("status") != "restored":
                failures += 1
    else:
        for uid in args.uid:
            rec = engine.restore_item(uid)
            _print_action(rec)
            if rec.get("status") != "restored":
                failures += 1
    db.close()
    # The exit code must reflect per-item outcomes, not just process crashes: a
    # failed restore (corrupt blob, missing store, verify failure) is still a
    # failure callers need to see - smoke gates and scripts rely on rc != 0.
    return 1 if failures else 0


def _cmd_quarantine_list(args: argparse.Namespace) -> int:
    _, db, _engine = _build_engine(args)
    items = db.list_quarantine()
    if not items:
        print("quarantine is empty")
        return 0
    for row in items:
        print(f"{row['uid']:<10} {row['status']:<12} {row['created']:<20} "
              f"{row['threat_name'] or '-':<24} {row['original_path']}")
    db.close()
    return 0


def _cmd_seed(args: argparse.Namespace) -> int:
    _, db, _engine = _build_engine(args)
    count = db.seed_signatures_csv(Path(args.csv))
    print(f"seeded {count} signatures (total now {db.count_signatures()})")
    db.close()
    return 0


def _cmd_immunize(args: argparse.Namespace) -> int:
    from .immunizer import immunize
    rec = immunize(Path(args.path))
    _print_action(rec)
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    """Real-time background service: detect + auto-clean new removable media."""
    from .watcher import AutoCleanCoordinator, BackgroundWatcher

    cfg, db, engine = _build_engine(args)

    def clean_drive(drive_path: str) -> None:
        engine.clean_external_drive(Path(drive_path), dry_run=args.dry_run)

    watcher = BackgroundWatcher(
        interval=float(cfg.get("poll_interval", 1.5)),
        on_attach=clean_drive)
    coordinator = AutoCleanCoordinator(watcher, clean_fn=clean_drive)
    coordinator.start()
    print(f"watching for removable drives... backend={watcher.backend} "
          f"(Ctrl+C to stop)")
    try:
        watcher.wait_forever()
    finally:
        coordinator.stop()
        db.close()
    return 0


def _cmd_gui(args: argparse.Namespace) -> int:
    """Launch the PyQt6 desktop interface."""
    from .gui import launch_gui
    return launch_gui(base=args.base)


def _cmd_sigupdate(args: argparse.Namespace) -> int:
    """Fetch / import malware signatures into the local database."""
    cfg, db, _engine = _build_engine(args)
    from .sigfeed import SignatureFeedUpdater

    updater = SignatureFeedUpdater(db, cfg.data_dir)
    if args.demo:
        stats = updater.demo()
    elif args.url:
        stats = updater.update(args.url)
    elif args.csv:
        stats = updater.import_file(Path(args.csv))
    else:
        print("provide --url, --csv, or --demo", file=sys.stderr)
        db.close()
        return 2
    print(json.dumps(stats, indent=2))
    db.close()
    return 0


def _cmd_sigs(args: argparse.Namespace) -> int:
    _, db, _engine = _build_engine(args)
    print(f"signatures in db: {db.count_signatures()}")
    for row in db.recent_findings(args.limit):
        print(f"{row['first_seen']} {row['category']:<9} {row['threat_name']:<24} {row['path']}")
    db.close()
    return 0


# ------------------------------------------------------------------ rendering
def _print_action(rec: dict) -> None:
    """Pretty-print a recovery action report without paging."""
    print(json.dumps(rec, indent=2, default=str))


def os_name_is_windows() -> bool:
    import os as _os
    return _os.name == "nt"


def _drive_letters(path: str) -> List[str]:
    import os
    from string import ascii_uppercase
    root = os.path.splitdrive(path)[0].upper().rstrip("\\")
    if root.endswith(":") and os.path.isdir(root + "\\"):
        return [root]
    return [f"{letter}:" for letter in ascii_uppercase if os.path.isdir(f"{letter}:\\")]


# ------------------------------------------------------------------------ main
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secudrive",
        description="Desktop Security & Data Recovery Tool - scan, disinfect, "
                    "and restore files & external drives. Windows-first.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--base", help="project base dir (overrides default data paths)")
    parser.add_argument("--passphrase", help="master passphrase (overrides machine key)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="recursively scan a directory/drive")
    p.add_argument("path", nargs="+", help="file(s) or folder(s) to scan")
    p.add_argument("--max-size", type=int, help="skip hashing files above N MiB")
    p.add_argument("--depth", type=int, default=0, help="max directory depth (0=unlimited)")
    p.add_argument("--follow-symlinks", action="store_true")
    p.add_argument("--no-md5", action="store_true")
    p.add_argument("--no-heuristics", action="store_true")
    p.add_argument("--threads", type=int, default=0,
                   help="hash worker threads for the compiled engine (0=auto)")
    p.add_argument("--no-rust", action="store_true",
                   help="force the pure-Python scan engine")
    p.add_argument("--json", action="store_true")
    p.add_argument("--seed-sigs", help="CSV of signatures to load before scanning")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("reveal", help="reset HIDDEN/SYSTEM attributes on user data")
    p.add_argument("path")
    p.add_argument("--recursive", action="store_true", default=True)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=_cmd_reveal)

    p = sub.add_parser("strip-shortcuts", help="quarantine fake/hostile .lnk files")
    p.add_argument("path")
    p.add_argument("--recursive", action="store_true", default=True)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=_cmd_strip)

    p = sub.add_parser("clean-drive", help="deep-clean an external/removable drive")
    p.add_argument("path", help="drive root, e.g. E:\\ ")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--registry", action="store_true",
                   help="also prune drive-scoped registry autostarts (Windows)")
    p.set_defaults(func=_cmd_clean_drive)

    p = sub.add_parser("disinfect", help="strip appended payloads from files (backup+verify)")
    p.add_argument("files", nargs="+")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-verify", action="store_true")
    p.set_defaults(func=_cmd_disinfect)

    p = sub.add_parser("quarantine", help="quarantine file(s) with encrypted backup")
    p.add_argument("files", nargs="+")
    p.add_argument("--threat", help="label for the log")
    p.set_defaults(func=_cmd_quarantine)

    p = sub.add_parser("restore", help="restore quarantined items (decrypt+verify)")
    p.add_argument("uid", nargs="*", help="quarantine UIDs; none with --all")
    p.add_argument("--all", action="store_true", help="restore every quarantined item")
    p.set_defaults(func=_cmd_restore)

    p = sub.add_parser("quarantine-list", help="list quarantine contents")
    p.set_defaults(func=_cmd_quarantine_list)

    p = sub.add_parser("seed-sigs", help="bulk-load signatures from CSV")
    p.add_argument("csv")
    p.set_defaults(func=_cmd_seed)

    p = sub.add_parser("immunize", help="vaccinate a drive against autorun persistence")
    p.add_argument("path")
    p.set_defaults(func=_cmd_immunize)

    p = sub.add_parser("watch", help="auto-clean removable drives as they are inserted")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=_cmd_watch)

    p = sub.add_parser("gui", help="launch the PyQt6 desktop interface")
    p.set_defaults(func=_cmd_gui)

    p = sub.add_parser("sigupdate", help="sync malware signatures from a feed")
    p.add_argument("--url", help="remote JSON/CSV feed URL (https:// preferred)")
    p.add_argument("--csv", help="local signature CSV file (air-gap import)")
    p.add_argument("--demo", action="store_true",
                   help="offline self-test: sync a generated sample feed via file://")
    p.set_defaults(func=_cmd_sigupdate)

    p = sub.add_parser("sigs", help="show recent findings / signature count")
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=_cmd_sigs)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(level=10 if args.verbose else 20)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"[secudrive] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # guard: clones must never die unexplainably on USB
        logger.exception("unhandled error")
        print(f"[secudrive] fatal: {exc}", file=sys.stderr)
        return 2