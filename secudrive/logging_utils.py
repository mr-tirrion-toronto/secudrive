"""Logging helpers - single formatter, file + console, used across all modules."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

_ROOT = "secudrive"
_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger, e.g. ``get_logger("scanner")``."""
    return logging.getLogger(f"{_ROOT}.{name}")


def setup_logging(level: int = logging.INFO, log_file: Optional[Path] = None) -> None:
    """Configure the secudrive logger tree. Idempotent; safe to call once in CLI."""
    root = logging.getLogger(_ROOT)
    if root.handlers:
        root.setLevel(level)
        return

    root.setLevel(level)
    fmt = logging.Formatter(_FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as exc:  # Non-fatal: consoles still spool diagnostics.
            root.warning("could not attach file logging handler %s: %s", log_file, exc)