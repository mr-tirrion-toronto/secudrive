#!/usr/bin/env python3
"""Run script - ``python run.py scan E:\\`` etc. Thin wrapper over secudrive.cli."""
from secudrive.cli import main

if __name__ == "__main__":
    raise SystemExit(main())