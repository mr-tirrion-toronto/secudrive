#!/usr/bin/env python3
"""PyInstaller bootstrapper.

``SecuDrive.exe`` (windowed, UAC-elevated) boots straight into the GUI.
Pass "--cli <subcommand> ..." to get the console CLI inside the same binary
(useful for ``SecuDrive.exe --cli scan E:\\`` from an elevated terminal).
"""
import os
import sys


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--cli":
        from secudrive.cli import main as cli_main
        return int(cli_main(argv[1:]) or 0)

    if argv and argv[0] in ("--register-wsc", "--unregister-wsc"):
        # Called once during install / uninstall (elevated by the manifest).
        from secudrive import wsc_register
        if argv[0] == "--register-wsc":
            exe = argv[1] if len(argv) > 1 and os.path.exists(argv[1]) else ""
            result = wsc_register.register_antivirus(exe_path=exe)
        else:
            result = wsc_register.unregister_antivirus()
        if getattr(sys, "frozen", False) and result.get("ok"):
            return 0
        print(result.get("message", ""))
        return 0 if result.get("ok") else 1

    from secudrive.gui import launch_gui

    # HEADLESS SMOKE SUPPORT: SECUDRIVE_BASE_DIR redirects all data paths
    # (config/database/backups/quarantine/logs) to a sandbox directory, so the
    # frozen binary can be driven against a throwaway copy instead of the
    # user's real state.  Undefined = normal AppData location.
    base = os.environ.get("SECUDRIVE_BASE_DIR")
    if base:
        from pathlib import Path
        return int(launch_gui(base=Path(base)) or 0)
    return int(launch_gui() or 0)


if __name__ == "__main__":
    raise SystemExit(main())