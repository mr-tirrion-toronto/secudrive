# SecuDrive

A Windows antivirus built in Python, with one main goal: **Zero Data Loss**. SecuDrive scans your drives, removes malware, and recovers files that were infected, locked or stuck in quarantine, so you do not lose your data when you clean a PC or flash drive.

## Download

Get the latest Windows installer from the [Releases page](https://github.com/mr-tirrion-toronto/secudrive/releases/latest).

> Windows may show an "Unknown publisher" warning because the installer is not yet code-signed.

## Features

- Scans internal drives, external HDD/SSD, USB flash drives and memory cards
- Quarantines or removes malware and recovers infected files
- Cleans autorun files and fake shortcuts from external drives
- Automatic malware signature updates from online feeds and local sources
- Real-time file-system protection
- Plain-language scan reports and an in-app activity feed
- Encrypted backups (Fernet) and an audit log in SQLite
- Optional Rust scan engine (`rust_engine/`) for faster scanning
- Platform layer for Windows, Linux and macOS (`secudrive/platform/`); Windows is the primary target

## Run from source

Requires Python 3.11 or newer.

```
pip install -r requirements.txt
python run.py
```

## Build the Windows installer

```
python build.py
```

Then compile `installer/SecuDrive.iss` with Inno Setup. Code-signing notes are in `installer/SIGNING-NOTES.md`.

## Project layout

| Folder | What it holds |
| --- | --- |
| `secudrive/` | Main package: scanner, recovery, heuristics, crypto, database, GUI, updater, real-time monitor |
| `secudrive/platform/` | Windows, Linux and macOS providers |
| `rust_engine/` | Optional Rust (PyO3) scan engine |
| `installer/` | Inno Setup script, terms and privacy text |
| `scripts/` | Smoke tests and test scripts |
| `assets/` | Icon and version info |

## Status

Actively developed. Windows 11 is the main supported platform; Linux and macOS support is experimental.

## Disclaimer

SecuDrive is provided as is. Keep backups of important data and do not rely on it as your only protection.
