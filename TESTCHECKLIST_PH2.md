# TEST CHECKLIST - Phase 3: Production-Readiness Fixes

Scope: crash-proofing, layout/resize, scan-state signals, live activity feed,
plain-language + actionable post-scan reports, quarantine persistence, version
metadata / signing, installer EULA + shortcuts, and Windows Security Center
registration.

Run automated checks first (they are the regression gate), then the manual
walks on a machine with a spare USB/HDD.

---

## A. Automated gate (run from the repo root)

```powershell
python -m compileall -q secudrive bootstrap.py
python C:\Users\MR_TIR~1\AppData\Local\Temp\opencode\gui_smoke3.py   # phase-3 smoke
python C:\Users\MR_TIR~1\AppData\Local\Temp\opencode\regress_run.py  # backend regression
```

| # | Check | Validated by |
|---|-------|--------------|
| 1 | Worker crash never kills QApplication; full traceback is in `secudrive_debug.log`; a non-fatal error dialog is produced (debounced). | smoke `worker_crash_survives` |
| 2 | `sys.excepthook` + `threading.excepthook` installed on GUI launch; a deliberately bad callback cannot take the app down. | smoke `global_hooks` |
| 3 | Window is resizable with `minimumWidth() == 900` and `minimumHeight() == 600`. | smoke `min_resize` |
| 4 | Sidebar `QListWidget` has uniform item sizes (42px row hints) and the UI is built once (`_build_ui` is guarded) - no duplicated stacked pages. | smoke `nav_unique` |
| 5 | Scan button state machine: on `scan_started` Start shows "Scanning..." + disabled and Stop enabled; on `scan_finished` / `scan_stopped` it flips back. Driven purely by the worker signals. | smoke `scan_button_state` |
| 6 | Live activity feed updates from real worker signals (scan progress, signature update/import, autopilot), and the idle line shows "Idle - last scan N min ago" after a scan. | smoke `activity_feed` |
| 7 | `report_formatter` produces a plain-language summary and a technical block; a scan with findings populates them. | smoke `report_plain` |
| 8 | A scan that finds findings summons the actionable dialog (Clean All / Quarantine All / Ignore / Review Individually); auto-mode surfaces a non-modal summary - never fully silent. | smoke `actions_dialog`/`auto_summary` |
| 9 | Quarantine page reloads history straight from `secudrive.db` on every refresh, dedupes rows, and stamps "Last synced". | smoke `quarantine_lastsynced` |
| 10 | Close + reopen DB: quarantine history persists, is not stale, no duplicates. | smoke `quarantine_persist` |
| 11 | `assets/version_info.txt` parses (CompanyName/Product/Copyright present) and is wired into the spec (`version=`). | smoke `version_meta` |
| 12 | `wsc_register` degrades gracefully: `security_center_status()` runs without crashing; without admin it returns a clear message and does not `registry-write`. | smoke `wsc_degrade` |
| 13 | Backend untouched: drive-target binding, dry-run banner, autopilot auto/off/prompt, signature import/update still pass. | regress_run + smoke |

## B. MANUAL - hot-plug a second HDD while a scan is running

Hot-plugging (bug #1) is the headline manual check:

1. Launch `dist\SecuDrive.exe` (accept UAC).
2. Drive Doctor: pick an external drive, click **Deep Clean** - or start a
   **Full Scan** on the Scanner page.
3. **While the scan/clean is running**, plug a second external HDD/USB stick
   into another port.
   - Within a few seconds it must appear in Drive Doctor and Scanner lists
     (typed label), WITHOUT restarting the app.
   - The running scan must NOT crash, freeze, or throw the error dialog more
     than once; it continues to completion.
4. **While the same scan is running**, yank the drive being scanned (or the
   newly attached one).
   - The app must keep running; the scan reports skipped files + I/O errors
     and ends gracefully; the tray icon remains.
5. Tray check (bug #1 / "never silently disappears"): during all of the above
   the tray icon must remain present. If you ever see a non-fatal dialog,
   that is ACCEPTABLE (bug #1 fix surfaced it) - the app must be alive after OK.

## C. MANUAL - resize to the minimum

1. App open. Drag the window edges: it must shrink to at least 900x600.
2. At the minimum size: sidebar rows must not overlap, the Scanner row not
   clip the buttons, and every page (Dashboard/Scanner/Quarantine/Drive
   Doctor/Logs) must be usable with scrolling where needed.
3. Maximize and restore - layouts must reflow, no black/stuck panes.

## D. MANUAL - close/reopen, quarantine history persists

1. Scan a fixture drive so 1-2 items end up quarantined (or use Drive Doctor
   Deep Clean on a harmless test stick).
2. Quarantine page shows the item; "Last synced" has a timestamp.
3. Close the app (tray icon disappears). Reopen it.
4. Quarantine page must show the SAME items (identical UIDs), in the same
   state - loaded from `secudrive.db`, not a stale cache, no duplicate rows.
5. Restore one item to its original path; close/reopen again; the restored
   item must still show status "restored" and the file must exist.

## E. MANUAL - post-scan report surfaces in auto-mode too (no silent action)

1. Set Dashboard policy to **Auto (recommended)**.
2. Arrange a removable drive with a test-as-detected file, then launch the app.
3. After the automatic pass finishes you must see a **non-modal summary**
   ("Scan finished...") even though the actions already happened, with an
   "Open Quarantine" button. Tray notification also fires.
4. Switch policy to **Scan only - never touch**, rescan the same drive: the
   actionable dialog must offer Clean All / Quarantine All / Ignore / Review
   Individually, and "Ignore" must leave files untouched.

## F. MANUAL - installer, version metadata, WSC (on an admin machine with Inno Setup 6 + a signing cert)

> Requires: ISCC.exe (Inno Setup 6.3.1+), a signing certificate (see
> `installer\SIGNING-NOTES.md`).  Not installed on this dev box - these are
> the documented acceptance steps.

1. `python build.py` -> confirm `dist\SecuDrive.exe`.
2. Explorer -> Properties -> Details: CompanyName "SecuDrive Software",
   ProductName "SecuDrive", FileDescription, Copyright must be filled
   (bug #9).  Without a cert, UAC still says "Unknown Publisher" - expected.
3. With a cert: `signtool verify /pa dist\SecuDrive.exe` passes; UAC shows
   the publisher name.
4. `ISCC.exe installer\SecuDrive.iss` -> `dist\SecuDriveSetup.exe`.
5. Run the installer: it must show the **Terms acceptance** page
   (`terms.txt`) before install can continue, and the Privacy notice on the
   Welcome page (bug #10).
6. The installer must create a **Start Menu** shortcut always, and a
   **Desktop** shortcut controlled by the opt-out checkbox (uncheck -> no
   desktop icon, bug #11).
7. Install must call `SecuDrive.exe --register-wsc` (bug #12); on Pro/Ent
   client Windows with admin the Security Center may list SecuDrive. On Home
   SKUs / Server it documents "not applicable" without crashing.
8. Uninstall removes the Start Menu + desktop shortcuts, unregisters WSC,
   and offers to keep user data.

---

## G. REAL-TIME FILE-SYSTEM PROTECTION (Phase 4)

Scope: continuous `ReadDirectoryChangesW` protection that reacts the instant a
file changes - not on a schedule - with debounced single-file scans, a bounded
thread pool, CPU-aware throttling, path/extension exclusions, and the same
Zero-Data-Loss quarantine pipeline as the rest of the app.

### Automated gate

```powershell
python C:\Users\MR_TIR~1\AppData\Local\Temp\opencode\realtime_smoke.py   # core 18 + GUI 9 checks
python C:\Users\MR_TIR~1\AppData\Local\Temp\opencode\gui_smoke3.py       # phase-3 smoke still green
python C:\Users\MR_TIR~1\AppData\Local\Temp\opencode\regress_run.py      # backend regression
python C:\Users\MR_TIR~1\AppData\Local\Temp\opencode\gui_smoke2.py       # real F:\ drive smoke
```

| # | Check | Validated by |
|---|-------|--------------|
| 1 | A known-bad file written to a watched root is quarantined automatically within seconds (default `rt_action=quarantine`). | `realtime_smoke` #2 |
| 2 | Zero Data Loss: an encrypted `.bak.aes` backup is secured before the live file is removed. | `realtime_smoke` #2 |
| 3 | Quarantine table records the `original_path`; the live file no longer exists. | `realtime_smoke` #2 |
| 4 | Clean files produce no detection (no false positives). | `realtime_smoke` #3 |
| 5 | Built-in exclusions honored - e.g. anything under `AppData` is never scanned even though `C:\` is watched; app data/backup/quarantine dirs; `secudrive.db`/key/debug log. | `realtime_smoke` #4 |
| 6 | Burst writes coalesce through the debounce - no detection flood. | `realtime_smoke` #5 |
| 7 | `add_root`/`remove_root`/`sync_roots` are stable, never hang, and calls after `stop()` are safe no-ops. | `realtime_smoke` #6/#8 |
| 8 | CPU throttle seam (`_set_paused`) pauses and resumes dispatch. | `realtime_smoke` #7 |
| 9 | `MainWindow` auto-arms RT at launch when `rt_enabled=True`; dashboard "Real-time protection" row shows Active + watched roots; the checkbox reflects state. | `realtime_smoke` gui |
| 10 | A real-time detection surfaces through the Qt bridge into the live activity feed (`REAL-TIME: <threat> <action> - <path>`). | `realtime_smoke` gui |
| 11 | GUI toggle OFF stops the monitor (`rt_enabled=False`); `close()` tears everything down without leaking threads/handles. | `realtime_smoke` gui |
| 12 | Existing phase-3 + backend behavior is unchanged (RT is opt-in; all automated smokes set `rt_enabled=False`). | smoke2/smoke3/regress |

### MANUAL walk (real machine, after `python build.py`)

1. Run `dist\SecuDrive.exe`, go to Dashboard, tick **Real-time protection**
   (or set `rt_enabled: true` in `secudrive.json` before launch).
2. The dashboard row and the live feed should show "watching N root(s)".
3. Drop a known test signature into `secudrive.db` (or use an offline import),
   then create a matching file anywhere outside the exclusions - it must be
   grabbed and shown in the feed within ~1 second, an encrypted backup must
   appear under `data\backups`, and the file must land in the Quarantine page.
4. Hot-unplug the USB drive while watching - the root is dropped silently and
   no error dialogs appear; replug and it is re-watched on the next poll.
5. Enable RT, then run a heavy scan - SecuDrive should throttle its own RT
   dispatches when process CPU stays at/above `rt_cpu_threshold`.
6. Toggle RT off and quit - no phantom processes, no stuck directory handles
   (unplug the drive after quitting to confirm it is released).

## H. COMPILED SCAN ENGINE (Phase 4, Rust/PyO3)

Scope: the hot walk+hash loop of `scanner.py` (`_walk`/`_scan_file`) can now run
in a compiled Rust extension (`secudrive_rust`) via PyO3 while every byte of
business logic (signature lookups, heuristics, disinfection, quarantine, GUI)
stays in Python unchanged. Results stream back as `FileHashResult` records;
Python feeds them through the identical `_check_signature` / heuristic sweep.

### One-time toolchain setup (manual, this machine)

1. `rustup`: install from https://rustup.rs (accept defaults, restart shell).
2. `python -m pip install "maturin>=1.7,<2.0"`
3. From the repo root: `python build.py` (builds the wheel, installs it into
   the active Python, then PyInstaller packages the `.pyd` into the exe).
   If the toolchain is absent the build script skips the step and the exe
   falls back to the pure-Python engine automatically.

### Automated gate

```powershell
python scripts\rust_smoke.py        # engine parity + hashes + cancel + sig finding (run from repo root)
python benchmark.py --files 20000   # files/sec before/after (repo root)
python scripts\fallback_smoke.py    # python engine still intact without the .pyd
```

| # | Check | Validated by |
|---|-------|--------------|
| 1 | `secudrive_rust` loads; a bare repo crate dir is NOT mistaken for the engine (namespace-package rejection). | `rust_smoke` #1 |
| 2 | files/dirs/bytes/errors counters match the pure-Python engine on the same tree. | `rust_smoke` #2 |
| 3 | Rust sha256+md5 output equals hashlib on a sample. | `rust_smoke` #3 |
| 4 | `.lnk` discovery surfaces in `outcome.lnk_dirs` so shortcut heuristics still run. | `rust_smoke` #4 |
| 5 | `max_depth` semantics match (bounded walk). | `rust_smoke` #5 |
| 6 | `max_hash_size` enforced: oversized files reported unhashed, heuristics still run. | `rust_smoke` #6 |
| 7 | A seeded signature produces the same signature finding through both engines. | `rust_smoke` #7 |
| 8 | Cancellation propagates `ScanCancelled`; progress callback fires. | `rust_smoke` #8 |
| 9 | Threads knob respected (`scan_threads` config / `--threads`; GUI/autopilot/CLI unchanged). | cli `--threads` |
| 10 | Benchmark shows a measurable speedup; fallback smoke passes when the engine is absent. | `benchmark` / `fallback_smoke` |

### MANUAL walk (real machine, after toolchain + `python build.py`)

1. Run `python benchmark.py --files 20000` from the repo root - expect
   `speedup > 1x` and the hash cross-check `OK`.
2. Run the full `dist\SecuDrive.exe` and do a full-drive scan of `F:\` plus a
   quick scan of `C:\` - live progress must still stream, then cancel with the
   GUI button (no freeze, clean unwind).
3. Confirm `data\logs\secudrive.log` shows `rust scan engine active` at first
   scan; delete/rename the `.pyd` and relaunch to see it fall back with a
   `using Python scan engine` line (still fully functional).