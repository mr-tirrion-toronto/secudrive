# SecuDrive - Manual TEST CHECKLIST

Verify against the rebuilt `dist\SecuDrive.exe` (run it as Administrator the
first time so UAC + device notification register; the tray icon appears).

## 1. External drive detection (SSD / HDD / USB)
- [ ] Plug in the external SSD named **"USB Drive (F:)"** (do it while the app is running).
- [ ] It appears in the **Drive Doctor** dropdown **within ~3 seconds** - **without restarting the app**.
- [ ] The label shows its type, e.g. `F:\ - USB Flash (Removable)` or
      `F:\ - External SSD/HDD (Fixed)` (hover shows the volume name).
- [ ] Unplug the drive -> the entry disappears from the dropdown without restart.
- [ ] Replug -> it returns.

## 2. No silent default fallback (bug #1)
- [ ] While a drive is selected, click **Clean** / **Reveal Hidden** / **Immunize** /
      **Quick Scan** and confirm the report header names **exactly the drive you picked**.
- [ ] Unplug every external drive (list shows `<no external drive detected>` and is disabled).
- [ ] Click any button -> an **on-screen error** appears ("ERROR: no valid drive selected...").
      It must NEVER fall back to `C:\Users\<you>` or any other folder.
- [ ] Switch between `F:\` and `D:\` in the dropdown and click again - the action
      must follow the newly selected drive, not the first one you picked.

## 3. Dry-run accuracy (bug #2)
- [ ] Tick **"Dry run (no changes)"** - a persistent red **DRY RUN MODE ON** banner appears.
- [ ] Click **Clean** while dry-run is ON: report says **"dry run - nothing was modified"**,
      and the drive is untouched (file timestamps/dates unchanged).
- [ ] Untick the box, click **Clean** again: the banner disappears and the action
      REALLY runs now. (State is read from the tick-box at every single click.)
- [ ] Toggle dry-run a few times and confirm each click matches the tick-box state.

## 4. Launch-time auto service (new `autopilot.py`)
- [ ] Set **Auto-scan on launch = Auto** on the Dashboard (and **Auto signature update** ON).
- [ ] Restart the app. On the **"Logs & Audit"** page you should see (or the tray should
      notify): `Scanned N files - X disinfected, Y quarantined, Z attributes restored`.
- [ ] Plug in a USB drive with a suspicious file (e.g. `Invoice.pdf.exe`, or a
      `photo.jpg` with bytes appended past the `FFD9` marker). The auto pass detects it.
- [ ] The file was NOT deleted blindly: check `data\backups\*.bak.aes` exists for every
      act (encrypted zero-data-loss backups) and the file shows up on the Quarantine page.
- [ ] Set **prompt** mode: each finding pauses with a question dialog - **Disinfect**,
      **Quarantine**, or **Skip** decides; choosing Skip does nothing to that file.
- [ ] Set **off**: findings are counted and reported only, nothing is touched.

## 5. Signature updater (online + local)
- [ ] Dashboard shows **"Last updated: <time>"** after startup / on the 6-hour cycle.
- [ ] Dashboard **Import signatures...** - pick a CSV (e.g. URLhaus CSV) or JSON file;
      rows appear as `Added 3 of 3`, etc. Drag & drop a file onto the Dashboard also works.
- [ ] Disconnect the network, press **Update now**: no crash, clean "offline / failed"
      message, previously stored signatures still work.

## 6. Debug logging
- [ ] With the app running, click a few Drive Doctor buttons.
- [ ] **Logs & Audit** page has a **Debug** tab showing `GUI action:` lines with
      `target='F:\'`, `dry_run=True/False`, `command=...`.
- [ ] `secudrive_debug.log` exists next to the app data folder and contains the same lines.

## 7. Regressions (tray / quarantine)
- [ ] Tray icon shows; double-click restores the window.
- [ ] A quarantined file can be **restored** and **purged** from the Quarantine page.