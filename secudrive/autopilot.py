"""autopilot.py - fully automatic scan -> repair -> remove -> notify service.

Runs off the UI thread the moment SecuDrive launches:

    1. optionally refresh online signature hashes (non-fatal),
    2. silent scan over C:\\ plus every mounted external/removable drive,
    3. auto-repair (disinfect / quarantine / restore hidden attributes),
    4. summary signal for a Windows toast/tray notification.

ZERO DATA LOSS INVARIANT - this automatic path is NOT allowed to shortcut the
mandatory safety pipeline.  Every single action goes through
``RecoveryEngine``:

    encrypted BACKUP -> SANDBOX (byte stream, never execute)
    -> DISINFECT -> VERIFY -> ROLLBACK on failure

so an automatic pass is no more destructive than a manual one: the original
bytes always exist (encrypted) under ``backups/`` before anything is touched,
and any failed disinfection is rolled back from that backup.  No ``os.remove``,
no ``shutil.rmtree``, no raw renames, no bypassing the engine - ever.

Action policy (config ``auto_action_policy``):

    'auto'   disinfect / quarantine silently (default).
    'prompt' block on ``respond()`` per acting step; the GUI asks the user
             before anything is changed (cautious mode).
    'off'    scan only - findings counted and reported, never touched.

Default course of action (config ``on_detection``, default ``'resolve'``): a
finding is resolved IN PLACE from an encrypted backup when a safe EOF-marker
strip point exists (jpg/png/gif/pdf/zip), and only moved to the encrypted
Quarantine store when an in-place fix is not possible.  The old always-
quarantine behavior is the opt-in ``on_detection == 'quarantine'`` value.
Both the automatic flow and every manual per-item handler route through the
same ``resolve_plan()`` + ``execute_plan()`` path, so behavior is identical.

Retention (config ``quarantine_retention_mode``, default ``auto_purge_verified``):
pure-malware files (confident live full-file signature hits, non-container
extensions only) can be backup -> deleted -> verified -> their short-lived
encrypted backup purged, freeing storage; any doubt falls back to long-term
Quarantine.  Auto-purge applies ONLY in the silent background flow
(``auto_action_policy == 'auto'``): prompt mode and every manual per-item
handler keep the current Quarantine behavior, never auto-purge.
``purge_after_days`` relies on the GUI background sweep.

The worker is fully cancellable; a cancelled pass still reports partial stats
and never leaves a file half-processed (acting steps are atomic per file).
"""
from __future__ import annotations

import os
import threading
import time
import sys
from typing import Dict, List, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from . import crashguard
from .logging_utils import get_logger

logger = get_logger("autopilot")

#: Decisions the GUI passes back through ``respond()``.
DISINFECT = "disinfect"
QUARANTINE = "quarantine"
SKIP = "skip"

_PROMPT_TIMEOUT_S = 600          # have mercy on the user; auto-skip if idle


def _is_mount_point(path) -> bool:
    """True for drive/volume roots and any local mount point (C:\\, a mounted
    USB stick, a network share...).  Mirrors scanner.py's guardrail."""
    import pathlib
    p = pathlib.Path(str(path)).resolve()
    try:
        return os.path.ismount(str(p))
    except OSError:
        return False


class AutoPilotWorker(QThread):
    """Launch-time service.  Signals: progress / waiting / finished.

    ``waiting_sig(dict)`` is emitted in ``prompt`` mode right before an action;
    the GUI responds with ``worker.respond(DISINFECT|QUARANTINE|SKIP)``.
    """

    progress_sig = pyqtSignal(str)
    waiting_sig = pyqtSignal(dict)
    finished_sig = pyqtSignal(dict)

    def __init__(self, ctx, updater, targets: List[str], options,
                 policy: str = "auto", parent=None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.updater = updater
        self.targets = list(targets or [])
        self.options = options
        self.policy = (policy or "auto").lower()
        if self.policy not in ("auto", "prompt", "off"):
            self.policy = "auto"
        self._cancel = threading.Event()
        self._decision_event = threading.Event()
        self._decision: Optional[str] = None
        self.report: Dict = {
            "policy": self.policy,
            "sig_feed": None,
            "scan": {"files": 0, "dirs": 0, "errors": [], "findings": 0,
                     "targets": list(self.targets)},
            "disinfected": 0, "quarantined": 0, "rolled_back": 0,
            "auto_purged": 0, "freed_bytes": 0,
            "requires_manual_review": 0,
            "revealed": 0, "attribs_fixed": 0, "skipped_actions": 0,
            "errors": [],
        }

    # ------------------------------------------------------------ lifecycle
    def cancel(self) -> None:
        """Ask the worker to stop at the next safe boundary."""
        self._cancel.set()
        self._decision_event.set()

    def respond(self, decision: str) -> None:
        """GUI thread: deliver the prompt-mode decision."""
        self._decision = decision
        self._decision_event.set()

    def run(self) -> None:
        crashguard.safe_run(self.worker_name(), self._run_body,
                            error_hook=self._crash_hook)

    def worker_name(self) -> str:
        return "autopilot"

    def _crash_hook(self, _msg: str) -> None:
        self.report["errors"].append("autopilot crashed (see debug log)")
        self.finished_sig.emit(self.report)

    def _run_body(self) -> None:
        start = time.time()
        self.report["started"] = time.strftime("%Y-%m-%d %H:%M:%S")
        logger.info("autopilot started policy=%s targets=%d",
                    self.policy, len(self.targets))
        try:
            self.ctx.db.audit(
                "autopilot_start",
                f"policy={self.policy} targets={len(self.targets)}")
            self._step_signatures()
            if self.targets and not self._cancel.is_set():
                self._step_scan_and_act()
        except Exception:
            # Keep the service alive - route through crashguard so the GUI
            # shows a non-fatal dialog instead of the app silently vanishing.
            crashguard.report_exception(self.worker_name() + ".run",
                                        sys.exc_info()[1],
                                        sys.exc_info()[2])
            self.report["errors"].append("autopilot crashed")
        finally:
            self.report["duration_s"] = round(time.time() - start, 1)
            try:
                self.ctx.db.audit(
                    "autopilot_finish",
                    f"files={self.report['scan']['files']} "
                    f"findings={self.report['scan']['findings']} "
                    f"disinfected={self.report['disinfected']} "
                    f"quarantined={self.report['quarantined']} "
                    f"auto_purged={self.report['auto_purged']} "
                    f"freed_bytes={self.report['freed_bytes']} "
                    f"skipped={self.report['skipped_actions']}")
            except Exception:
                pass
            self.finished_sig.emit(self.report)

    # ------------------------------------------------------------- step 1: sigs
    def _scan_progress(self, info: dict) -> None:
        """Scanner progress callback -> plain-language live feed lines."""
        try:
            path = str(info.get("path") or "scanning...")
            files = info.get("files_seen") or 0
            dirs = info.get("dirs_seen") or 0
            findings = info.get("findings") or 0
            if info.get("event") == "file":
                self.progress_sig.emit(
                    f"Scanning {path} - {files:,} files, "
                    f"{findings} finding(s)")
            elif info.get("event") == "dir":
                self.progress_sig.emit(
                    f"Entering {path} ({dirs:,} folders in)")
        except Exception:
            pass  # progress formatting must never take the service down

    def _step_signatures(self) -> None:
        if self.updater is None:
            return
        self.progress_sig.emit("Updating malware signatures (online feeds)...")
        try:
            self.report["sig_feed"] = self.updater.update_all()
        except Exception as exc:
            self.report["errors"].append(f"signature update failed: {exc}")
            self.report["sig_feed"] = {"status": "error", "errors": [str(exc)]}

    # ----------------------------------------------------- steps 2+3: scan+act
    def _step_scan_and_act(self) -> None:
        from .scanner import ScanCancelled, Scanner

        self.progress_sig.emit(
            f"Silent scan scheduled on {len(self.targets)} target(s)...")
        scanner = Scanner(self.ctx.db, self.options,
                          progress=self._scan_progress,
                          cancel_event=self._cancel)
        try:
            scan = scanner.scan(self.targets)
            persisted = scanner.persist()
        except ScanCancelled:
            scan = scanner.report
            persisted = 0
        self.report["scan"] = {
            "files": scan.files_seen, "dirs": scan.dirs_seen,
            "errors": scan.errors, "persisted": persisted,
            "findings": len(scan.findings), "targets": list(self.targets),
            "scan_id": scan.scan_id,
        }
        self.progress_sig.emit(
            f"Scan complete: {scan.files_seen} files, {len(scan.findings)} "
            f"finding(s).")

        if self.policy == "off" or self._cancel.is_set():
            return

        engine = self.ctx.ensure_engine()
        for finding in scan.sorted_findings():
            if self._cancel.is_set():
                break
            self._handle_finding(engine, finding)
        self._reveal_root_attributes(engine)

    def _handle_finding(self, engine, finding) -> None:
        """Route ONE finding through the engine (never destructive directly)."""
        if not finding.path.exists():
            return
        if (finding.category == "heuristic"
                and finding.name == "HiddenRootFolder"):
            if _is_mount_point(finding.path):
                # Guardrail mirroring the scanner: drive/volume roots never
                # enter the reveal flow (a recursive reveal would walk the
                # whole volume).  Recorded for manual review only.
                self.report["requires_manual_review"] += 1
                self.progress_sig.emit(
                    f"Drive root flagged - manual review only: {finding.path}")
                return
            decision = DISINFECT
            if self.policy == "prompt":
                decision = self._ask(finding, kind="reveal")
                if decision == SKIP:
                    self.report["skipped_actions"] += 1
                    return
            if decision != SKIP:
                try:
                    rec = engine.reveal_hidden(finding.path, dry_run=False)
                    self.report["revealed"] += len(rec.get("changed", []))
                except Exception as exc:
                    self.report["errors"].append(f"reveal {finding.path}: {exc}")
            return

        if not finding.path.is_file() or finding.path.is_symlink():
            return

        # Recovered user data (Android LOST.DIR / chkdsk FOUND.NNN /
        # $RECYCLE.BIN / macOS recovery dirs...) is almost NEVER malware:
        # fs/OS recovery artifacts hold rescued photos/videos/documents with
        # numeric names and no extension.  The TrailingPayload heuristic
        # over-triggers on their fragmented content, so the automatic
        # disinfect/quarantine/auto-purge pipeline MUST NOT touch them - a
        # previous build moved hundreds of legitimate recovered files to
        # quarantine this way.  In silent 'auto' mode we leave the file in
        # place and record it for explicit manual review; in 'prompt' mode the
        # user is the review (decision defaults to SKIP).
        from .heuristics import is_recovery_data_path
        if is_recovery_data_path(finding.path):
            self.report["requires_manual_review"] += 1
            self.progress_sig.emit(
                f"Recovered-data artifact - manual review only: {finding.path}")
            if self.policy == "auto":
                self.ctx.db.audit(
                    "manual_review_required",
                    f"{finding.path} under OS recovery dir - left untouched")
                return
            self.report["errors"].append(
                f"{finding.path}: recovered-data artifact flagged for review")

        self.progress_sig.emit(f"Handling finding: {finding.path}")
        decision = DISINFECT
        if self.policy == "prompt":
            decision = self._ask(finding, kind="disinfect")
            if decision == SKIP:
                self.report["skipped_actions"] += 1
                return

        try:
            if decision == QUARANTINE:
                rec = engine.execute_outcome_b(finding.path, finding)
                if rec.get("status") == "quarantined":
                    self.report["quarantined"] += 1
                else:
                    self.report["errors"].append(
                        f"{finding.path}: {rec.get('reason', 'quarantine failed')}")
                return

            # Auto-Purge is a SILENT-BACKGROUND flow ONLY.  It fires solely when
            # the launch-time service runs fully automatically
            # (auto_action_policy == 'auto') AND auto_purge_verified is enabled.
            # Prompt mode makes the user personally review + approve each action
            # in the moment, so it - like every manual per-item handler in the
            # Findings viewer (which calls engine.execute_outcome_a directly and
            # never reaches this branch) - always keeps the current Quarantine
            # behavior regardless of quarantine_retention_mode: a file the user
            # is actively deciding on is NEVER auto-purged.  Any doubt or verify
            # failure also falls back to Quarantine - never a silent delete.
            if (self.policy == "auto" and
                    str(self.ctx.cfg.get("quarantine_retention_mode", "keep_forever"))
                    == "auto_purge_verified"):
                from .recovery import is_auto_purge_candidate
                if is_auto_purge_candidate(finding.path, self.ctx.db, finding):
                    rec = engine.purge_verified_file(
                        finding.path, threat=finding.name,
                        expected_sha=getattr(finding, "sha256", None))
                    if rec.get("status") == "auto_purged":
                        self.report["auto_purged"] += 1
                        self.report["freed_bytes"] += int(rec.get("freed_bytes") or 0)
                        self.progress_sig.emit(
                            f"Auto-purged pure malware: {finding.path} "
                            f"({rec.get('freed_bytes', 0)} bytes recovered)")
                        return
                    if rec.get("requires_manual_review"):
                        # Deletion blocked by a transient file-lock after
                        # retries: NOTHING is wrong evidence-wise, so the file
                        # is NOT quarantined and NOT deleted - it is flagged for
                        # the user to close the handle and review.
                        self.report["requires_manual_review"] += 1
                        self.progress_sig.emit(
                            f"Deletion locked - flagged for manual review: "
                            f"{finding.path} ({rec.get('reason', 'locked')})")
                        try:
                            self.ctx.db.audit(
                                "manual_review_required",
                                f"{finding.path} - delete blocked after retries; "
                                "left in place for manual review")
                        except Exception:  # noqa: BLE001 - audit never breaks resolve
                            pass
                        return
                    if rec.get("file_present"):
                        q = engine.quarantine_file(finding.path,
                                                   threat=finding.name)
                        if q.get("status") == "quarantined":
                            self.report["quarantined"] += 1
                        else:
                            self.report["errors"].append(
                                f"{finding.path}: auto-purge fallback quarantine "
                                f"failed: {q.get('reason')}")
                    else:
                        self.report["errors"].append(
                            f"{finding.path}: {rec.get('reason', 'auto-purge failed')}")
                    return

            # Immediate-resolve default.  One shared classifier (resolve_plan)
            # decides the outcome for the auto flow AND every manual per-item
            # handler, so a finding always behaves the same: resolve IN PLACE
            # from an encrypted backup when a safe EOF-marker strip point
            # exists (Outcome A), otherwise move the live copy into the
            # quarantine store (Outcome B).  The old always-quarantine default
            # is now the opt-in ``on_detection == "quarantine"`` config value.
            # In prompt mode the user's explicit Disinfect choice wins over the
            # opt-in config, so config=None.
            from .recovery import PLAN_QUARANTINE, resolve_plan
            plan = resolve_plan(
                finding.path, self.ctx.db, finding,
                config=None if self.policy == "prompt" else self.ctx.cfg,
                head_window=engine.head_window, tail_window=engine.tail_window,
                min_trailing_payload=engine.min_trailing_payload)
            rec = engine.execute_plan(plan, finding.path, finding)
            outcome = rec.get("outcome") or rec.get("status")
            if outcome == "resolved_in_place":
                self.report["disinfected"] += 1
            elif (outcome in ("quarantined_removed", "fell_back_to_quarantine",
                              "quarantined_after_attempts")
                    or rec.get("status") == "quarantined"):
                self.report["quarantined"] += 1
            elif outcome == "rolled_back" or rec.get("status") == "rolled_back":
                self.report["rolled_back"] += 1
            elif outcome == "revealed":
                self.report["revealed"] += len(rec.get("changed", []))
            elif outcome == "skipped" or rec.get("status") == "skipped":
                self.report["skipped_actions"] += 1
            else:
                # Engine could not act safely; persistent malware is moved to
                # quarantine rather than blindly touched.
                if (plan.get("plan") != PLAN_QUARANTINE
                        and finding.confidence >= 0.9
                        and not self._cancel.is_set()):
                    q = engine.quarantine_file(finding.path, threat=finding.name)
                    if q.get("status") == "quarantined":
                        self.report["quarantined"] += 1
                    else:
                        self.report["errors"].append(
                            f"{finding.path}: {q.get('reason')}")
                else:
                    self.report["errors"].append(
                        f"{finding.path}: {rec.get('reason') or rec.get('outcome_detail')}")
        except Exception as exc:
            self.report["errors"].append(f"resolve {finding.path}: {exc}")

    def _reveal_root_attributes(self, engine) -> None:
        """Restore hidden/system attributes on every scanned root so persistent
        "hidden folder" malware loses its camouflage.  Safe, reversible."""
        for target in self.targets:
            if self._cancel.is_set():
                break
            try:
                rec = engine.reveal_hidden(target, dry_run=False)
                self.report["attribs_fixed"] += len(rec.get("changed", []))
            except Exception as exc:
                self.report["errors"].append(f"reveal {target}: {exc}")

    def _ask(self, finding, kind: str) -> str:
        """Prompt mode: block the worker until the GUI replies."""
        self._decision_event.clear()
        self._decision = None
        self.waiting_sig.emit({
            "kind": kind,
            "path": str(finding.path),
            "threat": finding.name,
            "category": finding.category,
            "confidence": finding.confidence,
        })
        self._decision_event.wait(_PROMPT_TIMEOUT_S)
        if not self._decision_event.is_set() or self._cancel.is_set():
            return SKIP
        decision = self._decision or SKIP
        self._decision = None
        return decision if decision in (DISINFECT, QUARANTINE, SKIP) else SKIP

    # ------------------------------------------------------------ notify text
    def summarize(self) -> str:
        """One-line tray/notification body, e.g.::

            Scanned 42,301 files. Found 2 threat(s) - 2 cleaned and restored,
            1 removed completely. Nothing requires your attention.

        The closing clause flips to "N item(s) still need your attention."
        whenever anything was Quarantined (incl. ``quarantined_after_attempts``
        and the opt-in always-quarantine config) or flagged
        ``requires_manual_review``.
        """
        from .report_formatter import headline
        scan = self.report.get("scan") or {}
        attention = (int(self.report["quarantined"])
                     + int(self.report["rolled_back"])
                     + int(self.report.get("requires_manual_review") or 0)
                     + int(self.report["skipped_actions"]))
        body = headline(int(scan.get("files") or 0),
                        int(scan.get("findings") or 0),
                        int(self.report["disinfected"]),
                        int(self.report["auto_purged"]), attention)
        extras = []
        if self.report["attribs_fixed"]:
            extras.append(f"{self.report['attribs_fixed']} attributes restored")
        if self.report["freed_bytes"]:
            extras.append(f"{self.report['freed_bytes']:,} bytes freed")
        if self.report["errors"]:
            extras.append(f"{len(self.report['errors'])} warning(s)")
        if extras:
            body = f"{body} ({'; '.join(extras)})"
        return body