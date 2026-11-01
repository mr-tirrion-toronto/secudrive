"""report_formatter.py - plain-language scan reports for non-technical users.

The GUI (and the post-scan action dialog) builds a human-readable summary here
plus an optional technical deep-dive.  All numbers come from the scanner's
report dict and the action results - this module never touches the filesystem.

The plain-language HEADLINE follows the canonical format, e.g.:

    Scanned 42,301 files. Found 2 threat(s) - 2 cleaned and restored, 1 removed
    completely. Nothing requires your attention.

The trailing clause flips to "N item(s) still need your attention." whenever
anything was moved to Quarantine (incl. 'quarantined_after_attempts' and the
opt-in always-quarantine config) or flagged ``requires_manual_review``.  The
zero-data-loss detail sentence ("every step ran through a safe, encrypted
backup first") and the auto-purge / freed-bytes stats sit underneath as the
supporting copy - the headline is the plain-language takeaway, not a
replacement for the detail beneath it.

Language reflects the default 'on_detection == resolve' behavior: findings
are resolved IN PLACE when a safe strip point exists, moved to Quarantine
when they cannot be fixed in place, and auto-purged only for pure-malware
files under the silent background 'auto_purge_verified' retention policy.
"""
from __future__ import annotations

from typing import Dict, List, Optional


def _file_count(n: int) -> str:
    return f"{n:,}"


def headline(files: int, findings: int, cleaned: int = 0, removed: int = 0,
             attention_items: int = 0) -> str:
    """Canonical plain-language headline.

    ``cleaned`` counts findings resolved IN PLACE (stripped at the safe EOF
    marker, restored to their path); ``removed`` counts pure-malware files
    auto-purged completely.  ``attention_items`` covers anything Quarantined
    (incl. ``quarantined_after_attempts`` and the opt-in always-quarantine
    path) or flagged ``requires_manual_review`` - when nonzero the closing
    clause stops claiming "Nothing requires your attention".
    """
    head = f"Scanned {_file_count(files)} files. Found {findings} threat(s)"
    bits: List[str] = []
    if cleaned:
        bits.append(f"{cleaned} cleaned and restored")
    if removed:
        bits.append(f"{removed} removed completely")
    if bits:
        head = f"{head} — {', '.join(bits)}"
    clause = ("Nothing requires your attention." if attention_items == 0
              else f"{attention_items} item(s) still need your attention.")
    return f"{head}. {clause}"


def human_scan_summary(scan: Dict, cleaned: int = 0, quarantined: int = 0,
                       revealed: int = 0, attribs_fixed: int = 0,
                       auto_purged: int = 0, freed_bytes: int = 0,
                       errors: Optional[int] = None,
                       attention_items: Optional[int] = None) -> str:
    """Build the short user-facing paragraph for a finished scan.

    ``scan`` mirrors the ScanWorker payload: ``files``, ``findings``,
    ``errors``, ``duration_s``, ``cancelled``.  ``cleaned`` counts findings
    resolved IN PLACE (their payload stripped at the safe EOF marker, file
    left where it belongs); ``auto_purged``/``freed_bytes`` come from the
    silent-background Auto-Purge retention mode.  ``attention_items`` is how
    many findings still need the user (Quarantined / requires_manual_review /
    rolled_back / skipped); when omitted it defaults to ``quarantined`` so
    direct callers get the honest closing clause.
    """
    files = int(scan.get("files") or 0)
    findings = int(scan.get("findings") or 0)
    attention = (int(quarantined or 0) if attention_items is None
                 else int(attention_items or 0))
    if scan.get("cancelled"):
        return (
            f"Scan was stopped part-way: we had checked {_file_count(files)} "
            f"files and found {findings} problem(s) before you cancelled. "
            "Anything found is listed below - nothing has been modified yet."
        )
    if findings == 0:
        return headline(files, 0, 0, 0, attention)

    parts = [headline(files, findings, int(cleaned), int(auto_purged), attention)]

    acting = cleaned + quarantined + revealed + attribs_fixed + auto_purged
    if acting > 0:
        parts.append(
            f"SecuDrive {_acted_verb(cleaned, quarantined, revealed, attribs_fixed, auto_purged)}. "
            "Every step ran through a safe, encrypted backup first, so your "
            "original files are never lost - nothing is deleted before a "
            "verified copy exists.")
        if freed_bytes > 0:
            parts.append(
                f"In total, {freed_bytes:,} bytes were freed by auto-purge.")
    elif errors and errors > 0:
        parts.append(
            "Some items could not be fixed automatically and are listed below "
            "for you to decide what to do next.")
    else:
        parts.append(
            "SecuDrive has listed them below and will not touch them until you "
            "make a choice.")
    return " ".join(parts)


def _acted_verb(cleaned: int, quarantined: int, revealed: int,
                attribs_fixed: int, auto_purged: int) -> str:
    bits: List[str] = []
    if cleaned:
        bits.append(f"resolved {cleaned} file(s) in place")
    if quarantined:
        bits.append(f"moved {quarantined} file(s) to a safe quarantine folder")
    if auto_purged:
        bits.append(f"auto-purged {auto_purged} verified malware file(s)")
    if revealed:
        bits.append(f"revealed {revealed} hidden folder(s)")
    if attribs_fixed:
        bits.append(f"restored hidden attributes on {attribs_fixed} item(s)")
    if not bits:
        return "took care of the issue(s)"
    return ", ".join(bits)


def technical_details(scan: Dict, finding_rows: Optional[List[Dict]] = None,
                      actions: Optional[Dict] = None,
                      scan_id=None, targets=None) -> str:
    """Technical deep-dive shown behind the "Show Technical Details" expander."""
    lines: List[str] = []
    sid = scan_id or scan.get("scan_id")
    lines.append(f"Scan ID        : {sid or '-'}")
    lines.append(f"Files scanned  : {_file_count(int(scan.get('files') or 0))}")
    lines.append(f"Folders entered: {_file_count(int(scan.get('dirs') or 0))}")
    try:
        mb = int(scan.get("bytes") or 0) / (1024 * 1024)
        lines.append(f"Data scanned   : {mb:,.1f} MB")
    except (TypeError, ValueError, ZeroDivisionError):
        pass
    lines.append(f"Findings       : {int(scan.get('findings') or 0)}")
    err = scan.get("errors")
    err_count = len(err) if isinstance(err, (list, tuple)) else err
    lines.append(f"I/O errors     : {int(err_count) if err_count is not None else 0}")
    dur = scan.get("duration_s")
    if dur is not None:
        lines.append(f"Duration       : {float(dur):.1f} s")
    if targets:
        lines.append(f"Targets        : {', '.join(str(t) for t in targets)}")

    if actions:
        lines.append("")
        lines.append("Actions taken:")
        for key, label in (("disinfected", "Resolved in place"),
                           ("quarantined", "Quarantined"),
                           ("auto_purged", "Auto-purged (verified)"),
                           ("freed_bytes", "Storage freed by auto-purge"),
                           ("rolled_back", "Rolled back (restored)"),
                           ("revealed", "Hidden roots revealed"),
                           ("attribs_fixed", "Attributes restored"),
                           ("skipped_actions", "Skipped (kept as-is)")):
            val = actions.get(key)
            if val:
                lines.append(f"  - {label}: {int(val)}")

    rows = list(finding_rows or [])
    if rows:
        lines.append("")
        lines.append("Details of each finding:")
        by_name: Dict[str, int] = {}
        for r in rows:
            by_name[r.get("name", "unknown")] = by_name.get(
                r.get("name", "unknown"), 0) + 1
        for name, count in sorted(by_name.items()):
            lines.append(f"  - {name}: {count} file(s)")
        lines.append("")
        lines.append("(individual paths are shown in the scan results list)")
    return "\n".join(lines)


_ATTENTION_STATES = {
    "error", "failed", "would_quarantine", "quarantined_after_attempts",
    "requires_manual_review", "rolled_back", "skipped_actions"}


def _unresolved_findings(finding_rows: Optional[List[Dict]]) -> int:
    """Count findings still needing attention from their per-finding status.

    A row is unresolved when its ``status`` is a failed / quarantined /
    flagged-for-review state - i.e. exactly the rows the findings table
    renders as a red "Failed" (``error``) and its cousins.  This is what
    keeps the headline honest: if any row shows Failed but was never counted
    into the aggregate ``actions`` summary, the closing clause must still
    stop claiming "Nothing requires your attention".
    """
    if not finding_rows:
        return 0
    total = 0
    for row in finding_rows:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").lower()
        if status and status in _ATTENTION_STATES:
            total += 1
    return total


def unresolved_findings(finding_rows: Optional[List[Dict]]) -> int:
    """Public spelling: count folded findings still needing attention.

    Delegates to the underscore helper so the GUI headline and ``build_report``
    share exactly one attention definition (any per-finding ``Failed`` /
    ``error`` / flagged-for-review state flips the closing clause).
    """
    return _unresolved_findings(finding_rows)


def build_report(scan: Dict, finding_rows: Optional[List[Dict]] = None,
                 actions: Optional[Dict] = None, scan_id=None,
                 targets=None) -> Dict:
    """One-shot helper returning ``{"plain": str, "detailed": str}``."""
    actions = actions or {}
    attention_items = (int(actions.get("quarantined") or 0)
                       + int(actions.get("rolled_back") or 0)
                       + int(actions.get("requires_manual_review") or 0)
                       + int(actions.get("skipped_actions") or 0)
                       + int(actions.get("error") or 0)
                       + int(actions.get("failed") or 0))
    attention_items += _unresolved_findings(finding_rows)
    return {
        "plain": human_scan_summary(
            scan,
            cleaned=int(actions.get("disinfected") or 0),
            quarantined=int(actions.get("quarantined") or 0),
            revealed=int(actions.get("revealed") or 0),
            attribs_fixed=int(actions.get("attribs_fixed") or 0),
            auto_purged=int(actions.get("auto_purged") or 0),
            freed_bytes=int(actions.get("freed_bytes") or 0),
            errors=scan.get("errors"),
            attention_items=attention_items),
        "detailed": technical_details(scan, finding_rows, actions, scan_id,
                                      targets),
    }


def finding_to_plain(finding: Dict) -> str:
    """One-line plain-language description for the review/action dialog."""
    name = finding.get("name") or "suspicious item"
    path = str(finding.get("path") or "?")
    pretty: Dict[str, str] = {
        "SignatureMatch": "matches known malware",
        "Polyglot": "contains a hidden executable (polyglot file)",
        "EmbeddedSignature": "has known-malware code hidden inside it",
        "TrailingPayload": "has suspicious executable data appended to it",
        "HiddenRootFolder": "looks like a hidden-camouflage folder",
        "DoubleExtension": "file name hides its real type",
        "OfficeExploit": "office document with embedded macro/exploit hints",
        "ResignedPE": "signed executable repackaged with malware",
        "DangerousExtension": "executable-type file in a surprising place",
        "ExecutableInDocs": "executable inside a documents/office folder",
    }
    why = pretty.get(name, "needs your attention")
    return f"{path} - {why}"