"""Heuristic checks - stateless, side-effect-free detectors.

Every function returns a list of ``HeuristicFinding`` objects describing WHAT
was seen, WHY it looks suspicious, and a ``confidence`` in (0, 1].  Nothing in
this module touches the filesystem state - it is pure analysis - so it is safe
to call from a sandboxed thread or a future Rust-backed scanner worker.

Detectors shipped:
    * double-extension deception        (photo.jpg.exe)
    * fake-shortcut / shadowed file     (photo.jpg.lnk hiding photo.jpg)
    * autorun.inf / desktop.ini abuse   (open=, shell keys, executables)
    * script obfuscation markers        (base64 / IEX / -enc / encoder digests)
    * appended payload after EOF marker (PDF %%EOF, JPEG FFD9, PNG IEND, ZIP EOCD)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .logging_utils import get_logger
from .safefile import (looks_likely_script, looks_text, read_head, read_tail,
                       sniff_magic)

logger = get_logger("heuristics")

# --------------------------------------------------------------------------- data
@dataclass
class HeuristicFinding:
    path: Path
    name: str                       # threat/rule name, e.g. "DoubleExtension"
    evidence: str
    confidence: float = 0.5
    category: str = "heuristic"
    meta: dict = field(default_factory=dict)


# Document/media extensions that cyber-creeps like to impersonate.
DOC_LIKE_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".wmv",
    ".avi", ".zip", ".rar", ".7z", ".java", ".py",
}

# Double-extension: a real-looking extension followed by an executable one.
DOUBLE_EXT_RE = re.compile(
    r"""\.(?P<real>pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|bmp|mp3|mp4|wmv|avi|zip|rar|7z|txt|rtf|csv)\.(?P<fake>exe|com|bat|cmd|scr|pif|vbs|vbe|js|jse|wsf|wsc|cpl|jar|msi|hta)$""",
    re.IGNORECASE,
)

# Executables / runner files that mask as anything.
EXEC_LIKE_EXTS = {
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsc", ".cpl", ".jar", ".msi", ".hta", ".ps1", ".psm1",
    ".gadget",
}

# ------------------------------------------------------------------ fs recovery
# Known OS / filesystem-RECOVERY artifact directories.  Files under these trees
# are almost always *recovered user data* (photos / videos / documents rescued
# by fsck / chkdsk / OS file-scrubbers after an improper unmount or card
# ejection) with generated numeric names and no extension - NOT malware.  The
# TrailingPayload heuristic over-triggers on their fragmented content, so any
# automatic action (disinfect / quarantine / auto-purge) on them must be
# refused and routed to explicit human review.
_RECOVERY_DIRNAMES = frozenset({
    "lost.dir",                       # Android fsck recovery (numeric entries)
    "found.000",                      # placeholder kept for clarity below
    "$recycle.bin",                   # Windows recycle bin (SID-contained users)
    "system volume information",      # Windows VSS / indexing metadata
    ".trashes",                       # macOS Trash
    ".fseventsd",                     # macOS file-system events log
    ".spotlight-v100",                # macOS spotlight index
    ".temporaryitems",                # macOS drag/drop staging
})
_FOUND_REC_RE = re.compile(r"^found\.\d{3}$", re.IGNORECASE)      # found.000..999
_TRASH_RE = re.compile(r"^\.trash-[\w-]+$", re.IGNORECASE)        # .Trash-<id>


def is_recovery_data_path(path: object) -> bool:
    """True when ANY path component is a known OS/filesystem-recovery
    artifact directory (Android ``LOST.DIR``, chkdsk ``FOUND.NNN``,
    ``$RECYCLE.BIN``, macOS recovery/index dirs, ...).  Callers that perform
    automatic destructive/transformative actions on findings MUST check this
    first and refuse, surfacing the file for explicit manual review instead."""
    s = str(path)
    parts = [c for c in s.replace("\\", "/").split("/") if c]
    for part in parts:
        low = part.lower()
        if low in _RECOVERY_DIRNAMES or low == "found.000":
            return True
        if _FOUND_REC_RE.match(part) or _TRASH_RE.match(part):
            return True
    return False

# String tokens that make an .lnk or autorun target look hostile.
_DANGER_TOKENS = (
    "cmd.exe", "cscript", "wscript", "powershell", "pwsh", "mshta", "rundll32",
    "certutil", "regsvr32", "wmic", "forfiles", "bitsadmin", "schtasks",
    "downloadstring", "-enc", "-e ", " -enc ", "frombase64string", "reg add",
)

_TEMP_ISH = re.compile(r"(\\temp\b|\\appdata\\|\\programdata\\|%temp%|%appdata%)", re.IGNORECASE)

# Firefox-style / IE-style .lnk does NOT count: only paths that (a) hit temp/appdata
# and (b) carry an EXEC_LIKE extension or a danger token are flagged.
def _lnk_has_hostile_target(strings: List[str]) -> Optional[str]:
    for s in strings:
        low = s.lower()
        if not _TEMP_ISH.search(low):
            continue
        if any(ext + " " in low + " " for ext in (".exe",)) or any(low.endswith(ext) for ext in EXEC_LIKE_EXTS):
            return s.strip()[:160]
    for s in strings:
        low = s.lower()
        if any(tok in low for tok in ("-enc", "downloadstring", "certutil -decode", "mshta", "rundll32 javascript")):
            return s.strip()[:160]
    return None


def _extract_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Extract printable ASCII and UTF-16-LE strings from a binary blob (LNK targets)."""
    out: List[str] = [m.group().decode("ascii", "ignore")
                      for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    try:
        text = data.decode("utf-16-le", "replace")
        out += [m.group() for m in re.finditer(r"[\x20-\x7e]{%d,}" % min_len, text)]
    except Exception:
        pass
    return out


# ------------------------------------------------------------------ detectors
def check_double_extension(path: Path) -> List[HeuristicFinding]:
    findings: List[HeuristicFinding] = []
    m = DOUBLE_EXT_RE.search(path.name)
    if m:
        findings.append(HeuristicFinding(
            path=path,
            name="DoubleExtension",
            confidence=0.9,
            evidence=(f"file is disguised as {m.group('real').upper()} but is actually "
                      f"{m.group('fake').upper()}"),
        ))
    return findings


def check_fake_shortcut(lnk_path: Path, sibling_names_lower: set) -> List[HeuristicFinding]:
    """A real-file-shadowing .lnk: 'photo.jpg.lnk' exists while 'photo.jpg' does not."""
    findings: List[HeuristicFinding] = []
    name = lnk_path.name
    if not name.lower().endswith(".lnk"):
        return findings
    base = name[:-4]                      # strip .lnk
    ext = Path(base).suffix.lower()
    if ext in DOC_LIKE_EXTS and base.lower() not in sibling_names_lower:
        findings.append(HeuristicFinding(
            path=lnk_path,
            name="FakeShortcutShadowing",
            confidence=0.88,
            evidence=(f"'{base}' is advertised by a shortcut but the real file is missing "
                      f"- classic USB payload hiding"),
        ))
    return findings


def check_lnk_hostile_target(lnk_path: Path) -> List[HeuristicFinding]:
    """Parse .lnk binary for embedded target paths that point at runners in temp."""
    findings: List[HeuristicFinding] = []
    try:
        head = read_head(lnk_path, 64 * 1024)
        tail = read_tail(lnk_path, 64 * 1024)
        strings = _extract_strings(head + tail)
    except Exception:
        return findings
    if not strings:
        return findings
    hostile = _lnk_has_hostile_target(strings)
    if hostile:
        findings.append(HeuristicFinding(
            path=lnk_path,
            name="LNKHostileTarget",
            confidence=0.75,
            evidence=f"shortcut embeds target path under temp/appdata: {hostile}",
        ))
    return findings


_AUTORUN_EXEC_RE = re.compile(
    r"""^\s*(open|shell\\(open|explore|autorun)\\command|startup)\s*=\s*\S+"""
    r"""\.(exe|com|bat|cmd|vbs|vbe|js|jse|wsf|hta|scr|pif|msi|jar)\b""",
    re.IGNORECASE | re.MULTILINE,
)
_AUTORUN_INTERP_RE = re.compile(
    r"(powershell|wscript|cscript|mshta|rundll32|certutil|regsvr32|cmd\.exe|bitsadmin)",
    re.IGNORECASE,
)


def check_autorun_inf(path: Path) -> List[HeuristicFinding]:
    """Flag autorun.inf / desktop.ini whose directives launch code."""
    findings: List[HeuristicFinding] = []
    lower = path.name.lower()
    if lower not in ("autorun.inf", "desktop.ini"):
        return findings
    content = read_head(path, 32 * 1024)          # both files are tiny, this is ample
    if not content:
        return findings
    try:
        text = content.decode("utf-8", "replace")
    except Exception:
        text = content.decode("latin-1", "replace")

    matched = ""
    m = _AUTORUN_EXEC_RE.search(text)
    if m:
        matched = m.group(0).strip()
    elif _AUTORUN_INTERP_RE.search(text):
        found = _AUTORUN_INTERP_RE.search(text)
        matched = f"interpreter reference: {found.group(1)}"
    if matched:
        findings.append(HeuristicFinding(
            path=path,
            name="AutorunExecutable" if lower == "autorun.inf" else "DesktopIniExec",
            confidence=0.95 if lower == "autorun.inf" else 0.7,
            evidence=f"autorun-style file contains launch directive: {matched}",
        ))
    return findings


_OBFUSCATION_MARKERS = (
    "iex", "invoke-expression", "invoke-expression", "frombase64string",
    "certutil -decode", "-enc", "mshta", "wscript.shell", "shell.run",
    "downloadstring", "reg add", "schtasks", re.compile(r"#@~\^", re.I),
    re.compile(r"1jlc3bvc2uaq==", re.I),   # base64 of "Response" (JSE encoder)
)


def check_script_payload(path: Path, size: int) -> List[HeuristicFinding]:
    """Obfuscation markers in script-ish files (small files only, head+tail windows)."""
    findings: List[HeuristicFinding] = []
    if size > 1024 * 1024 or size <= 0:
        return findings
    if not looks_likely_script(path.name):
        return findings
    head = read_head(path, 4096).decode("utf-8", "replace")
    tail = read_tail(path, 4096).decode("utf-8", "replace")
    blob = (head + tail).lower()
    hits = []
    for marker in _OBFUSCATION_MARKERS:
        probe = marker.pattern.lower() if isinstance(marker, re.Pattern) else marker
        if probe in blob:
            hits.append(probe.strip())
    if len(hits) >= 2:
        findings.append(HeuristicFinding(
            path=path,
            name="ObfuscatedScript",
            confidence=0.8,
            evidence=f"obfuscation markers detected: {', '.join(set(hits))[:200]}",
        ))
    elif any(h in hits for h in ("downloadstring", "-enc", "certutil -decode")):
        findings.append(HeuristicFinding(
            path=path,
            name="DownloadCradleScript",
            confidence=0.85,
            evidence=f"payload-download marker: {hits[0]}",
        ))
    return findings


def check_trailing_payload(path: Path, head: bytes, tail: bytes, size: int) -> List[HeuristicFinding]:
    """Detect bytes appended after a valid container EOF marker (polyglot payloads)."""
    findings: List[HeuristicFinding] = []
    if size < 64 or not head:
        return findings
    magic = sniff_magic(head)
    if magic is None:
        return findings

    markers = {
        "jpeg": (b"\xff\xd9", 2),
        "png":  (b"IEND\xaeB`\x82", 12),
        "gif":  (b"\x3b", 1),
        "pdf":  (b"%%EOF", 5),
        "zip":  (b"PK\x05\x06", 22),   # End Of Central Directory
    }
    if magic not in markers:
        return findings
    marker, marker_len = markers[magic]
    pos = tail.rfind(marker)
    if pos == -1:
        return findings
    trailing = len(tail) - (pos + marker_len)
    if trailing < 32:                     # ignore trivial terminal whitespace/newlines
        return findings
    findings.append(HeuristicFinding(
        path=path,
        name="TrailingPayload",
        confidence=0.82,
        evidence=(f"{trailing} bytes follow the valid {magic} end-of-file marker "
                  f"(appended malicious payload)"),
        meta={"trailing_bytes": trailing, "magic": magic},
    ))
    return findings


# ------------------------------------------------------------------ aggregator
def run_file_heuristics(path: Path, size: Optional[int] = None) -> List[HeuristicFinding]:
    """Full-file heuristic sweep used by the scanner and pre-disinfect checks."""
    findings: List[HeuristicFinding] = []
    if size is None:
        st = path.stat() if Path(path).exists() else None
        size = st.st_size if st else 0

    findings += check_double_extension(path)
    findings += check_autorun_inf(path)
    findings += check_script_payload(path, size)

    if size > 0:
        head = read_head(path, 64 * 1024)
        tail = read_tail(path, 64 * 1024)
        if head and not looks_text(head):
            findings += check_trailing_payload(path, head, tail, size)
    return findings


def run_lnk_heuristics(lnk_path: Path, sibling_names_lower: Iterable[str]) -> List[HeuristicFinding]:
    findings: List[HeuristicFinding] = []
    siblings = set(sibling_names_lower)
    findings += check_fake_shortcut(lnk_path, siblings)
    findings += check_lnk_hostile_target(lnk_path)
    return findings