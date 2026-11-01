# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""test_report_language.py - regression test for the plain-language report copy.

Guards the rewritten ``report_formatter`` wording for the IMMEDIATE-RESOLVE
default:

  * the plain-language HEADLINE follows the canonical format::

        Scanned 42,301 files. Found 2 threat(s) - 2 cleaned and restored,
        1 removed completely. Nothing requires your attention.

    and the trailing clause flips to "N item(s) still need your attention."
    whenever anything was Quarantined (incl. ``quarantined_after_attempts``
    and the opt-in always-quarantine path) or requires manual review;
  * the zero-data-loss reassurance ("safe, encrypted backup ... never lost")
    is always present when something was acted on;
  * quarantine language and auto-purge / freed-bytes stats are surfaced;
  * cancelled scans and clean scans keep the canonical headline copy;
  * technical_details labels the new actions (Resolved in place, Auto-purged,
    Storage freed).
"""
import sys
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive.report_formatter import (  # noqa: E402
    build_report, headline, human_scan_summary, technical_details)

CHECKS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""))


def scan_payload(files: int = 42_301, findings: int = 2, **kw) -> dict:
    data = {"files": files, "findings": findings, "errors": 0}
    data.update(kw)
    return data


def main() -> int:
    print("1. canonical headline - cleaned and restored / removed completely")
    plain = human_scan_summary(scan_payload(), cleaned=2, quarantined=1)
    check("headline opens 'Scanned 42,301 files. Found 2 threat(s)'",
          "Scanned 42,301 files. Found 2 threat(s)" in plain, plain)
    check("'2 cleaned and restored' present", "2 cleaned and restored" in plain)
    check("attention clause flips for quarantined",
          "1 item(s) still need your attention." in plain, plain)
    check("detail keeps 'resolved 2 file(s) in place'",
          "resolved 2 file(s) in place" in plain, plain)
    check("quarantine wording present",
          "moved 1 file(s) to a safe quarantine folder" in plain)
    check("zero-data-loss reassurance present",
          "safe, encrypted backup" in plain and "never lost" in plain)

    print("2. auto-purge stats surface in plain text")
    plain2 = human_scan_summary(scan_payload(findings=1), cleaned=0,
                                quarantined=0, auto_purged=1, freed_bytes=4096)
    check("headline says '1 removed completely'",
          "1 removed completely" in plain2, plain2)
    check("no 'cleaned' segment when nothing was resolved in place",
          "cleaned" not in plain2, plain2)
    check("with no quarantined/attention -> nothing requires attention",
          "Nothing requires your attention." in plain2, plain2)
    check("'auto-purged 1 verified malware file(s)' present",
          "auto-purged 1 verified malware file(s)" in plain2, plain2)
    check("freed-bytes stat present",
          "4,096 bytes were freed by auto-purge" in plain2)

    print("3. build_report wires the action counts through")
    rep = build_report(scan_payload(findings=3),
                       actions={"disinfected": 2, "quarantined": 1,
                                "auto_purged": 1, "freed_bytes": 2048})
    check("headline includes cleaned + removed segments",
          "2 cleaned and restored" in rep["plain"]
          and "1 removed completely" in rep["plain"], rep["plain"])
    check("attention clause reflects the quarantine",
          "1 item(s) still need your attention." in rep["plain"], rep["plain"])
    rep_manual = build_report(scan_payload(findings=4),
                              actions={"disinfected": 4,
                                       "requires_manual_review": 2})
    check("requires_manual_review flips the attention clause",
          "2 item(s) still need your attention." in rep_manual["plain"],
          rep_manual["plain"])
    check("rolled_back + skipped also count as attention",
          "3 item(s) still need your attention." in
          build_report(scan_payload(findings=3), actions={"rolled_back": 2,
                                                          "skipped_actions": 1})
          ["plain"])
    check("detailed block labels the new actions",
          "Resolved in place: 2" in rep["detailed"]
          and "Auto-purged (verified): 1" in rep["detailed"]
          and "Storage freed by auto-purge: 2048" in rep["detailed"],
          rep["detailed"])

    print("4. clean / cancelled scans keep their copy")
    check("clean scan -> headline with 'Nothing requires your attention.'",
          "Found 0 threat(s)" in
          human_scan_summary(scan_payload(findings=0))
          and "Nothing requires your attention." in
          human_scan_summary(scan_payload(findings=0)))
    check("cancelled scan -> nothing modified yet",
          "nothing has been modified yet" in
          human_scan_summary(scan_payload(findings=3, cancelled=True)))

    print("5. headline() helper emits the canonical formatting")
    check("headline with all segments",
          headline(42_301, 2, cleaned=2, removed=1) ==
          "Scanned 42,301 files. Found 2 threat(s) \u2014 2 cleaned and "
          "restored, 1 removed completely. Nothing requires your attention.",
          headline(42_301, 2, cleaned=2, removed=1))
    check("attention clause variant",
          "2 item(s) still need your attention." in
          headline(10, 2, cleaned=1, attention_items=2))

    print("6. technical_details honors the full action vocabulary")
    det = technical_details(scan_payload(), finding_rows=[],
                            actions={"disinfected": 2, "quarantined": 1,
                                     "auto_purged": 3, "freed_bytes": 5,
                                     "revealed": 1, "attribs_fixed": 7,
                                     "rolled_back": 1, "skipped_actions": 2})
    for needle in ("Resolved in place: 2", "Quarantined: 1",
                   "Auto-purged (verified): 3", "Storage freed by auto-purge: 5",
                   "Hidden roots revealed: 1", "Attributes restored: 7",
                   "Rolled back (restored): 1", "Skipped (kept as-is): 2"):
        check(f"technical row '{needle}'",
              needle in det, f"missing: {needle}")

    print(f"\nReport language: {sum(CHECKS)}/{len(CHECKS)} checks passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nReport language: FAIL ({exc})", file=sys.stderr)
        raise