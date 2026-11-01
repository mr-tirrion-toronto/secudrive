#!/usr/bin/env python3
"""test_resolve_plan.py - regression test for the resolve_plan() classifier.

Guards the IMMEDIATE-RESOLVE default (config ``on_detection``, default
``'resolve'``):

  * container files with a safe EOF-marker strip point (jpg / png / gif /
    pdf / zip) plan to 'strip' - resolved IN PLACE from an encrypted backup;
  * files with no safe in-place fix (pure-malware executables, whole-file
    malware, unknown containers, payload below the noise floor) plan to
    'quarantine' - moved to the quarantine store, never damaged;
  * the OLD always-quarantine behavior is the opt-in
    ``on_detection == 'quarantine'`` config value;
  * OS/fs-recovery artifacts, symlinks and missing files plan to 'skip'
    (manual review only);
  * hidden-camouflage root folders plan to 'reveal' (attributes only).

Each check runs against a temp dir + real SQLite DB; PASS/FAIL per check.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive.database import Database  # noqa: E402
from secudrive.recovery import (  # noqa: E402
    PLAN_QUARANTINE, PLAN_REVEAL, PLAN_SKIP, PLAN_STRIP, resolve_plan)
from secudrive.scanner import Finding  # noqa: E402

CHECKS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""))


class _Cfg:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def get(self, key, default=None):
        return self.values.get(key, default)


def write_jpeg(tmp: Path, name: str = "photo.jpg",
               payload: bytes = b"PAYLOADJUNK" * 5) -> Path:
    p = tmp / name
    p.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00"
                  + b"\x00" * 40 + b"\xff\xd9" + payload)
    return p


def write_mz(tmp: Path, name: str = "evil.exe") -> Path:
    p = tmp / name
    p.write_bytes(b"MZ" + b"\x00" * 96 + b"evil dropper payload")
    return p


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="secudrive-rsolve-"))
    try:
        tmp = sandbox / "ai"
        tmp.mkdir(parents=True)
        db = Database(tmp / "secudrive.db")

        print("1. default on_detection=resolve: safe strip points resolve in place")
        jpeg = write_jpeg(tmp)
        jpeg_f = Finding(path=jpeg, category="heuristic", name="TrailingPayload",
                         confidence=0.82)
        plan = resolve_plan(jpeg, db, jpeg_f)
        check("jpg + FFD9 + payload -> strip",
              plan.get("plan") == PLAN_STRIP, str(plan))
        check("strip plan exposes the byte offset",
              isinstance(plan.get("strip_offset"), int) and
              plan.get("strip_offset", 0) > 0 and
              plan.get("strip_bytes", 0) > 0)

        pdf = tmp / "report.pdf"
        pdf.write_bytes(b"%PDF-1.4\n" + b"x" * 80 + b"%%EOF" + b"PDEP" * 12)
        plan_pdf = resolve_plan(pdf, db,
                                Finding(path=pdf, category="heuristic",
                                        name="TrailingPayload", confidence=0.82))
        check("pdf + %%EOF + payload -> strip",
              plan_pdf.get("plan") == PLAN_STRIP, str(plan_pdf))

        z = tmp / "arch.zip"
        z.write_bytes(b"PK\x03\x04" + b"\x00" * 40
                      + b"PK\x05\x06" + b"\x00" * 18     # full 22-byte EOCD record
                      + b"ZPAY" * 12)
        plan_z = resolve_plan(z, db,
                              Finding(path=z, category="heuristic",
                                      name="TrailingPayload", confidence=0.82))
        check("zip + EOCD + payload -> strip",
              plan_z.get("plan") == PLAN_STRIP, str(plan_z))

        print("2. no safe in-place fix -> quarantine (never damage)")
        evil = write_mz(tmp)
        evil_f = Finding(path=evil, category="signature", name="TestDropper",
                         confidence=1.0)
        plan_evil = resolve_plan(evil, db, evil_f)
        check("MZ PE executable (no split point) -> quarantine",
              plan_evil.get("plan") == PLAN_QUARANTINE, str(plan_evil))

        small = tmp / "tiny.jpg"
        small.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 40 + b"\xff\xd9"
                          + b"CC")      # 2 junk bytes < 32 noise floor
        plan_small = resolve_plan(small, db,
                                  Finding(path=small, category="heuristic",
                                          name="TrailingPayload", confidence=0.82))
        check("payload below the 32-byte noise floor -> quarantine",
              plan_small.get("plan") == PLAN_QUARANTINE, str(plan_small))

        txt = tmp / "notes.txt"
        txt.write_bytes(b"plain text with some junk appended at the end")
        plan_txt = resolve_plan(txt, db,
                                Finding(path=txt, category="heuristic",
                                        name="TrailingPayload", confidence=0.82))
        check("unknown container (no magic) -> quarantine",
              plan_txt.get("plan") == PLAN_QUARANTINE, str(plan_txt))

        print("3. dict-form findings (DB rows) work too")
        plan_dict = resolve_plan(jpeg, db, {"path": jpeg, "category": "heuristic",
                                            "threat_name": "TrailingPayload",
                                            "confidence": 0.82})
        check("dict finding with threat_name -> strip",
              plan_dict.get("plan") == PLAN_STRIP and
              plan_dict.get("threat") == "TrailingPayload", str(plan_dict))

        print("4. opt-in on_detection='quarantine' restores old behavior")
        jpeg2 = write_jpeg(tmp, name="photo2.jpg")
        plan_opt = resolve_plan(jpeg2, db, jpeg_f,
                                config=_Cfg({"on_detection": "quarantine"}))
        check("strip-able jpeg STILL quarantined under the opt-in",
              plan_opt.get("plan") == PLAN_QUARANTINE, str(plan_opt))
        plan_res = resolve_plan(jpeg2, db, jpeg_f,
                                config=_Cfg({"on_detection": "resolve"}))
        check("on_detection=resolve (or unset) strips in place",
              plan_res.get("plan") == PLAN_STRIP)
        plan_unset = resolve_plan(jpeg2, db, jpeg_f, config=_Cfg({}))
        check("config without the key defaults to resolve",
              plan_unset.get("plan") == PLAN_STRIP)

        print("5. recovery data / missing / non-regular files -> skip")
        lost = tmp / "LOST.DIR" / "file0.frd"
        lost.parent.mkdir(parents=True)
        lost.write_bytes(b"\xff\xd8\xff\xe0 recovering" + b"\x00" * 100)
        plan_lost = resolve_plan(lost, db,
                                 Finding(path=lost, category="heuristic",
                                         name="TrailingPayload", confidence=0.82))
        check("OS/fs-recovery artifact -> skip (manual review)",
              plan_lost.get("plan") == PLAN_SKIP, str(plan_lost))

        missing = tmp / "nope.exe"
        plan_missing = resolve_plan(missing, db,
                                    Finding(path=missing, category="signature",
                                            name="TestDropper", confidence=1.0))
        check("missing file -> skip",
              plan_missing.get("plan") == PLAN_SKIP, str(plan_missing))

        hidden = tmp / "HiddenRootFolder"
        hidden.mkdir(parents=True)
        plan_hidden = resolve_plan(hidden, db,
                                   Finding(path=hidden, category="heuristic",
                                           name="HiddenRootFolder", confidence=0.9))
        check("hidden root folder -> reveal (attributes only)",
              plan_hidden.get("plan") == PLAN_REVEAL, str(plan_hidden))

        link = tmp / "link"
        try:
            os.symlink(str(evil), link)
        except OSError as exc:
            print(f"  [SKIP] symlink fixture unavailable on this session ({exc})")
        else:
            plan_link = resolve_plan(link, db,
                                     Finding(path=link, category="signature",
                                             name="TestDropper", confidence=1.0))
            check("symlink -> skip",
                  plan_link.get("plan") == PLAN_SKIP, str(plan_link))

        print(f"\nresolve_plan(): {sum(CHECKS)}/{len(CHECKS)} checks passed")
        return 0 if all(CHECKS) else 1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nresolve_plan(): FAIL ({exc})", file=sys.stderr)
        raise