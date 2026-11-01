"""wsc_register.py - register SecuDrive as a Windows Security Center provider.

Compatibility shim: the implementation lives in
``secudrive.platform.windows_provider``; every function here delegates to the
active platform provider so the bootstrap / cli entry points keep working
unchanged across all platforms.

Windows Security Center (WSC, the "Virus & threat protection" page) decides
which antivirus products it lists by querying the ``SecurityCenter2`` WMI
namespace.  Third-party products register a **provider sub-key** under:

    HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider\\<GUID>

plus an optional update stamp under:

    HKCU\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Updates\\<GUID>

The Security Health service reads those keys and exposes the product through
``AntivirusProduct`` in ``root\\SecurityCenter2``.

Requirements / limitations (please read - this is not magic):

* **Administrator** rights are required (HKLM write).
* Works on **Windows 8.1 / 10 / 11 client** editions (Home/Pro/Enterprise).
  Server editions and some SKUs with the Security Health service disabled
  will not display a third-party provider.
* Windows expects AV products to ship a **valid Authenticode code-signing
  certificate**.  An unsigned product may be listed as "potential threat" or
  ignored by the Security Center entirely - registration alone does not cure
  that.  Signing instructions: installer/SIGNING-NOTES.md.
* This writes registry entries only; it never modifies Windows Defender's own
  state, never claims to be Defender, and is fully reversible via
  ``unregister_antivirus``.

Module is importable on Linux/macOS (functions degrade to no-ops / False).
"""
from __future__ import annotations

import sys
import uuid as _uuid
from typing import Dict, List, Optional

from .logging_utils import get_logger
from .platform import get_provider

logger = get_logger("wsc")

provider = get_provider()

#: Stable provider GUID for SecuDrive (same key every run -> idempotent).
#: uuid5 derivation mirrors the Windows provider so both stay in lockstep.
PROVIDER_GUID = str(_uuid.uuid5(_uuid.NAMESPACE_DNS, "secudrive.wsc"))


def is_admin() -> bool:
    return bool(provider.is_admin())


def is_windows() -> bool:
    return provider.system() == "Windows"


def security_center_status() -> Dict:
    """Best-effort status of the local Security Center stack (never raises)."""
    return provider.security_center_status()


def register_antivirus(exe_path: str = "", signature_version: str = "1.0.0.0",
                       enabled: bool = True) -> Dict:
    """Register SecuDrive as a Security Center antivirus provider."""
    return provider.register_security_center(
        exe_path=exe_path, signature_version=signature_version, enabled=enabled)


def unregister_antivirus() -> Dict:
    """Reverses ``register_antivirus`` (also needs admin for the HKLM key)."""
    return provider.unregister_security_center()


def wmi_visible(provider_guid: Optional[str] = None) -> bool:
    """Best-effort read-back via root\\SecurityCenter2 (requires pywin32)."""
    return provider.wmi_visible(provider_guid)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry used by the installer / first-run:
    ``python -m secudrive.wsc_register [register|unregister|status]``."""
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = (argv[0] if argv else "register").lower()
    if cmd == "unregister":
        out = unregister_antivirus()
    elif cmd == "status":
        out = {"ok": True, "message": "status", "status": security_center_status()}
    else:
        out = register_antivirus(exe_path=argv[1] if len(argv) > 1 else "")
    print(out.get("message", ""))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())