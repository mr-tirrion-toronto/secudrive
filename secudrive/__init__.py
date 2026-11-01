"""secudrive - Desktop Security & Data Recovery Tool.

A modular, CLI-first malware disinfection and data-recovery engine for
Windows 11 (portable to Linux/macOS).  Core pipeline per destructive action:

    BACKUP (encrypted) -> SANDBOX (byte-stream analysis, never execute)
    -> DISINFECT (strip payload, atomic replace) -> VERIFY -> ROLLBACK on failure.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]