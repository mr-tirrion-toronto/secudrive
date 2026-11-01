#!/usr/bin/env python3
"""test_quick_scan.py - regression test for quick_scan_targets() dedup.

Guards the fix replacing the ``key[:2]``-based sibling dedup with true
path-containment dedup: on a single-volume system (one drive letter on
Windows, one mount tree on POSIX) EVERY content directory must be returned -
Desktop, Documents, Downloads, Pictures... collapsing to the first one defeats
the purpose of a quick user-data scan.

Checks, exercising the base helper directly with overridden
``user_content_paths`` and with the running OS's path flavour swapped so both
Windows- and POSIX-style paths are covered on the same machine:
  * single volume: all four content dirs are kept (Windows + POSIX style)
  * nesting is still deduped: a directory under an already-kept one is dropped
  * two different volumes are both kept (no over-dedup)
  * the active provider returns exactly its content dirs (nothing dropped)
"""
import ntpath
import os
import posixpath
import sys
from pathlib import Path

PROJ = (Path(__file__).resolve().parents[1]
        if (Path(__file__).resolve().parents[1] / "secudrive" / "platform").exists()
        else Path(r"C:\Users\Mr_Tirrion\Documents\Default Project\secudrive"))
sys.path.insert(0, str(PROJ))

from secudrive.platform import get_provider  # noqa: E402
from secudrive.platform.base import PlatformProvider  # noqa: E402

CONTENT = ("Desktop", "Documents", "Downloads", "Pictures")


class FixedContent(PlatformProvider):
    """Provider whose only behaviour is a fixed user-content directory set."""

    def __init__(self, paths):
        super().__init__()
        self._paths = paths

    def user_content_paths(self):
        return list(self._paths)


def run_with_path_flavour(flavour, root: str) -> list:
    """Return quick_scan_targets() results under a forced path library."""
    held = os.path
    try:
        os.path = flavour
        paths = [os.path.join(root, name) for name in CONTENT]
        assert os.path.normpath(paths[0]) == paths[0]
        return FixedContent(paths).quick_scan_targets()
    finally:
        os.path = held


def main() -> int:
    # 1. Single-volume Windows-style: every content dir is kept.
    win = run_with_path_flavour(ntpath, r"C:\Users\me")
    names = sorted(os.path.split(p)[1] for p in win)
    assert names == sorted(CONTENT), win
    print(f"windows-style: all {len(CONTENT)} content dirs kept ({win!r})")

    # 2. Single-volume POSIX-style: every content dir is kept.
    posix = run_with_path_flavour(posixpath, "/home/me")
    names = sorted(os.path.split(p)[1] for p in posix)
    assert names == sorted(CONTENT), posix
    print(f"posix-style:   all {len(CONTENT)} content dirs kept ({posix!r})")

    # 3. Nesting still dedupes: a dir under an already-kept one is dropped.
    held = os.path
    try:
        os.path = ntpath
        nested = FixedContent([r"C:\Desktop", r"C:\Desktop\Documents"]).quick_scan_targets()
        assert [os.path.normpath(p) for p in nested] == [r"C:\Desktop"], nested
    finally:
        os.path = held
    print("windows-style: nested target dropped (parent kept)")

    try:
        os.path = posixpath
        nested = FixedContent(["/u/Desktop", "/u/Desktop/Documents"]).quick_scan_targets()
        assert [os.path.normpath(p) for p in nested] == ["/u/Desktop"], nested
    finally:
        os.path = held
    print("posix-style:   nested target dropped (parent kept)")

    # 4. Different volumes on Windows are both kept (no over-dedup).
    try:
        os.path = ntpath
        volumes = FixedContent([r"C:\Desktop", r"D:\Documents"]).quick_scan_targets()
        assert [os.path.normpath(p) for p in volumes] == [r"C:\Desktop", r"D:\Documents"], volumes
    finally:
        os.path = held
    print("windows-style: distinct volumes both kept")

    # 5. Active provider returns exactly its content dirs (siblings never
    #    dropped on a real single-volume machine).
    provider = get_provider()
    expected = provider.user_content_paths()
    actual = provider.quick_scan_targets()
    assert [os.path.normpath(p) for p in actual] == [
        os.path.normpath(p) for p in expected], (expected, actual)
    print(f"active({provider.system()}): quick_scan == content dirs "
          f"({len(actual)} targets, none dropped)")

    print("\nquick_scan_targets regression: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # keep the traceback meaningful on failure
        print(f"\nquick_scan_targets regression: FAIL ({exc})", file=sys.stderr)
        raise