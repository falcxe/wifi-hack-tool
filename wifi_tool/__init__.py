"""WifiHackTool — a TUI WiFi cracking tool built on opentui."""
__version__ = "0.2.1"

#: Build stamp, shown in every screen header.
#:
#: This exists because of a specific, repeated failure: the app was relaunched,
#: a change did not appear, and there was no way to tell a stale process from a
#: stale cache from a change that never ran. One glance at the header answers it.
#: Use the newest package source time, including UI-only edits.
_BUILD_STAMP = None


def build_stamp() -> str:
    """The running version and the newest package source timestamp.

    A frozen build (PyInstaller and friends) has no ``.py`` sources on disk at
    all -- they live inside the bundled archive, not as files `rglob` can see
    -- so ``max()`` over an empty sequence used to raise ``ValueError`` and
    take the whole screen down with it the first time this ran from the exe.
    The executable's own mtime is the closest equivalent there: it still
    answers the question this stamp exists for ("is this the build I just
    rebuilt"), just one level up from source files that do not exist.
    """
    global _BUILD_STAMP
    if _BUILD_STAMP is None:
        from datetime import datetime
        from pathlib import Path
        import sys
        try:
            package = Path(__file__).resolve().parent
            mtime = max(
                (source.stat().st_mtime for source in package.rglob("*.py")),
                default=None,
            )
            if mtime is None:
                exe = Path(sys.executable if getattr(sys, "frozen", False) else __file__)
                mtime = exe.stat().st_mtime
            _BUILD_STAMP = f"{__version__} · {datetime.fromtimestamp(mtime):%d.%m %H:%M}"
        except OSError:
            _BUILD_STAMP = __version__
    return _BUILD_STAMP
