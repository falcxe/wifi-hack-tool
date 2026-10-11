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
    """The running version and the newest package source timestamp."""
    global _BUILD_STAMP
    if _BUILD_STAMP is None:
        from datetime import datetime
        from pathlib import Path
        try:
            package = Path(__file__).resolve().parent
            mtime = max(source.stat().st_mtime for source in package.rglob("*.py"))
            _BUILD_STAMP = f"{__version__} · {datetime.fromtimestamp(mtime):%d.%m %H:%M}"
        except OSError:
            _BUILD_STAMP = __version__
    return _BUILD_STAMP
