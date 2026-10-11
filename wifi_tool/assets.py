"""Bundled assets (hashcat / cap80211 / wordlist) + admin detection & elevation."""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"


@dataclass
class Assets:
    hashcat: Path | None
    cap80211: Path | None
    wordlist: Path | None

    @property
    def has_wordlist(self) -> bool:
        return self.wordlist is not None and self.wordlist.exists()


def is_admin() -> bool:
    """True if the current process runs elevated (Windows only)."""
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _find(name: str, exts: tuple[str, ...] = ()) -> Path | None:
    """Locate ``name`` in the assets dir first, then on PATH."""
    candidates = []
    for ext in exts:
        candidates.append(ASSETS_DIR / (name + ext))
    candidates.append(ASSETS_DIR / name)
    for cand in candidates:
        if cand.exists():
            return cand
    on_path = shutil.which(name)
    if on_path:
        return Path(on_path)
    return None


def load_assets() -> Assets:
    return Assets(
        hashcat=_find("hashcat", (".exe", "")),
        cap80211=_find("cap80211", (".exe", "")),
        wordlist=_find("wordlist", (".txt", ".lst", "")),
    )


#: Terminals that render what opentui draws, best first. ``wt.exe`` ships
#: with Windows Terminal and is normally on PATH through WindowsApps.
WT_EXECUTABLES = ("wt.exe", "WindowsTerminal.exe")


def _terminal_command() -> tuple[str, list[str]] | None:
    """How to re-enter the terminal this process is running inside.

    ``ShellExecuteW("runas")`` does not inherit the parent console: it starts a
    brand new one. On Windows that legacy console cannot render what opentui
    draws -- box-drawing characters and Cyrillic come out as ``т╨тю═`` mojibake.
    So the app relaunches *into a terminal that can draw it* instead of into the
    interpreter alone.

    Used to be "only if we are already inside Windows Terminal", which is exactly
    backwards: that condition is true only for the launches that already work.
    Started from cmd or PowerShell -- the ordinary way -- it was false, and the
    elevation landed the app in the one host that mangles its own output. The
    console code page does not save it: UTF-8 is set on the console and the
    bytes are correct UTF-8, and the legacy host still renders every Cyrillic
    letter as mojibake. So the host is chosen by what it can draw, not by where
    the app happens to have been started from.

    Returns ``(executable, arguments)`` or None if no known host was found.
    """
    if os.environ.get("WT_SESSION"):
        return "wt.exe", ["-w", "new", "new-tab", "-d", str(Path.cwd()), "--title", "wifi_tool"]
    for name in WT_EXECUTABLES:
        found = shutil.which(name)
        if found:
            return found, ["-w", "new", "new-tab", "-d", str(Path.cwd()),
                           "--title", "wifi_tool"]
    return None


def relaunch_elevated() -> bool:
    """Re-launch the app elevated, keeping the current terminal if we can.

    Returns True if a new elevated process was started (caller should exit).
    """
    if os.name != "nt":
        return False

    script = str(Path(sys.argv[0]).resolve())
    args = [str(a) for a in sys.argv[1:]]

    host = _terminal_command()
    if host is not None:
        exe, prefix = host
        argv = [*prefix, sys.executable, script, *args]
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, subprocess.list2cmdline(argv), None, 1
            )
        except Exception:
            ret = 0
        if ret > 32:
            return True
        # Fall through to the plain interpreter if the host refused the elevation.

    command = subprocess.list2cmdline([script, *args])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, command, None, 1
        )
    except Exception:
        return False
    return ret > 32
