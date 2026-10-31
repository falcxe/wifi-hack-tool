"""Self-setup: fetch the pieces that cannot ship inside the package."""
from __future__ import annotations

import hashlib
import os
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from . import app_dir

PROJECT_ROOT = app_dir()
ASSETS_DIR = PROJECT_ROOT / "assets"

Progress = Callable[[str, int, int], None]


def _download(url: str, dest: Path, on_progress: Optional[Progress] = None,
              label: str = "") -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length", 0) or 0)
        done = 0
        with tmp.open("wb") as fh:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if on_progress is not None:
                    on_progress(label or dest.name, done, total)
    tmp.replace(dest)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_wordlists(on_progress: Optional[Progress] = None) -> list[Path]:
    found: list[Path] = []
    small = ASSETS_DIR / "probable-wpa.txt"
    if small.exists():
        found.append(small)
    else:
        try:
            _download(
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
                small, on_progress, "probable-wpa.txt",
            )
            found.append(small)
        except Exception:
            pass
    rockyou = ASSETS_DIR / "rockyou-wpa.txt"
    if rockyou.exists():
        found.append(rockyou)
    return found


def has_hashcat() -> bool:
    from . import cracker
    try:
        return cracker.find_hashcat() is not None
    except Exception:
        return False


def ensure_tools(on_log: Callable[[str], None] | None = None) -> dict:
    """Download missing external tools (hashcat, wpawolf) via installer."""
    from . import installer
    import asyncio

    wanted = []
    if not has_hashcat():
        wanted.append("hashcat")
    # wpawolf
    if not (ASSETS_DIR / "wpawolf.exe").exists():
        wanted.append("wpawolf")
    if not wanted:
        return {}
    try:
        return asyncio.run(installer.install_all(wanted, on_log=on_log or (lambda x: None)))
    except Exception:
        return {}


def _npcap_installed() -> bool:
    for candidate in (r"C:\Windows\System32\Npcap", r"C:\Program Files\Npcap"):
        if Path(candidate).exists():
            return True
    return False


def available_offline() -> dict:
    return {
        "hashcat": has_hashcat(),
        "probable": (ASSETS_DIR / "probable-wpa.txt").exists(),
        "rockyou": (ASSETS_DIR / "rockyou-wpa.txt").exists(),
        "npcap": _npcap_installed(),
    }


def log_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home())
    d = base / "WifiTool"
    d.mkdir(parents=True, exist_ok=True)
    return d / "session.log"