"""What the user picked the first time the app was opened.

The first screen of a tool like this is the only place where the user gets to
say *what they actually want to do*. Everywhere else the app already assumes an
answer: it lists networks, it offers a capture, it names hashcat. So the choice
made here is remembered in a tiny JSON file and re-offered later, rather than
being asked once and then thrown away.

Three rules this file follows:

* **A missing file means "first run"** -- and any error reading one means the
  same. A user who cannot parse JSON must not be locked out of the app on a
  screen whose whole purpose is to be understandable.
* **Never raise.** Every caller is a UI path, and an exception here would
  replace "choose a scenario" with a stack trace.
* **No clock, no machine name, nothing else in the file.** One key, so a user
  who deletes it gets the question again and nothing else changes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

#: Scenario keys. ``network`` scans and captures live, ``file`` cracks a capture
#: that already exists, ``saved`` reads the keys Windows has already stored.
SCENARIOS = ("network", "file", "saved")

#: Where the file lives. ``LOCALAPPDATA`` is per-user and never wiped by a
#: reinstall of the project, which is what makes "show this once" work across
#: updates. The env override exists so tests never touch the real profile.
ENV_STATE_DIR = "WIFI_TOOL_STATE_DIR"
ENV_FORCE = "WIFI_TOOL_FIRST_RUN"
FILE_NAME = "first_run.json"


def state_dir() -> Path:
    """The per-user directory holding this file."""
    override = os.environ.get(ENV_STATE_DIR)
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    return (Path(base) if base else Path.home()) / "WifiTool"


def settings_file() -> Path:
    return state_dir() / FILE_NAME


def load() -> dict:
    """The stored choices, or ``{}``. Never raises."""
    forced = os.environ.get(ENV_FORCE)
    if forced == "1":
        return {}
    try:
        raw = settings_file().read_text(encoding="utf-8")
    except (OSError, ValueError):
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        # A half-written file (a killed process, a full disk) is still just
        # "we do not know yet" -- the same answer as no file at all.
        return {}
    return data if isinstance(data, dict) else {}


def save(data: dict) -> bool:
    """Write the choices. Returns False instead of raising on a read-only disk."""
    try:
        path = settings_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError):
        return False
    return True


def is_first_run() -> bool:
    """True until a scenario has been chosen once."""
    if os.environ.get(ENV_FORCE) == "0":
        return False
    return not chosen_scenario()


def chosen_scenario() -> str | None:
    """The remembered scenario key, or None if there is a usable one."""
    value = load().get("scenario")
    return value if value in SCENARIOS else None


def remember(scenario: str, *, remember_choice: bool = True) -> None:
    """Store the chosen scenario. A write failure is not worth interrupting a run."""
    if remember_choice and scenario not in SCENARIOS:
        return
    save({"scenario": scenario} if scenario in SCENARIOS else {})


def forget() -> None:
    """Drop the stored choice, so the next launch asks again."""
    try:
        settings_file().unlink(missing_ok=True)
    except OSError:
        pass