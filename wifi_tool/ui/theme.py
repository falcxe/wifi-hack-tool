"""Shared colors and small style helpers for the TUI."""
from __future__ import annotations

# One semantic graphite-and-cobalt palette for every screen and component.
CANVAS = "#090d14"
SURFACE = "#111827"
OUTLINE = "#46566f"
TEXT_PRIMARY = "#f3f6fc"
TEXT_SECONDARY = "#a8b4c7"
ACCENT = "#5b8cff"
SUCCESS = "#4ade80"
WARNING = "#ffc857"
ERROR = "#fb7185"
FOCUS_SURFACE = "#203a70"
SELECTION_SURFACE = "#1a2538"
MAX_WORKSPACE_WIDTH = 144


def signal_bar(percent: int, width: int = 5) -> tuple[str, str]:
    """Return (text, color) for a textual signal meter."""
    percent = max(0, min(100, percent))
    filled = round(width * percent / 100)
    bar = "█" * filled + "░" * (width - filled)
    if percent >= 70:
        color = SUCCESS
    elif percent >= 40:
        color = WARNING
    else:
        color = ERROR
    return bar, color


def auth_color(auth: str) -> str:
    a = auth.lower()
    if "wpa3" in a:
        return SUCCESS
    if "wpa2" in a:
        return ACCENT
    if "wpa" in a:
        return WARNING
    if "open" in a or "открыта" in a or "нет" in a:
        return ERROR
    return TEXT_SECONDARY


def progress_bar(percent: float, width: int = 32, done: bool = False) -> str:
    """A solid progress bar; ``percent`` is clamped to 0..100."""
    percent = max(0.0, min(100.0, float(percent)))
    filled = int(round(width * percent / 100))
    filled = max(1 if percent > 0 else 0, min(width, filled))
    bar = "█" * filled + "░" * (width - filled)
    return f"{bar} {percent:5.1f}%"


def progress_color(percent: float) -> str:
    return SUCCESS if percent >= 100 else ACCENT


def fmt_duration(seconds: float) -> str:
    """``93.4`` -> ``1м 33с``."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}с"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}м {secs}с"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}ч {minutes}м"


def crack_hint(auth: str) -> str:
    """Short reason why a network is or isn't a valid offline target."""
    a = auth.lower()
    if not a:
        return "нет данных"
    if "open" in a or "открыт" in a:
        return "открытая — пароля нет"
    if "wep" in a:
        return "WEP — устаревший, не поддерживается"
    if "wpa3" in a and "wpa2" not in a:
        return "WPA3-only — нужен переходный режим"
    if "enterprise" in a or "корпорац" in a:
        return "Enterprise — нужен RADIUS"
    if "personal" in a or "общая" in a or "psk" in a:
        return "можно подбирать"
    return "не определён"
