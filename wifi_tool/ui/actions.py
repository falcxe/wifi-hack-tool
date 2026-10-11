"""Command descriptors and normalised key names shared by screens and dialogs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

ENTER = ("enter", "return")
LEFT = ("left",)
RIGHT = ("right",)
UP = ("up",)
DOWN = ("down",)
BACK = ("escape", "esc", *LEFT)
CHOOSE = (*ENTER, *RIGHT)


@dataclass(frozen=True)
class Action:
    """One selectable command."""

    label: str
    run: Callable[[], None]
    primary: bool = False
    enabled: bool = True
    danger: bool = False
    description: str = ""
    category: str = ""
    identifier: str = ""


ACTION_GROUPS = ("Основное", "Список и поиск", "Источники", "Настройки",
                 "Компоненты", "Сведения", "Переходы", "Приложение")


def group_actions(items: list[Action]) -> list[Action]:
    """Keep frequent commands first and related commands adjacent, stably.

    Availability does not affect order: background checks must not move focus.
    """
    ranks = {name: index for index, name in enumerate(ACTION_GROUPS)}
    return sorted(items, key=lambda item: ranks.get(item.category, 0))


def key_of(event) -> str:
    """Normalise a key event to a lowercase name.

    Real terminal input and the test harness disagree about where the useful
    value lives: ``name`` is the symbolic name for both, but some events only
    carry ``key`` or an escape sequence in ``code``. Every screen funnels through
    here so that difference is handled once instead of in each handler.
    """
    for attribute in ("name", "key", "code"):
        value = getattr(event, attribute, "") or ""
        text = str(value).lower()
        if text:
            return text
    return ""


def is_ctrl(event) -> bool:
    return bool(getattr(event, "ctrl", False))


def open_menu() -> None:
    from .commands import open_menu as show

    show()
