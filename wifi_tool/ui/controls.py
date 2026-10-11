"""Persistent keyboard focus shared by screen controls and their mouse actions."""
from __future__ import annotations

from . import state
from .actions import Action, key_of

ESCAPE = ("escape", "esc")


def action_id(action: Action) -> str:
    return "action:" + (action.identifier or action.label)


def action_ids(actions: list[Action]) -> list[str]:
    return [action_id(action) for action in actions if action.enabled]


def all_action_ids(actions: list[Action]) -> list[str]:
    return [action_id(action) for action in actions]


def focused(screen: str, choices: list[str], *, default: str = "") -> str:
    stored = state.control_focus().get(screen, "")
    return stored if stored in choices else default if default in choices else next(iter(choices), "")


def peek_focus(screen: str, choices: list[str], *, default: str = "") -> str:
    stored = state.control_focus.peek().get(screen, "")
    return stored if stored in choices else default if default in choices else next(iter(choices), "")


def set_focus(screen: str, identifier: str) -> None:
    state.control_focus.set({**state.control_focus.peek(), screen: identifier})


def is_tab(event) -> bool:
    return key_of(event) in ("tab", "backtab", "shift+tab", "shift-tab")


def tab_delta(event) -> int:
    return -1 if key_of(event) != "tab" or getattr(event, "shift", False) else 1


def step(screen: str, choices: list[str], delta: int, *, default: str = "") -> None:
    if not choices:
        return
    current = peek_focus(screen, choices, default=default)
    index = choices.index(current)
    set_focus(screen, choices[(index + delta) % len(choices)])


def handle_action_key(event, screen: str, actions: list[Action], *,
                      regions: tuple[str, ...] = (), default: str = "") -> bool:
    """Tab traverses regions/actions; arrows navigate actions; Enter activates."""
    choices = [*regions, *action_ids(actions)]
    ordered = [*regions, *(action_id(action) for action in actions)]
    current = peek_focus(screen, ordered, default=default)
    key = key_of(event)
    if is_tab(event):
        index = ordered.index(current) if current in ordered else 0
        for distance in range(1, len(ordered) + 1):
            candidate = ordered[(index + distance * tab_delta(event)) % len(ordered)]
            if candidate in choices:
                set_focus(screen, candidate)
                break
        return True
    if current not in regions:
        if key in ("up", "down"):
            identifiers = [action_id(action) for action in actions]
            index = identifiers.index(current) if current in identifiers else 0
            for distance in range(1, len(identifiers) + 1):
                candidate = identifiers[(index + distance * (-1 if key == "up" else 1)) % len(identifiers)]
                if candidate in choices:
                    set_focus(screen, candidate)
                    break
            return True
        if key in ("enter", "return"):
            selected = next((action for action in actions if action_id(action) == current), None)
            if selected is not None and selected.enabled:
                selected.run()
            return True
    return False


def activate(screen: str, action: Action) -> None:
    set_focus(screen, action_id(action))
    if action.enabled:
        action.run()


def scroll_log(key: str, lines: list[str]) -> None:
    page = max(1, state.log_page.peek())
    maximum = max(0, len(lines) - page)
    if key in ("up", "down", "pageup", "pagedown"):
        delta = {"up": 1, "down": -1, "pageup": page, "pagedown": -page}[key]
        state.log_scroll.set(max(0, min(maximum, state.log_scroll.peek() + delta)))
    elif key in ("home", "end"):
        state.log_scroll.set(maximum if key == "home" else 0)


def list_page(screen: str, room: int | None = None) -> int:
    if room is not None and state.list_pages.peek().get(screen) != room:
        state.list_pages.set({**state.list_pages.peek(), screen: max(1, room)})
    return max(1, state.list_pages.peek().get(screen, 8))
