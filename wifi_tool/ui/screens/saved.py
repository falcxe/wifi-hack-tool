"""Saved networks screen: the keys Windows already stores for this machine.

This is the path that always works. A profile is saved when a network is joined,
and for profiles owned by the current user Windows returns the plaintext key
without administrator rights and without any special capture hardware.
"""
from __future__ import annotations

from opentui import Box, Column, Row, Text, click_handler, component
from opentui.hooks import use_keyboard, use_terminal_dimensions

from ... import profiles
from ...models import Network
from .. import actions as nav
from .. import controls, motion, state
from ..actions import Action, group_actions, key_of
from ..controller import back_from_saved, open_audit, refresh_saved
from ..theme import ACCENT, TEXT_SECONDARY, SUCCESS, MAX_WORKSPACE_WIDTH, TEXT_PRIMARY, WARNING
from ..widgets import (action_list, col, list_viewport, truncate, wrap, workspace,
                       workspace_footer, workspace_header, workspace_section)

def _crack_selected() -> None:
    """Run the ladder for the highlighted profile, using the key it already has.

    The stored key is not proof of anything -- it is what this machine was given
    when it joined -- but it is the cheapest rung of the ladder by far and it is
    the only one that needs neither a capture nor a dictionary. Going through
    :func:`open_audit` rather than starting a run directly keeps one rule intact:
    nothing begins on a list screen, whatever the key column says.
    """
    if state.saved_loading.peek():
        return
    profile = _selected_profile()
    if profile is None:
        return
    open_audit(Network(ssid=profile.name, bssid="", auth=profile.auth or "WPA2-Personal"))


def saved_actions() -> list[Action]:
    """Commands for the saved-profile selection."""
    profile = _selected_profile()
    revealed = bool(profile and state.revealed_secret.peek() == ("saved", profile.name))
    return group_actions([
        Action("Открыть сеть", _crack_selected, primary=True,
               enabled=bool(state.saved.peek()) and not state.saved_loading.peek(), category="Основное"),
        Action("Скрыть ключ" if revealed else "Показать ключ", _toggle_key,
               enabled=bool(profile and profile.has_key) and not state.saved_loading.peek(), identifier="secret", category="Основное"),
        Action("Обновить", refresh_saved, enabled=not state.saved_loading.peek(), category="Список и поиск"),
        Action("Назад", back_from_saved, category="Переходы"),
    ])


def _toggle_key() -> None:
    profile = _selected_profile()
    if profile and profile.has_key:
        token = ("saved", profile.name)
        revealed = state.revealed_secret.peek() == token
        state.revealed_secret.set(None if revealed else token)
        controls.set_focus("saved", "action:secret")


def _on_key(event) -> None:
    if state.phase.peek() != "saved" or nav.is_ctrl(event):
        return
    event.stop_propagation()
    key = key_of(event)
    actions = saved_actions()
    if key in controls.ESCAPE:
        back_from_saved()
        return
    if controls.handle_action_key(event, "saved", actions, regions=("list",), default="list"):
        return
    if controls.peek_focus("saved", ["list", *controls.all_action_ids(actions)], default="list") != "list":
        return
    items = state.saved.peek()
    selected = state.saved_selected.peek()
    if key in ("up", "down", "pageup", "pagedown"):
        page = controls.list_page("saved")
        delta = {"up": -1, "down": 1, "pageup": -page, "pagedown": page}[key]
        state.saved_selected.set(max(0, min(len(items) - 1, selected + delta * getattr(event, "repeat_count", 1))))
    elif key in ("home", "end"):
        state.saved_selected.set(0 if key == "home" else max(0, len(items) - 1))
    elif key in nav.CHOOSE:
        _crack_selected()


def _selected_profile():
    items = state.saved.peek()
    index = state.saved_selected.peek()
    return items[index] if 0 <= index < len(items) else None


@component
def SavedScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    use_keyboard(_on_key)
    items = state.saved()
    loading = state.saved_loading()
    error = state.saved_error()
    state.revealed_secret()
    cursor = max(0, min(state.saved_selected(), len(items) - 1))
    inner = max(8, width - 4)
    actions = saved_actions()
    action_room = len(actions)
    focus = controls.focused("saved", ["list", *controls.all_action_ids(actions)], default="list")
    list_active = focus == "list"
    context = "Загрузка…" if loading else f"{len(items)} сетей · {profiles.count_with_keys(items)} с ключом"
    detail_rows = []
    scroll = None
    if error:
        rows = [Text(truncate(line, inner), fg=WARNING, height=1, wrap_mode="none")
                for line in wrap(error, inner)[:2]]
    elif loading:
        rows = [Text("Загрузка профилей…", fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
    elif not items:
        rows = [Text("Сохранённых сетей нет", fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
    else:
        auth_w = 19 if width >= 80 else 0
        status_w = 14
        name_w = max(8, inner - 2 - auth_w - status_w)
        headings = width >= 60
        room = max(1, height - (10 if headings else 9) - action_room)
        controls.list_page("saved", room)
        token = (width, height, id(items))
        first, indices = motion.window("saved", len(items), room, cursor, token=token)
        scroll = (len(items), room, first)
        rows = []
        if headings:
            cells = [col("", 2), col("Сеть", name_w)]
            if auth_w:
                cells.append(col("Защита", auth_w))
            cells.append(col("Ключ", status_w))
            rows.append(Row(*cells, height=1, flex_shrink=0))
        for index in indices:
            profile = items[index]
            selected = index == cursor
            color = SUCCESS if profile.has_key else TEXT_SECONDARY if profile.open_network else WARNING
            status = "Сохранён" if profile.has_key else "Без пароля" if profile.open_network else "Недоступен"
            def choose(*_, at=index):
                controls.set_focus("saved", "list")
                state.saved_selected.set(at)
                _crack_selected()
            cells = [col("›" if selected and list_active else "•" if selected else "", 2,
                         fg=ACCENT if list_active else TEXT_SECONDARY),
                     col(truncate(profile.name, name_w - 1), name_w,
                         fg=ACCENT if selected and list_active else TEXT_PRIMARY, bold=selected)]
            if auth_w:
                cells.append(col(truncate(profile.auth, auth_w - 1), auth_w))
            cells.append(col(status, status_w, fg=color))
            rows.append(motion.paint(Row(*cells, height=1, flex_shrink=0,
                            on_mouse_down=click_handler(choose)), "saved", cursor, index, token=token,
                                                        focused=list_active, zebra=True))
        profile = items[cursor]
        detail = "Ключ: " + (profile.key if state.revealed_secret.peek() == ("saved", profile.name) else
                            "[скрыто] · действие «Показать ключ»") if profile.has_key else (
            "Открытая сеть" if profile.open_network else profile.key_error or "Ключ недоступен")
        detail_rows = [Text(truncate(line, inner), fg=SUCCESS if profile.has_key else TEXT_SECONDARY,
                            height=1, flex_shrink=0, wrap_mode="none") for line in wrap(detail, inner)[:2]]
    return workspace(
        workspace_header("Сохранённые сети", context, width=width),
        list_viewport("Сети", *rows, height=len(rows) + 2, focused=list_active,
                      scroll=scroll,
                      on_focus=lambda: controls.set_focus("saved", "list")),
        workspace_section("", Column(*detail_rows), height=len(detail_rows), flex_shrink=0),
        Box(height=1, flex_shrink=0),
        action_list("saved", actions, width=width, room=action_room, regions=("list",), default="list"),
        Box(flex_grow=1),
        workspace_footer(width=width, hint="↑↓ сеть · Tab · Enter · Esc" if list_active else
                         "↑↓ Tab · Enter · Esc назад"),
        width=terminal_width, height=height,
    )
