"""Completed result with a readable verdict and a scrollable full log."""
from __future__ import annotations

from opentui import Box, Column, Text, component
from opentui.hooks import use_keyboard, use_terminal_dimensions

from .. import actions as nav
from .. import controls, dialogs, navigation, state
from ..actions import Action, group_actions, key_of
from ..controller import back_to_scan, open_crack_form, pick_capture_file
from ..theme import ACCENT, TEXT_SECONDARY, SUCCESS, MAX_WORKSPACE_WIDTH, TEXT_PRIMARY, WARNING, fmt_duration
from ..widgets import (action_list, secret_lines, text_line, truncate, truncate_middle, wrap, workspace, workspace_footer,
                       workspace_header, workspace_log, workspace_section)


def _retry() -> None:
    result = state.result.peek()
    if result is not None:
        from ..controller import retry_result
        retry_result(result)


def _open_parameters() -> None:
    result = state.result.peek()
    if result is not None and result.request is not None:
        from ..forms import open_form
        open_form(result.network, options=result.request.options,
                  capture=result.request.capture_path)
        return
    open_crack_form(result.network if result else None,
                    capture=state.form_values.peek().get("capture", ""),
                    from_cli=True)


#: Revealing a recovered password on screen. On by default: the toggle is what
#: keeps it away from a shoulder when someone wants that, and a tool whose whole
#: output is a password should not arrive with the answer already withheld and
#: no way to ask for it.
REVEAL_SECRET = True

#: A key read from this machine's own Windows profile. It was decrypted out of
#: the local key store seconds earlier and sits in the user's own profiles in the
#: clear, so masking it on screen protects nothing -- and refusing to say it
#: makes the app announce a found password and then behave as if it had forgotten
#: it. Shown outright. A password *recovered* from a handshake is somebody else's
#: until shown otherwise, and that one stays behind the toggle.
LOCAL_KEY_METHOD = "ключ Windows"


def _shown(result) -> bool:
    """Whether this result's password is on screen right now."""
    if result is None or not result.success or not result.password:
        return False
    if result.method == LOCAL_KEY_METHOD:
        return True
    return bool(REVEAL_SECRET
                and state.revealed_secret.peek() == ("result", id(result)))


def _masked(result) -> bool:
    """Whether the toggle is worth offering for this result."""
    return bool(result is not None and result.success and result.password
                and result.method != LOCAL_KEY_METHOD)


def result_actions(has_result: bool = True) -> list[Action]:
    result = state.result.peek()
    actions = []
    if REVEAL_SECRET and _masked(result):
        revealed = _shown(result)
        actions.append(Action("Скрыть пароль" if revealed else "Показать пароль", _toggle_password,
                              primary=True, identifier="secret", category="Основное"))
    if has_result and result is not None and result.request is not None:
        capture = result.method == "захват" or result.request.mode in ("capture", "board")
        actions.append(Action("Повторить захват" if capture else "Повторить подбор", _retry,
                              primary=not actions, category="Основное"))
    if has_result and result is not None and not result.success:
        # The remedy for a failed run is almost always "try another source", and
        # a capture file is the one that works without the hardware. Offered
        # right here, and choosing a file starts on it.
        actions.append(Action("Файл захвата", pick_capture_file,
                              description="Другой источник данных", category="Источники"))
    actions.append(Action("Параметры", _open_parameters, enabled=has_result, category="Настройки"))
    if result is not None and (result.error or result.remedy or result.summary):
        actions.append(Action("Подробности", _show_details, category="Сведения"))
    actions += [
        Action("К списку сетей", back_to_scan, primary=not has_result, category="Переходы"),
        Action("Назад", navigation.back, category="Переходы"),
    ]
    return group_actions(actions)


def _toggle_password() -> None:
    result = state.result.peek()
    if result and result.success and result.password:
        token = ("result", id(result))
        revealed = state.revealed_secret.peek() == token
        state.revealed_secret.set(None if revealed else token)
        controls.set_focus("result", "action:secret")


def _show_details() -> None:
    from .. import controller
    result = state.result.peek()
    if result is None:
        return
    text = "\n".join(part for part in (result.summary, result.error, result.remedy) if part)
    revealed = _shown(result)
    width = min(64, getattr(controller._renderer, "width", 68) - 8)
    lines = wrap("\n".join(secret_lines(text.splitlines(), result.password, revealed)), width)
    dialogs.open_select("Подробности результата", [Action(line, lambda: None) for line in lines], searchable=False)


def _on_key(event) -> None:
    if state.phase.peek() != "result" or nav.is_ctrl(event):
        return
    event.stop_propagation()
    key = key_of(event)
    result = state.result.peek()
    actions = result_actions(result is not None)
    default = controls.action_id(next((action for action in actions if action.enabled), actions[0]))
    if key in controls.ESCAPE:
        navigation.back()
    elif controls.handle_action_key(event, "result", actions, regions=("log",), default=default):
        return
    elif controls.peek_focus("result", ["log", *controls.all_action_ids(actions)], default=default) == "log":
        controls.scroll_log(key, lines_of(result, state.log.peek()))


def lines_of(result, fallback) -> list[str]:
    """A historical result owns its log, including an intentionally empty one."""
    candidate = getattr(result, "log", []) if result else fallback
    return candidate if isinstance(candidate, list) else []


@component
def ResultScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    use_keyboard(_on_key)
    result = state.result()
    state.revealed_secret()
    inner = max(8, width - 4)
    verdict_room = max(3, min(7, height - 11))
    label = result.network.label if result else ""
    if result is None:
        rows = [Text("Результат недоступен", fg=WARNING, height=1, wrap_mode="none")]
    else:
        is_capture = result.method == "захват"
        title = ("Захват готов" if result.success else "Захват не получен") if is_capture else (
            "Пароль найден" if result.success else "Пароль не найден")
        if not result.success and any(word in result.error.casefold() for word in ("остановлен", "остановлено", "отменён")):
            title = "Операция остановлена"
        rows = [Text(title, fg=SUCCESS if result.success else WARNING, bold=True, height=1, wrap_mode="none")]
        revealed = _shown(result)
        detail = (result.summary if is_capture and result.success else
                  result.password if revealed else "Пароль: [скрыто]" if result.success else result.error) or "Нет данных"
        rows.extend(Text(line, fg=SUCCESS if result.success else TEXT_PRIMARY, bold=result.success,
                         height=1, flex_shrink=0, wrap_mode="none")
                    for line in secret_lines(wrap(detail, inner), result.password, revealed)[:max(1, verdict_room - 3)])
        if not result.success and result.remedy:
            rows.append(text_line("Далее: " + result.remedy.splitlines()[0], inner, color=ACCENT))
        rows.append(Text(truncate(f"{result.method or '—'} · {fmt_duration(result.elapsed)}", inner),
                         fg=TEXT_SECONDARY, height=1, flex_shrink=0, wrap_mode="none"))
    actions = result_actions(result is not None)
    default = controls.action_id(next((action for action in actions if action.enabled), actions[0]))
    action_room = max(1, min(len(actions), height - 9 - len(rows)))
    # The journal is sized to what it has, not to what the window can hold.
    # Filling the leftover rows made a two-line log into a fifteen-row empty box
    # that dominated the screen and read as "something failed to load" rather
    # than "there was nothing more to say".
    raw_log = lines_of(result, state.log())
    have = len(raw_log) if isinstance(raw_log, list) else 0
    journal_height = max(3, min(have + 2, height - 6 - len(rows) - action_room))
    state.log_page.set(max(1, journal_height - 2))
    focus = controls.focused("result", ["log", *controls.all_action_ids(actions)], default=default)
    lines = secret_lines(raw_log if isinstance(raw_log, list) else [], result.password if result else "",
                         _shown(result))
    if result and result.request and result.request.capture_path:
        label += " · " + truncate_middle(result.request.capture_path, max(10, inner - len(label) - 3))
    return workspace(
        workspace_header("Результат", label, width=width),
        workspace_section("", Column(*rows), height=len(rows), flex_shrink=0),
        Box(height=1, flex_shrink=0),
        action_list("result", actions, width=width, room=action_room, regions=("log",), default=default),
        Box(height=1, flex_shrink=0),
        workspace_log(lines, width, journal_height, state.log_scroll(), focused=focus == "log",
                      on_focus=lambda: controls.set_focus("result", "log")),
        Box(flex_grow=1),
        workspace_footer(width=width, hint="↑↓ журнал · Tab · Esc назад" if focus == "log" else
                         "↑↓ Tab · Enter · Esc назад"), width=terminal_width, height=height,
    )
