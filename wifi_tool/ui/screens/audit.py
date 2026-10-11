"""Compact target confirmation screen."""
from __future__ import annotations
from dataclasses import replace

from opentui import Box, Column, Row, Text, component
from opentui.hooks import use_keyboard, use_terminal_dimensions

from ...models import Network
from .. import actions as nav
from .. import controls, dialogs, state
from ..actions import Action, group_actions, key_of
from ..controller import back_from_audit
from ..theme import (ACCENT, OUTLINE, TEXT_SECONDARY, SUCCESS, MAX_WORKSPACE_WIDTH, TEXT_PRIMARY, WARNING, auth_color,
                     crack_hint)
from ..widgets import (action_list, col, text_line, truncate, wrap, workspace, workspace_footer,
                       workspace_header)


def _run_auto() -> None:
    from .. import controller

    network = state.audit_network.peek()
    if network is not None:
        controller.begin_auto_for(network)


def _auto_enabled(network: Network | None) -> bool:
    return bool(network and (network.crackable or (network.ssid and not network.is_open)))


START_LABEL = "Начать подбор"


def _auto_label(network: Network | None) -> str:
    if network is None:
        return "Выбрать сеть"
    if network.is_open:
        return "Пароль не требуется"
    if not network.crackable:
        return "Проверить ключ Windows"
    return START_LABEL


def _capture_only() -> None:
    from .. import controller

    network = state.audit_network.peek()
    if network is not None:
        controller.begin_capture_for(network)


def _file_offered(network: Network | None) -> bool:
    """Whether a capture file is a sensible thing to offer for ``network``.

    Not when the machine can capture and the network is a plain WPA2 target:
    then live capture is the better route and the alternative is noise.
    """
    if network is None:
        return False
    ready = state.readiness.peek()
    return (not _auto_enabled(network) or bool(_blocker(network, ready))
            or not network.crackable or state.audit_has_key.peek() is False)


def _file_is_the_way_forward(network: Network | None) -> bool:
    """Whether the capture file is the only thing that can work.

    True when the machine cannot capture and this network has no stored key: the
    run's first two stages have nothing to do between them, so offering "start"
    as the primary action is offering a failure.
    """
    if network is None or not network.crackable:
        return False
    if state.audit_has_key.peek() is not False:
        return False
    ready = state.readiness.peek()
    return not _auto_enabled(network) or bool(_blocker(network, ready))


def _pick_capture_file() -> None:
    from .. import controller

    controller.pick_capture_file()


def _board_present() -> bool:
    from .. import controller

    if isinstance(state.board.peek(), str):
        return True
    # A board that is attached but busy -- for example mid-capture, holding the
    # serial line -- must still show the capture action, otherwise the only
    # moment someone wants it is the moment it is gone.
    return controller.board_is_plugged()


def _board_capture() -> None:
    """The on-screen board line. Thin: the flow lives in the controller.

    It used to live here plus a second polling loop in this file, which meant the
    F1 menu entry for the same action pulled a file and then left it sitting in a
    directory -- the run only ever started when the button on *this* screen was
    pressed.
    """
    from ..controller import start_board_capture

    start_board_capture()


def _open_parameters(*_) -> None:
    from ..controller import open_crack_form

    open_crack_form(state.audit_network.peek())


def _show_details() -> None:
    from .. import controller
    net = state.audit_network.peek()
    if net is None:
        return
    width = min(64, getattr(controller._renderer, "width", 68) - 8)
    info = [net.label, f"BSSID: {net.bssid or 'не получен'}", f"Защита: {net.auth or 'не объявлена'}",
            f"Шифрование: {net.protection or 'не объявлено'}", f"Канал: {net.channel or 'не получен'}",
            f"Сигнал: {net.signal}%", f"Радио: {net.radio or 'не объявлено'}"]
    blocked = _blocker(net, state.readiness.peek())
    if blocked:
        info.append(blocked)
    dialogs.open_select("Сведения о сети", [Action(line, lambda: None)
                        for text in info for line in wrap(text, width)], searchable=False)


def audit_actions(blocked: str = "") -> list[Action]:
    from .. import controller

    network = state.audit_network.peek()
    if network is None:
        return [Action("К списку сетей", back_from_audit, primary=True, category="Переходы")]
    if network.is_open:
        return [Action("Назад к сетям", back_from_audit, primary=True, category="Переходы")]
    blocked = blocked or _blocker(network, state.readiness.peek())
    has_board = _board_present() and network.crackable
    has_key = state.audit_has_key.peek()
    if has_key:
        primary = Action("Проверить ключ Windows", _run_auto, primary=True)
    elif has_board and (has_key is False or blocked):
        primary = Action("Захват с платы", controller.start_board_capture, primary=True)
    elif _file_is_the_way_forward(network) or (not network.crackable and has_key is False):
        primary = Action("Выбрать файл захвата", _pick_capture_file, primary=True)
    else:
        primary = Action(_auto_label(network), _run_auto, primary=True, enabled=_auto_enabled(network))
    actions = [replace(primary, identifier="primary", category="Основное"),
               Action("Параметры", _open_parameters, category="Настройки")]
    if primary.run is not _pick_capture_file:
        actions.append(Action("Файл захвата", _pick_capture_file, category="Источники"))
    if has_board and primary.label != "Захват с платы":
        actions.append(Action("Захват с платы", controller.start_board_capture, category="Источники"))
    if network.crackable and not (has_board and blocked):
        actions.append(Action("Захват адаптером", _capture_only, enabled=not blocked,
                              description=blocked, category="Источники"))
    actions += [Action("Подробности сети", _show_details, category="Сведения"),
                Action("Назад к сетям", back_from_audit, category="Переходы")]
    return group_actions(actions)


def _on_key(event) -> None:
    if state.phase.peek() != "audit" or nav.is_ctrl(event):
        return
    event.stop_propagation()
    if controls.handle_action_key(event, "audit", audit_actions()):
        return
    if key_of(event) in controls.ESCAPE:
        back_from_audit()


def _disabled_reason(network: Network | None) -> str:
    """Why the button is greyed, in the network's own words.

    Not a generic "проверка недоступна": for an open network the fact is that
    there is no password, and that is the one thing this screen can tell
    someone who picked it by accident.
    """
    if network is None:
        return "Сеть не выбрана"
    if network.is_open:
        return "Пароль не требуется"
    return "Проверка недоступна"




def _blocker(network: Network, ready) -> str:
    """One concise reason shown by the command menu and primary action."""
    if not network.crackable:
        return crack_hint(network.auth)
    if ready is None:
        return ""
    if ready.capture_problem:
        return "Захват недоступен: " + ready.capture_problem
    if not ready.admin:
        return "Нет прав администратора; живой захват недоступен."
    if ready.backend is None or ready.iface is None:
        return "Источник захвата не найден; проверь параметры."
    return ""


@component
def AuditScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    use_keyboard(_on_key)
    network = state.audit_network()
    ready = state.readiness()
    has_key = state.audit_has_key()
    state.board()
    inner = max(8, width - 4)
    actions = audit_actions()
    if network is None:
        rows = [Text("Сеть не выбрана", fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
    else:
        rows = []
        blocked = _blocker(network, ready)
        primary = actions[0]
        if network.is_open:
            status, color = "Открытая сеть · пароля нет", TEXT_SECONDARY
        elif has_key:
            status, color = "Ключ сохранён в Windows", SUCCESS
        elif primary.label == "Захват с платы":
            status, color = "Плата подключена", SUCCESS
        elif blocked:
            status, color = "Нужен файл захвата", WARNING
        elif ready is None:
            status, color = "Проверка компонентов…", TEXT_SECONDARY
        else:
            status, color = "Готово к запуску", SUCCESS
        marker = "OK" if color == SUCCESS else "!" if color == WARNING else "…"
        rows += [text_line(f"[{marker}] {status}", inner, color=color, bold=True)]
        if blocked and not _board_present() and not has_key and network.crackable:
            rows.append(Text(truncate(reason_short(ready), inner), fg=TEXT_SECONDARY, height=1, wrap_mode="none"))
        if not network.is_open:
            source = "Ключ Windows" if has_key else "Плата M5StickC" if primary.label == "Захват с платы" else (
                "Файл захвата" if primary.run is _pick_capture_file else "Wi-Fi адаптер")
            rows.append(Row(col("Источник", 12), Text(source, fg=TEXT_PRIMARY, height=1, wrap_mode="none")))
        rows += [text_line("", inner),
                 text_line(f"{network.auth or '—'} · {network.protection or '—'} · канал {network.channel or '—'}", inner,
                           color=auth_color(network.auth)), text_line(network.bssid or "BSSID неизвестен", inner)]
        if height >= 24:
            rows.append(text_line(f"Сигнал {network.signal}% · {network.radio or 'тип радио не объявлен'}", inner))
    action_room = max(1, min(len(actions), height - 9 - len(rows)))
    details_panel = Box(
        Column(*rows), width=width, height=len(rows) + 2,
        border=True, border_style="rounded", border_color=OUTLINE,
        padding_x=1, flex_shrink=0, overflow="hidden",
    )
    actions_panel = Box(
        action_list("audit", actions, width=width - 2, room=action_room),
        width=width, height=action_room + 2,
        border=True, border_style="rounded", border_color=ACCENT,
        flex_shrink=0, overflow="hidden",
    )
    return workspace(
        workspace_header("Проверка сети", network.label if network else "", width=width),
        details_panel,
        Box(height=1, flex_shrink=0),
        actions_panel,
        Box(flex_grow=1),
        workspace_footer(width=width, hint="↑↓ Tab · Enter · Esc назад"),
        width=terminal_width, height=height,
    )


def reason_short(ready) -> str:
    """The one fact worth showing when there is genuinely nothing else to do."""
    if ready is None:
        return ""
    if ready.capture_problem:
        return "Захват в эфире недоступен."
    if not ready.admin:
        return "Нужен запуск от администратора."
    return "Захват в эфире недоступен."
