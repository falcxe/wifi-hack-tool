"""The first screen: pick what you came for, then see whether the machine can.

Two jobs, in this order, because a screen that asks a question before it knows
the answer answers it into a wall. If live capture cannot work here, that is
shown *above* the choice, so choosing "check my network" is an informed click
rather than a discovery three screens later.

The technical half -- exact tool names, paths and driver messages -- is one
row away behind «Технические детали», never mixed into the instruction lines.
"""
from __future__ import annotations

from opentui import Box, Column, Row, click_handler, component
from opentui.hooks import use_keyboard, use_terminal_dimensions

from .. import controls, plain, state
from ..actions import Action, key_of
from ..theme import (ACCENT, ERROR, MAX_WORKSPACE_WIDTH, OUTLINE, SUCCESS,
                     TEXT_PRIMARY, TEXT_SECONDARY, WARNING)
from ..widgets import (list_viewport, text_line, truncate, workspace,
                       workspace_action, workspace_footer, workspace_header,
                       workspace_section, wrap)

#: The three things a person can actually want from this program, in the order
#: they are offered. The first is the main flow, the second is the one that
#: works on any machine, and the third needs nothing installed at all.
SCENARIOS = ("network", "file", "saved")

REGIONS = ("list", "details")


def available(key: str) -> bool:
    """Whether this scenario can run at all in this build.

    The saved-keys screen is behind :data:`wifi_tool.profiles.HISTORY_ENABLED`,
    and that flag ships off. A row that looks selectable and then does nothing
    is the worst thing a first screen can do -- worse than not offering it --
    so it is drawn greyed with the reason instead.
    """
    if key == "saved":
        from ... import profiles

        return bool(profiles.HISTORY_ENABLED)
    return True


def unavailable_reason(key: str) -> str:
    return "" if available(key) else "Отключено в этой сборке."

#: Rows the chrome costs around the two panels: header 3, gap 1, details
#: toggle 1, primary action 1, footer 1. Derived rather than guessed, because a
#: wrong constant is a frame that scrolls off the top of a 20-row terminal.
_CHROME = 7


def scenario_key() -> str:
    index = state.scenario_index.peek()
    return SCENARIOS[index] if 0 <= index < len(SCENARIOS) else SCENARIOS[0]


def _move(delta: int) -> None:
    state.scenario_index.set((state.scenario_index.peek() + delta) % len(SCENARIOS))


def _toggle_details() -> None:
    state.start_details.set(not state.start_details.peek())


def _focus(key: str) -> None:
    controls.set_focus("start", key)


def _detail_lines(inner: int) -> list:
    rows = []
    for line in plain.technical_lines(state.readiness.peek()):
        for piece in wrap(line, inner - 2)[:2]:
            rows.append(text_line("· " + piece, inner, color=TEXT_SECONDARY))
    return rows


def _scenario_block(index: int, focus: str, inner: int, two_lines: bool) -> Box:
    """One selectable scenario: its number, its name and what it gets you."""
    key = SCENARIOS[index]
    chosen = index == state.scenario_index.peek()

    def choose(*_) -> None:
        _focus("list")
        state.scenario_index.set(index)

    marker = "›" if chosen and focus == "list" else "•" if chosen else " "
    title = text_line(f"{marker} {index + 1}. {plain.TITLES[key]}", inner,
                      color=ACCENT if chosen and focus == "list" else TEXT_PRIMARY,
                      bold=chosen)
    if not two_lines:
        return Box(Row(title, height=1, flex_shrink=0,
                       on_mouse_down=click_handler(choose)),
                   height=1, flex_shrink=0)
    subtitle = text_line(truncate(f"    {plain.SUBTITLES[key]}", inner), inner)
    return Box(Column(title, subtitle), height=2, flex_shrink=0,
               on_mouse_down=click_handler(choose))


def _checklist(inner: int, room: int, two_lines: bool) -> list:
    """Readiness for the selected scenario, as checkmarks and one instruction.

    Only the first blocking row carries a remedy. Three stacked "Что делать"
    paragraphs read as a wall of obligations and hide the one thing that is
    actually required first -- and the rest of the rows still say what is
    missing, so nothing is hidden by leaving them bare.
    """
    ready = state.readiness.peek()
    rows = [text_line(f"Проверка компьютера · {plain.TITLES[scenario_key()]}",
                      inner, bold=True)]
    todo_shown = False
    for fact in plain.facts(ready, scenario_key(), board=state.board.peek()):
        mark, color = ("OK", SUCCESS) if fact.ok else ("!", ERROR if two_lines else WARNING)
        rows.append(text_line(f"{mark} {fact.title} — {fact.status}", inner,
                              color=color, bold=fact.ok))
        if not fact.ok and fact.todo and not todo_shown:
            todo_shown = True
            for piece in wrap("Что делать: " + fact.todo, inner - 4)[:2]:
                rows.append(text_line("    " + piece, inner, color=TEXT_SECONDARY))
    rows.append(text_line(plain.headline(ready, scenario_key()), inner,
                          color=TEXT_PRIMARY, bold=True))
    # The verdict is the one line that must never be the one that gets cut:
    # a checklist without its summary is a list of complaints.
    return rows[:max(0, room - 1)] + rows[-1:]


def _begin() -> None:
    from .. import controller

    controller.start_scenario(scenario_key())


def _on_key(event) -> None:
    if state.phase.peek() != "start":
        return
    event.stop_propagation()
    key = key_of(event)
    focus = controls.peek_focus("start", list(REGIONS), default="list")
    if controls.is_tab(event):
        controls.step("start", list(REGIONS), controls.tab_delta(event), default="list")
    elif key in ("up", "down"):
        _focus("list")
        _move(-1 if key == "up" else 1)
    elif key in ("home", "end"):
        _focus("list")
        state.scenario_index.set(0 if key == "home" else len(SCENARIOS) - 1)
    elif key in ("enter", "return"):
        _toggle_details() if focus == "details" else _begin()
    elif key in controls.ESCAPE:
        from ..commands import open_menu

        open_menu()


def _focus_list() -> None:
    _focus("list")


def show_details_dialog() -> None:
    """The same technical list as a modal, for the F1 command menu."""
    from .. import dialogs

    dialogs.open_select("Технические детали", [
        Action(line, lambda: None)
        for line in plain.technical_lines(state.readiness.peek())
    ], searchable=False)


def start_actions() -> list[Action]:
    from .. import controller

    key = scenario_key()
    ready = state.readiness.peek()
    blocked = key != "saved" and plain.blocked_for(ready, key)
    return [
        Action(f"Начать: {plain.TITLES[key]}", _begin, primary=True,
               enabled=not blocked or key != "network",
               description="" if not blocked else plain.next_step(ready, key),
               category="Основное"),
        Action("Выбрать другой сценарий", _focus_list, category="Основное"),
        Action("Технические детали", _toggle_details, category="Сведения"),
        Action("Пропустить и открыть список сетей", controller.skip_start,
               description="Без проверки компьютера, сразу к поиску сетей.",
               category="Переходы"),
        Action("Выход", controller.quit_app, danger=True, category="Приложение"),
    ]


@component
def StartScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    use_keyboard(_on_key)
    inner = max(12, width - 8)
    focus = controls.focused("start", list(REGIONS), default="list")
    # Two lines per scenario only when the terminal can pay for them: at 20 rows
    # the checklist is the part worth protecting, not the subtitles.
    two_lines = height >= 26

    blocks = [_scenario_block(index, focus, inner, two_lines) for index in range(len(SCENARIOS))]
    list_height = len(SCENARIOS) * (2 if two_lines else 1) + 2
    listing = list_viewport("Выберите, что хотите сделать", *blocks,
                            height=list_height, focused=focus == "list",
                            on_focus=lambda: _focus("list"))

    details = _detail_lines(inner) if state.start_details() else []
    room = max(2, height - (_CHROME + list_height))
    detail_room = min(len(details), max(0, room - 4))
    check_room = max(2, room - detail_room)

    toggle = "Технические детали: [−] Скрыть" if details else "Технические детали: [+] Раскрыть"
    body = [
        listing,
        Box(height=1, flex_shrink=0),
        workspace_section("", *_checklist(inner, check_room, two_lines),
                          height=check_room, flex_shrink=0),
    ]
    if detail_room:
        body.append(workspace_section("", *details[:detail_room],
                                      height=detail_room, flex_shrink=0))
    body.append(workspace_section("", text_line(
        f"{'›' if focus == 'details' else ' '} {toggle}", inner,
        color=ACCENT if focus == "details" else TEXT_SECONDARY),
        height=1, flex_shrink=0))
    return workspace(
        workspace_header("С чего начать", f"Первый запуск · {plain.TITLES[scenario_key()]}",
                         width=width),
        *body,
        Box(flex_grow=1),
        workspace_action(f"Начать: {plain.TITLES[scenario_key()]}", _begin,
                         width=width, key="Enter", selected=focus == "list"),
        workspace_footer(width=width,
                         hint="↑↓ выбор · Enter начать · Tab детали · F1 меню"),
        width=terminal_width, height=height,
    )