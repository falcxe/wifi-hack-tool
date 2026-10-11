"""Running process: stable target, status and a keyboard-scrollable log."""
from __future__ import annotations

import time

from opentui import Box, Column, Text, component
from opentui.hooks import use_keyboard, use_terminal_dimensions

from .. import actions as nav
from .. import controls, state
from ..actions import Action, key_of
from ..controller import PHASE_LABELS, quit_app
from ..theme import (ACCENT, TEXT_SECONDARY, SUCCESS, MAX_WORKSPACE_WIDTH, TEXT_PRIMARY, WARNING, fmt_duration, progress_bar,
                     progress_color)
from ..widgets import (action_list, spinner_frame, truncate, workspace, workspace_footer,
                       workspace_header, workspace_log, workspace_section)

#: Default capture window. Imported rather than repeated so the countdown bar is
#: drawn from the same number the pipeline actually uses -- a local copy would
#: silently drift the moment someone changed the controller's default.
from ..controller import CAPTURE_SECONDS


#: ``done`` / ``current`` / ``pending`` marks. The stage names in
#: :data:`PHASE_LABELS` say what each stage is; they used to be followed by a
#: restatement of the same thing in the first person ("Ищу пароль, который
#: Windows уже сохранил для этой сети"), which doubled the checklist's height
#: to say nothing the row above it did not already say.
_MARKS = {
    "done": ("[OK]", SUCCESS, TEXT_SECONDARY),
    "current": (">>", ACCENT, TEXT_PRIMARY),
    "pending": ("[..]", TEXT_SECONDARY, TEXT_SECONDARY),
    "skipped": ("[--]", TEXT_SECONDARY, TEXT_SECONDARY),
}


def _stage_rows(inner: int, stages: list, tick: int = 0) -> list:
    """The run as a checklist: one short line per stage, nothing else.

    The running stage carries a spinner, which is what makes this screen read as
    working rather than stuck. It advances off ``tick`` -- a signal the run screen
    subscribes to -- because a spinner drawn from a value that never changes does
    not spin.
    """
    rows: list = []
    for key, status in stages:
        mark, mark_color, _ = _MARKS.get(status, _MARKS["pending"])
        caption = PHASE_LABELS.get(key, key)
        if status == "current":
            caption = f"{spinner_frame(tick)} {caption}"
            mark = ">>"
        rows.append(Text(
            truncate(f"{mark}  {caption}", inner), fg=mark_color, bold=status == "current",
            height=1, flex_shrink=0, wrap_mode="none"))
    return rows


def _run_bar(inner: int, stages: list, percent: float, activity: str, tick: int) -> Text:
    return Text(truncate("Прошло " + fmt_duration(state.elapsed.peek()), inner),
                fg=TEXT_SECONDARY, height=1, flex_shrink=0, wrap_mode="none")


def crack_actions(running: bool = True) -> list[Action]:
    label = "Остановить ожидание" if state.run_source.peek() == "board" else "Остановить"
    return [
        Action(label, _stop, primary=True, enabled=running, danger=True, category="Основное"),
        Action("Выход", quit_app, danger=True, category="Приложение"),
    ]


def _capture_rows(inner: int, seconds_left: int, size: int, cancelling: bool,
                  tick: int = 0) -> list:
    total = state.capture_total.peek()
    if total is None:
        total = CAPTURE_SECONDS
    percent = max(0.0, min(100.0, (total - seconds_left) / total * 100.0)) if total else 0.0
    rows = [
        Text(f"{spinner_frame(tick)}  Захват", fg=ACCENT, bold=True, wrap_mode="none"),
        Text(progress_bar(percent, max(8, min(26, inner - 8))),
             fg=progress_color(percent), wrap_mode="none"),
        Text(truncate(f"Осталось {seconds_left} с · {_size(size)}", inner),
             fg=TEXT_PRIMARY, wrap_mode="none"),
    ]
    if cancelling:
        rows.append(Text("Остановка…", fg=WARNING, wrap_mode="none"))
    return rows


def _size(count: int) -> str:
    if count >= 1 << 20:
        return f"{count / (1 << 20):.1f} МБ"
    if count >= 1 << 10:
        return f"{count / (1 << 10):.0f} КБ"
    return f"{count} Б"


def _on_key(event) -> None:
    if state.phase.peek() != "crack" or nav.is_ctrl(event):
        return
    event.stop_propagation()
    key = key_of(event)
    actions = crack_actions(not state.cancelled.peek())[:1]
    if key in controls.ESCAPE:
        _stop()
    elif controls.handle_action_key(event, "crack", actions, regions=("log",), default="log"):
        return
    elif controls.peek_focus("crack", ["log", *controls.all_action_ids(actions)], default="log") == "log":
        controls.scroll_log(key, state.log.peek())


def _stop() -> None:
    from ..commands import confirm_stop
    confirm_stop()


@component
def CrackScreen() -> Box:
    use_keyboard(_on_key)
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    net = state.cracking_network()
    source = state.run_source()
    context = state.run_context()
    deadline = state.board_deadline()
    status = state.status()
    activity = state.current_activity()
    percent = state.progress()
    known = state.progress_known()
    speed, eta = state.run_speed(), state.run_eta()
    cancelling = state.cancelled()
    stage = state.stage()
    stages = state.run_stages()
    capture_left = state.capture_left()
    state.capture_total()
    capture_bytes = state.capture_bytes()
    tick = state.tick()
    elapsed = state.elapsed()
    inner = max(8, width - 4)
    room = max(3, min(9, height - 11))
    if source == "board":
        title = "Захват с платы"
        caption = activity or "Подключение к плате…"
        rows = [Text(truncate(f"{spinner_frame(tick)}  {caption}", inner), fg=ACCENT,
                     bold=True, height=1, wrap_mode="none")]
        time_label = f"Прошло {fmt_duration(elapsed)}"
        if deadline is not None:
            time_label += f" · осталось {fmt_duration(max(0, deadline - time.monotonic()))}"
        rows.append(Text(truncate(time_label, inner), fg=TEXT_PRIMARY, height=1, wrap_mode="none"))
    elif capture_left is not None:
        title = "Захват сети"
        rows = _capture_rows(inner, capture_left, capture_bytes, cancelling, tick)
    elif stages:
        title = "Подбор"
        current = next((i for i, (_, status) in enumerate(stages) if status == "current"), 0)
        allowance = max(1, room - (4 if known or percent > 0 else 3))
        start = max(0, min(current - (1 if allowance > 1 else 0), len(stages) - allowance))
        rows = _stage_rows(inner, stages[start:start + allowance], tick)
        rows.append(_run_bar(inner, stages, percent, activity, tick))
        if known or percent > 0:
            rows.append(Text(progress_bar(percent, max(8, min(40, inner - 8))),
                             fg=progress_color(percent), height=1, wrap_mode="none"))
        if stage and len(rows) < room - 1:
            rows.append(Text(truncate(stage, inner), fg=TEXT_PRIMARY, height=1, flex_shrink=0, wrap_mode="none"))
    else:
        title = "Подбор"
        caption = PHASE_LABELS.get(activity, activity or "Запуск…")
        rows = [Text(truncate(f"{spinner_frame(tick)}  {caption}", inner), fg=ACCENT,
                     bold=True, height=1, wrap_mode="none"),
                Text(fmt_duration(elapsed), fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
        if stage:
            rows.append(Text(truncate(stage, inner), fg=TEXT_PRIMARY, height=1, wrap_mode="none"))
        if known or percent > 0:
            rows.append(Text(progress_bar(percent, max(8, min(40, inner - 8))),
                             fg=ACCENT, height=1, flex_shrink=0, wrap_mode="none"))
    found = state.capture_found()
    if found and len(rows) < room - 1:
        rows.append(Text(truncate(found, inner), fg=SUCCESS, height=1, wrap_mode="none"))
    if cancelling:
        rows.insert(0, Text("Остановка… ждём завершения процесса", fg=WARNING, height=1, flex_shrink=0, wrap_mode="none"))
    elif speed or eta:
        metrics = ([f"Скорость {speed}"] if speed else []) + ([f"ETA ~{eta}"] if eta else ["ETA неизвестно"])
        rows.append(Text(truncate(" · ".join(metrics), inner), fg=TEXT_PRIMARY, height=1, flex_shrink=0, wrap_mode="none"))
    elif status:
        rows.append(Text(truncate(status, inner), fg=TEXT_SECONDARY, height=1, wrap_mode="none"))
    elif source != "board" and capture_left is None:
        rows.append(Text("Длительность неизвестна", fg=TEXT_SECONDARY, height=1, flex_shrink=0, wrap_mode="none"))
    rows = rows[:room]
    actions = crack_actions(not cancelling)[:1]
    journal_height = max(3, height - 6 - len(rows))
    state.log_page.set(max(1, journal_height - 2))
    focus = controls.focused("crack", ["log", *controls.all_action_ids(actions)], default="log")
    return workspace(
        workspace_header(title, context or (net.label if net else "Запуск проверки"), width=width),
        workspace_section("", Column(*rows), height=len(rows), flex_shrink=0),
        action_list("crack", actions, width=width, regions=("log",), default="log"),
        Box(height=1, flex_shrink=0),
        workspace_log(state.log(), width, journal_height, state.log_scroll(),
                      focused=focus == "log", on_focus=lambda: controls.set_focus("crack", "log"),
                      border_style="rounded"),
        workspace_footer(width=width, hint="↑↓ журнал · Tab · Esc стоп" if focus == "log" else
                         "Enter остановить · Tab журнал"),
        width=terminal_width, height=height,
    )
