"""Focused parameter editing, file/target lists and the help viewport."""
from __future__ import annotations

from pathlib import Path

from opentui import Box, Column, Row, Text, click_handler, component
from opentui.hooks import use_keyboard, use_paste, use_terminal_dimensions

from .. import actions as nav
from .. import controls, dialogs, forms, help_content, motion, state
from ..actions import Action, group_actions, key_of
from ..theme import ACCENT, TEXT_SECONDARY, FOCUS_SURFACE, SUCCESS, MAX_WORKSPACE_WIDTH, TEXT_PRIMARY, WARNING
from ..widgets import (action_list, col, edit_preview, list_viewport, text_line, truncate, truncate_middle, wrap, workspace, workspace_action, workspace_footer,
                       workspace_header, workspace_section)



def _display(key: str, values: dict) -> str:
    if key == "source":
        return ("Файл захвата" if values.get(key) == "file"
                else "Захват сети")
    if key == "mode":
        return forms.MODE_LABELS.get(values.get(key), "RockYou WPA")
    if key == "rules":
        return "Включены" if values.get(key) else "Выключены"
    if key == "start":
        return "Начать подбор"
    if key == "advanced":
        return "[−] Скрыть" if state.form_advanced.peek() else "[+] Раскрыть"
    return str(values.get(key, ""))


def _field_row(index, key, label, kind, values, selected, width):
    active = index == selected
    def paint(row):
        return motion.paint(row, "form", selected, index,
                            token=(width, tuple(field[0] for field in forms.fields())))
    if kind == "button":
        action = form_actions(forms.start_problem())[0]
        return paint(Row(col("›" if active else "", 2, fg=ACCENT),
                   col(action.label, width - 6, fg=TEXT_SECONDARY if not action.enabled else ACCENT if active else TEXT_PRIMARY,
                       bold=active), height=1, flex_shrink=0,
                   on_mouse_down=click_handler(lambda *args: _click_start(index, action))))
    available = max(8, width - 22)
    value = _display(key, values)
    if active and kind in ("text", "file"):
        cursor = min(state.form_cursor(), len(value))
        value = edit_preview(value, cursor, available)
    elif kind == "file":
        value = truncate_middle(value, available)
    if not value:
        value = {"capture": "Выбрать файл", "wordlist": "Выбрать словарь",
                 "rules_path": "Авто", "bssid": "Авто"}.get(key, "—")
    def click(*_) -> None:
        forms.focus(index)
        if kind == "choice":
            forms.open_choice(key)
        elif kind == "file":
            forms.open_picker_for(key)
    return paint(Row(
        col("›" if active else "", 2, fg=ACCENT),
        col(label, 14, fg=TEXT_PRIMARY if active else TEXT_SECONDARY),
        col(truncate(value, available), available, fg=TEXT_PRIMARY, bold=active,
            background_color=FOCUS_SURFACE if active and state.form_select_all.peek()
            and kind in ("text", "file") else None),
        col("›" if kind in ("file", "choice") else "", 2, fg=ACCENT),
        height=1, flex_shrink=0,
        on_mouse_down=click_handler(click),
    ))


# ---------------------------------------------------------------------------
# readiness
# ---------------------------------------------------------------------------


def _name(path) -> str:
    """Show just the file name -- full paths blow out narrow terminals."""
    return Path(path).name if path else ""


def _check_rows(readiness) -> list[tuple[bool, str, str, str]]:
    """``(ok, label, found, fix)`` for each component the pipeline needs."""
    checks = [
        (readiness.admin, "права админа", "да", "нужны права админа"),
        (
            readiness.adapter is not None,
            "Wi-Fi адаптер",
            readiness.adapter.description if readiness.adapter else "",
            "не найден",
        ),
        (
            readiness.hashcat is not None,
            "hashcat",
            _name(readiness.hashcat),
            # Not just the exe: hashcat needs its OpenCL/modules/kernels tree
            # beside it, and pointing at a bare hashcat.exe is what produces
            # "./OpenCL/: No such file or directory" on the first run.
            "папка hashcat -> assets/",
        ),
        (
            readiness.wordlist is not None,
            "словарь",
            _name(readiness.wordlist),
            "rockyou.txt -> assets/",
        ),
        (
            readiness.backend is not None,
            "захват",
            _name(getattr(readiness.backend, "exe", None)),
            "tshark/cap80211 -> assets/",
        ),
        (
            readiness.iface is not None,
            "интерфейс",
            f"#{readiness.iface.index} {readiness.iface.name}" if readiness.iface else "",
            "не найден",
        ),
    ]
    values = state.form_values.peek()
    if values.get("source") == "file":
        checks = [row for row in checks if row[1] in ("hashcat", "словарь")]
    if values.get("mode") == "mask":
        checks = [row for row in checks if row[1] != "словарь"]
    return checks




# ---------------------------------------------------------------------------
# body
# ---------------------------------------------------------------------------


def _clip(text: str, width: int, max_lines: int, color: str) -> list:
    lines = wrap(text, max(16, width))
    if len(lines) > max_lines:
        short = " ".join(lines[:max_lines]).rstrip(" ,;.:—-") + " …"
        lines = wrap(short, max(16, width))[:max_lines]
    return [Text(line, fg=color, wrap_mode="none") for line in lines]


def _compact_problem(problem: str) -> str:
    if problem.startswith("Нет данных для проверки пароля"):
        return "Выберите файл захвата с EAPOL / PMKID"
    if problem.startswith("Доступность захвата ещё не проверена"):
        return "Проверка компонентов…"
    return problem.split("\n")[0]


def _plan(width: int, height: int, fields, values, selected, problem, error,
          readiness) -> list:
    inner = max(8, width - 4)
    room = max(1, height - 7)
    errors = forms.field_errors()
    body, positions = [], {}
    for i, (key, label, kind) in enumerate(fields):
        if key == "start":
            continue
        group = {"source": "ДАННЫЕ", "mode": "ПРОВЕРКА"}.get(key)
        if group:
            body.append(text_line(group, inner, bold=True))
        positions[i] = len(body)
        body.append(_field_row(i, key, label, kind, values, selected, width))
        if key in errors:
            for line in wrap("! " + _compact_problem(errors[key]), inner)[:2]:
                body.append(text_line(line, inner, color=WARNING))
    at = positions.get(selected, len(body) - 1)
    first = max(0, min(at - room + 2, len(body) - room))
    visible = body[first:first + room]
    if len(body) > room:
        visible = visible[:room - 1] + [text_line(f"Параметры {first + 1}–{min(first + room - 1, len(body))}/{len(body)} · Tab далее", inner)]
    return visible


# ---------------------------------------------------------------------------
# screens
# ---------------------------------------------------------------------------


def form_actions(blocked: str = "", installing: bool = False) -> list[Action]:
    """Commands for form validation and component installation."""
    from .. import controller

    downloading = installing or state.install_state.peek() == "working"
    return group_actions([
        Action("Начать подбор", _submit, primary=not blocked,
               enabled=not blocked and not downloading,
               description="Идёт установка компонентов." if downloading else blocked, category="Основное"),
        Action("Файл", forms.open_picker_current, enabled=not downloading, category="Источники"),
        Action("Очистить поле", forms.clear_current_field, enabled=not downloading and
               forms.fields()[min(state.form_focus.peek(), len(forms.fields()) - 1)][2] in ("text", "file"), category="Настройки"),
        Action("Проверить компоненты", controller.refresh_readiness_here,
               enabled=not downloading, category="Компоненты"),
        Action("Установить компоненты", controller.download_tools, enabled=not downloading, category="Компоненты"),
        Action("Компоненты", _show_components, enabled=not downloading, category="Компоненты"),
        Action("Справка", forms.open_help, enabled=not downloading, category="Сведения"),
        Action("Назад", forms.go_back, enabled=not downloading, category="Переходы"),
    ])


def _submit() -> None:
    problem = forms.start_problem()
    if problem:
        state.form_error.set(problem)
    else:
        forms.submit()


def _click_start(index: int, action: Action) -> None:
    forms.focus(index)
    if action.enabled:
        action.run()


def _show_components() -> None:
    ready = state.readiness.peek()
    items = ([Action(f"{'OK' if ok else '!'} {label}", lambda: None,
                     description=found if ok else fix)
              for ok, label, found, fix in _check_rows(ready)] if ready else
             [Action("Проверка компонентов…", lambda: None)])
    dialogs.open_select("Компоненты", items, searchable=False)


def _on_key(event) -> None:
    if state.phase.peek() != "crack_form":
        return
    event.stop_propagation()
    key = key_of(event)
    if state.install_state.peek() == "working":
        if key in controls.ESCAPE:
            forms.go_back()
        return
    rows = forms.fields()
    index = min(state.form_focus.peek(), len(rows) - 1)
    field, _, kind = rows[index]
    if key in controls.ESCAPE:
        forms.go_back()
    elif key in nav.ENTER:
        if kind == "choice":
            forms.open_choice(field)
        elif kind == "file":
            forms.open_picker_for(field)
        elif kind == "button":
            _submit()
        else:
            forms.focus((index + 1) % len(rows))
    else:
        forms.on_key(event)


@component
def CrackFormScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    use_keyboard(_on_key)
    use_paste(forms.on_paste)
    values = state.form_values()
    selected = state.form_focus()
    state.form_select_all()
    state.form_advanced()
    network = state.form_network()
    error = state.form_error()
    readiness = state.readiness()
    install = state.install_state()
    progress = state.install_progress()
    problem = forms.start_problem()
    context = network.label if network else "Файл захвата"
    if install == "working":
        body = [Text("Установка компонентов…", fg=ACCENT, bold=True, height=1, wrap_mode="none"),
                Text(truncate(progress or "Проверка загрузки…", width - 4), fg=TEXT_SECONDARY,
                     height=1, wrap_mode="none"), Text("", height=1, flex_shrink=0)]
        body.extend(Text(truncate(line, width - 4), fg=TEXT_SECONDARY, height=1,
                         flex_shrink=0, wrap_mode="none")
                    for line in state.log()[-max(1, height - 7):])
    else:
        form_width = width - 40 if width >= 120 else width
        body = _plan(form_width, height, forms.fields(), values, selected, problem, error, readiness)
    kind = forms.fields()[min(selected, len(forms.fields()) - 1)][2]
    hint = "↑↓ Tab · Enter выбор · Esc назад" if kind in ("choice", "button") else (
        "Tab · Enter файл · ←→ · Esc назад" if kind == "file" else "Tab · ←→ курсор · Esc назад")
    action = form_actions(problem or error, install == "working")[0]
    ready_text = "Готово к запуску" if readiness else "Компоненты проверятся при запуске"
    if width >= 120 and install != "working":
        info = help_content.contextual_info(forms.fields()[min(selected, len(forms.fields()) - 1)][0], values)
        detail = [text_line(info.title, 34, color=TEXT_PRIMARY, bold=True)]
        detail += [text_line(line, 34) for line in wrap(info.description, 34)]
        if readiness:
            detail += [text_line("", 34), text_line("КОМПОНЕНТЫ", 34, bold=True)]
            detail += [text_line(f"{'OK' if ok else '!'} {label}: {found if ok else fix}", 34,
                                 color=SUCCESS if ok else WARNING) for ok, label, found, fix in _check_rows(readiness)]
        work_area = Row(workspace_section("", Column(*body), width=width - 40, height=len(body), flex_shrink=0),
                        workspace_section("", *detail, width=40, height=min(height - 7, len(detail)), flex_shrink=0))
    else:
        work_area = workspace_section("", Column(*body), height=len(body), flex_shrink=0)
    return workspace(
        workspace_header("Параметры", context, width=width),
        work_area,
        Box(flex_grow=1),
        *([] if install == "working" else [
            workspace_section("", text_line(_compact_problem(error or problem) or ready_text, width - 4,
                                             color=WARNING if error or problem else SUCCESS if readiness else TEXT_SECONDARY), height=1, flex_shrink=0),
            workspace_action("Начать подбор", lambda: _click_start(len(forms.fields()) - 1, action),
                             width=width, key="Enter" if kind == "button" else "",
                             enabled=action.enabled, selected=kind == "button")]),
        workspace_footer(width=width, hint="Установка…" if install == "working" else hint),
        width=terminal_width, height=height,
    )


@component
def MethodHelpScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    use_keyboard(_help_key)
    colors = {"title": ACCENT, "text": TEXT_PRIMARY, "plus": SUCCESS, "minus": WARNING}
    lines = [(line, kind) for text, kind in help_content.document()
             for line in (wrap(text, width - 4) if text else [""])]
    viewport_height = max(3, height - 6)
    room = max(1, viewport_height - 2)
    state.help_lines.set(len(lines))
    state.help_page.set(room)
    start = min(state.help_scroll(), max(0, len(lines) - room))
    start, indices = motion.window("help", len(lines), room, None, target=start,
                                    token=(width, height, len(lines)))
    actions = [help_actions()[-1]]
    focus = controls.focused("method_help", ["document", *controls.all_action_ids(actions)], default="document")
    visible = [Text(line, fg=colors[kind], bold=kind == "title", height=1,
                    flex_shrink=0, wrap_mode="none") for line, kind in (lines[i] for i in indices)]
    return workspace(
        workspace_header("Справка", f"{start + 1}–{min(start + room, len(lines))}/{len(lines)}", width=width),
        list_viewport("Документ", *visible, height=viewport_height, focused=focus == "document",
                      scroll=(len(lines), room, start),
                      on_focus=lambda: controls.set_focus("method_help", "document")),
        Box(height=1, flex_shrink=0),
        action_list("method_help", actions, width=width, regions=("document",), default="document"),
        workspace_footer(width=width, hint="↑↓ PgUp/PgDn · Tab · Esc назад" if focus == "document" else
                         "Enter закрыть · Tab · Esc назад"), width=terminal_width, height=height,
    )




def picker_actions() -> list[Action]:
    entries = state.file_entries.peek()
    selected = min(state.file_selected.peek(), max(0, len(entries) - 1))
    label = "Открыть папку" if entries and entries[selected].is_dir() else "Выбрать файл"
    return [Action(label, forms.choose_file, primary=True, enabled=bool(entries), identifier="primary", category="Основное"),
            Action("На уровень выше", forms.list_parent, category="Переходы"),
            Action("Назад к параметрам", forms.close_picker, category="Переходы")]


def _picker_key(event) -> None:
    if state.phase.peek() != "file_picker" or nav.is_ctrl(event):
        return
    event.stop_propagation()
    key = key_of(event)
    if key in controls.ESCAPE:
        forms.close_picker()
    elif controls.handle_action_key(event, "file_picker", [], regions=("list",), default="list"):
        return
    else:
        if key == "left":
            forms.list_parent()
        elif key in nav.CHOOSE:
            forms.choose_file()
        else:
            forms.picker_key(event)


@component
def FilePickerScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    use_keyboard(_picker_key)
    entries = state.file_entries()
    selected = state.file_selected()
    directory = Path(state.file_directory())
    error = state.file_error()
    focus = controls.focused("file_picker", ["list"], default="list")
    list_active = focus == "list"
    room = max(1, height - 6 - bool(error))
    controls.list_page("file_picker", room)
    token = (width, height, str(directory), id(entries))
    start, indices = motion.window("files", len(entries), room, selected, token=token)
    type_width = 9 if width >= 60 else 0
    name_width = max(8, width - 6 - type_width)
    rows = []
    for i in indices:
        path = entries[i]
        name = ".." if path == directory.parent and i == 0 else path.name
        is_dir = path.is_dir()
        def select(*_, index=i):
            controls.set_focus("file_picker", "list")
            state.file_selected.set(index)
            forms.choose_file()
        cells = [col("›" if i == selected and list_active else "•" if i == selected else "", 2,
                     fg=ACCENT if list_active else TEXT_SECONDARY),
                 col(truncate_middle(name + "/" if is_dir else name, name_width - 1), name_width,
                     fg=ACCENT if i == selected and list_active else TEXT_PRIMARY, bold=i == selected)]
        if type_width:
            cells.append(col("Папка" if is_dir else path.suffix.lstrip("."), type_width, fg=TEXT_SECONDARY))
        rows.append(motion.paint(Row(*cells, height=1, flex_shrink=0,
                        on_mouse_down=click_handler(select)), "files", selected, i, token=token,
                                                    focused=list_active, zebra=True))
    if not rows:
        rows = [Text("Подходящих файлов нет", fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
    error_view = ([workspace_section("", Text(truncate(error, width - 4), fg=WARNING,
                                             height=1, wrap_mode="none"), height=1, flex_shrink=0)] if error else [])
    return workspace(
        workspace_header("Выбор файла", truncate_middle(str(directory), width - 4), width=width),
        list_viewport("Папки и файлы", *rows, height=len(rows) + 2, focused=list_active,
                      scroll=(len(entries), room, start),
                      on_focus=lambda: controls.set_focus("file_picker", "list")),
        *error_view,
        Box(flex_grow=1),
        workspace_footer(width=width, hint="Enter выбор · ← вверх · Esc назад"),
        width=terminal_width, height=height,
    )


def help_actions() -> list[Action]:
    """Bar actions in the help screen: page down, page up, close.

    Page-sized steps as buttons, because scrolling a long document by single rows
    with ``down`` is exactly the tedious case buttons exist for.
    """
    return [
        Action("Страница +", lambda: forms.scroll_help(forms.help_page_step()), category="Основное"),
        Action("Страница −", lambda: forms.scroll_help(-forms.help_page_step()), category="Основное"),
        Action("Закрыть", forms.close_help, category="Переходы"),
    ]


def _help_key(event) -> None:
    if state.phase.peek() != "method_help" or nav.is_ctrl(event):
        return
    event.stop_propagation()
    actions = [help_actions()[-1]]
    if key_of(event) in controls.ESCAPE:
        forms.close_help()
    elif controls.handle_action_key(event, "method_help", actions, regions=("document",), default="document"):
        return
    elif controls.peek_focus("method_help", ["document", *controls.all_action_ids(actions)], default="document") == "document":
        forms.help_key(event)




def _choose_target() -> None:
    from .. import controller

    controller.choose_capture_target()


def _back_to_form() -> None:
    from .. import navigation
    navigation.back("crack_form")


def target_actions(count: int) -> list[Action]:
    """Bar actions when a capture holds several access points: pick, back.

    A file with three BSSIDs in it has three different keys, so choosing the wrong
    one wastes the whole capture. That is why this is a confirmation step with the
    network named, not a silent "picked the first".
    """
    return [
        Action("Выбрать сеть", _choose_target, primary=True, enabled=count > 0, category="Основное"),
        Action("Назад к параметрам", _back_to_form, category="Переходы"),
    ]


def _target_key(event) -> None:
    if state.phase.peek() != "capture_targets" or nav.is_ctrl(event):
        return
    event.stop_propagation()
    targets = state.capture_targets.peek()
    actions = target_actions(len(targets))
    key = key_of(event)
    if key in controls.ESCAPE:
        _back_to_form()
    elif controls.handle_action_key(event, "capture_targets", actions, regions=("list",), default="list"):
        return
    elif controls.peek_focus("capture_targets", ["list", *controls.all_action_ids(actions)], default="list") == "list":
        selected = state.capture_selected.peek()
        if key in ("up", "down", "pageup", "pagedown"):
            page = controls.list_page("capture_targets")
            delta = {"up": -1, "down": 1, "pageup": -page, "pagedown": page}[key]
            state.capture_selected.set(max(0, min(len(targets) - 1, selected + delta * getattr(event, "repeat_count", 1))))
        elif key in ("home", "end"):
            state.capture_selected.set(0 if key == "home" else max(0, len(targets) - 1))
        elif key in nav.CHOOSE:
            _choose_target()


@component
def CaptureTargetsScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    targets = state.capture_targets()
    selected = state.capture_selected()
    use_keyboard(_target_key)
    actions = target_actions(len(targets))
    focus = controls.focused("capture_targets", ["list", *controls.all_action_ids(actions)], default="list")
    list_active = focus == "list"
    room = max(1, height - 10)
    controls.list_page("capture_targets", room)
    token = (width, height, id(targets))
    start, indices = motion.window("targets", len(targets), room, selected, token=token)
    name_w = max(8, width - 24)
    rows = [Row(col("", 2), col("Сеть", name_w), col("BSSID", 18), height=1, flex_shrink=0)]
    for i in indices:
        network = targets[i]
        def choose(*_, index=i):
            controls.set_focus("capture_targets", "list")
            state.capture_selected.set(index)
            _choose_target()
        rows.append(motion.paint(Row(
            col("›" if i == selected and list_active else "•" if i == selected else "", 2,
                fg=ACCENT if list_active else TEXT_SECONDARY),
            col(truncate(network.label, name_w - 1), name_w,
                fg=ACCENT if i == selected and list_active else TEXT_PRIMARY, bold=i == selected),
            col(network.bssid, 18, fg=TEXT_SECONDARY), height=1, flex_shrink=0,
            on_mouse_down=click_handler(choose)), "targets", selected, i, token=token,
                                        focused=list_active, zebra=True))
    if not targets:
        rows = [Text("Сетей в файле нет", fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
    return workspace(
        workspace_header("Сеть из файла", f"{len(targets)} сетей · " +
                         truncate_middle(state.capture_source(), max(8, width - 18)), width=width),
        list_viewport("Сети", *rows, height=len(rows) + 2, focused=list_active,
                      scroll=(len(targets), room, start),
                      on_focus=lambda: controls.set_focus("capture_targets", "list")),
        Box(height=1, flex_shrink=0),
        action_list("capture_targets", actions, width=width, regions=("list",), default="list"),
        Box(flex_grow=1),
        workspace_footer(width=width, hint="↑↓ сеть · Tab · Enter · Esc" if list_active else
                         "↑↓ Tab · Enter · Esc назад"), width=terminal_width, height=height,
    )
