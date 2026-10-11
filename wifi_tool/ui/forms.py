"""TUI audit form, field editing, and file selection."""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from ..options import (CrackOptions, WORDLIST_NAMES, find_quick_wordlist,
                       find_wordlist)
from . import controls, dialogs, navigation, state
from .actions import Action, CHOOSE
from .help_content import MethodInfo

ROOT = Path(__file__).resolve().parents[2]

#: The choice that turns waiting into an event. Separate from the rest of the
#: form's options because it is the one that changes what happens to a network
#: that is not this machine.
DEAUTH = MethodInfo(
    "Как дождаться рукопожатия",
    "Пассивно — ждать, пока клиент сам переподключится. С deauth — в эфир "
    "уходит кадр отключения, клиент переподключается сразу, и рукопожатие "
    "попадает в захват за секунды.",
    "Deauth превращает пятиминутное ожидание в десятки секунд.",
    "Все устройства этой сети отвалятся на несколько секунд. Против сети "
    "с 802.11w (Protected Management Frames) не поможет: там клиенты по "
    "замыслу игнорируют такие кадры.",
)
ASSETS_DIR = ROOT / "assets"
#: Shown in the field when nothing is discovered yet, so the label still says
#: what the mode means. Resolution always goes through
#: :func:`~wifi_tool.options.find_wordlist`, never through this name.
ROCKYOU = ASSETS_DIR / "rockyou-wpa.txt"
QUICK = ASSETS_DIR / "probable-wpa.txt"
MODES = ("rockyou", "quick", "custom", "mask")
MODE_LABELS = {"rockyou": "RockYou WPA", "quick": "Быстрый словарь",
               "custom": "Свой словарь", "mask": "Маска"}
FILE_FIELDS = {"capture", "wordlist", "rules_path"}


def _draft_key(network) -> str:
    return (network.bssid or network.ssid) if network else "offline"


def save_draft() -> None:
    drafts = dict(state.form_drafts.peek())
    drafts[_draft_key(state.form_network.peek())] = (
        dict(state.form_values.peek()), state.form_focus.peek(), state.form_cursor.peek(),
        state.form_advanced.peek()
    )
    state.form_drafts.set(drafts)


def open_choice(field: str) -> None:
    from . import help_content

    if field == "advanced":
        state.form_advanced.set(not state.form_advanced.peek())
        return
    values = state.form_values.peek()
    variants = {
        "source": [("file", "Файл захвата"), ("live", "Захват сети")],
        "mode": [(mode, MODE_LABELS[mode]) for mode in MODES],
        "rules": [(False, "Мутации выключены"), (True, "Мутации включены")],
        "deauth": [(False, "Ждать переподключения"),
                   (True, "Отвалить клиентов (deauth)")],
    }.get(field, [])
    items = []
    for value, label in variants:
        info = help_content.contextual_info(field, {**values, field: value})
        enabled = not (field == "source" and value == "live"
                       and state.form_network.peek() is None)
        description = ("" if enabled
                       else "Сначала выберите сеть")
        items.append(Action(label, lambda value=value: set_value(field, value),
                            enabled=enabled, description=description))
    current = next((i for i, (value, _) in enumerate(variants)
                    if value == values.get(field)), 0)
    title = {"source": "Источник данных", "mode": "Метод подбора",
             "rules": "Мутации словаря",
             "deauth": "Как дождаться рукопожатия"}.get(field, "Выбор значения")
    dialogs.open_select(title, items, selected=current)


def open_form(network=None, *, options: CrackOptions | None = None, capture: str = "") -> None:
    navigation.push("crack_form")
    restore = options is None and not capture
    options = options or CrackOptions(use_rules=False)
    # Keep the target the user picked. Switching the source to "file" because
    # live capture is unavailable silently retargets the run -- the form then
    # submits a capture path nobody chose -- so the blocker is explained in the
    # message line and the source stays on the network they selected.
    source = "live" if network and not capture else "file"
    mode = "mask" if options.mask else ("custom" if options.wordlist else "rockyou")
    # Recognise the discovered files, not two hardcoded names: a wordlist the
    # pipeline accepted used to show up here as "Свой словарь" with an empty
    # field, and re-picking it there failed validation.
    if options.wordlist is not None:
        if options.wordlist == find_wordlist(ASSETS_DIR):
            mode = "rockyou"
        elif options.wordlist == find_quick_wordlist(ASSETS_DIR):
            mode = "quick"
    state.form_values.set({"source": source, "capture": capture, "mode": mode,
                           "wordlist": str(options.wordlist or ""), "mask": options.mask or "MyHome?d?d",
                           "runtime": str(options.runtime), "rules": options.use_rules,
                           "rules_path": str(options.rules or ""),
                           "bssid": options.bssid or (network.bssid if network else ""),
                           "deauth": options.deauth})
    state.form_network.set(network)
    state.form_advanced.set(bool(options.use_rules or options.rules or options.bssid))
    state.form_focus.set(1 if source == "file" else 0)
    state.form_cursor.set(len(capture))
    state.form_select_all.set(False)
    # Availability is derived from live readiness, never cached as an error.
    state.form_error.set("")
    draft = state.form_drafts.peek().get(_draft_key(network)) if restore else None
    if draft:
        state.form_advanced.set(draft[3] if len(draft) > 3 else False)
        state.form_values.set(dict(draft[0]))
        state.form_focus.set(min(draft[1], len(fields()) - 1))
        state.form_cursor.set(draft[2])
        state.form_error.set("")


def fields() -> list[tuple[str, str, str]]:
    values = state.form_values.peek()
    rows = [("source", "Источник", "choice")]
    if values.get("source") == "file":
        rows.append(("capture", "Захват", "file"))
    rows.append(("mode", "Подбор", "choice"))
    if values.get("mode") == "custom":
        rows.append(("wordlist", "Словарь", "file"))
    elif values.get("mode") == "mask":
        rows.append(("mask", "Маска", "text"))
    rows.append(("runtime", "Лимит, сек", "text"))
    rows.append(("advanced", "Дополнительно", "choice"))
    if state.form_advanced.peek() and values.get("source") == "live":
        rows.append(("deauth", "Отвалить клиентов", "choice"))
    if state.form_advanced.peek() and values.get("mode") != "mask":
        rows.append(("rules", "Мутации", "choice"))
        if values.get("rules"):
            rows.append(("rules_path", "Правила", "file"))
    if state.form_advanced.peek() and values.get("source") == "file":
        rows.append(("bssid", "BSSID", "text"))
    rows.append(("start", "Запуск", "button"))
    return rows


def focus(index: int) -> None:
    rows = fields()
    index = max(0, min(len(rows) - 1, index))
    state.form_focus.set(index)
    value = state.form_values.peek().get(rows[index][0], "")
    state.form_cursor.set(len(value) if isinstance(value, str) else 0)
    state.form_select_all.set(False)


def set_value(key: str, value) -> None:
    if key in ("rules", "rules_path", "bssid") and value:
        state.form_advanced.set(True)
    values = dict(state.form_values.peek())
    values[key] = value
    state.form_values.set(values)
    state.form_error.set("")


def clear_current_field() -> None:
    rows = fields()
    field, _, kind = rows[min(state.form_focus.peek(), len(rows) - 1)]
    if kind in ("text", "file"):
        set_value(field, "")
        state.form_cursor.set(0)
        state.form_select_all.set(False)


def toggle(key: str, direction: int = 1) -> None:
    values = state.form_values.peek()
    if key == "advanced":
        state.form_advanced.set(not state.form_advanced.peek())
    elif key == "source":
        if state.form_network.peek() is not None:
            set_value(key, "live" if values.get(key) == "file" else "file")
    elif key == "mode":
        set_value(key, MODES[(MODES.index(values.get(key, "rockyou")) + direction) % len(MODES)])
    elif key == "rules":
        set_value(key, not values.get(key))
    state.form_focus.set(min(state.form_focus.peek(), len(fields()) - 1))


def go_back() -> None:
    """Leave the form for the screen that opened it, keeping edits in memory."""
    navigation.back()


def insert_text(text: str) -> None:
    rows = fields()
    key, _, kind = rows[min(state.form_focus.peek(), len(rows) - 1)]
    if kind not in ("text", "file"):
        return
    # Single-line fields retain casing, Unicode and spaces in pasted paths.
    text = text.replace("\r", "").replace("\n", "")
    if not text:
        return
    old = str(state.form_values.peek().get(key, ""))
    cursor = min(state.form_cursor.peek(), len(old))
    if state.form_select_all.peek():
        old, cursor = "", 0
    set_value(key, (old[:cursor] + text + old[cursor:])[:4096])
    state.form_cursor.set(min(cursor + len(text), 4096))
    state.form_select_all.set(False)


def on_paste(event) -> None:
    if (state.phase.peek() != "crack_form" or event.propagation_stopped
            or state.install_state.peek() == "working"):
        return
    text = getattr(event, "text", "")
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    insert_text(text)
    event.stop_propagation()


def on_key(event) -> None:
    if state.phase.peek() != "crack_form":
        return
    if hasattr(event, "stop_propagation"):
        event.stop_propagation()
    # The symbolic name is shared by native input and the test harness.
    key = (getattr(event, "name", "") or getattr(event, "key", "") or getattr(event, "code", "")).lower()
    rows = fields()
    index = min(state.form_focus.peek(), len(rows) - 1)
    field, _, kind = rows[index]
    if getattr(event, "ctrl", False):
        if kind in ("text", "file"):
            if key == "a":
                state.form_select_all.set(True)
            elif key == "u":
                set_value(field, "")
                state.form_cursor.set(0)
                state.form_select_all.set(False)
        return
    if key in controls.ESCAPE:
        go_back()
    elif controls.is_tab(event):
        focus((index + controls.tab_delta(event)) % len(rows))
    elif key in ("up", "down"):
        focus(index + (1 if key == "down" else -1))
    elif key in ("enter", "return"):
        if kind == "choice":
            open_choice(field)
        elif kind == "file":
            open_picker_for(field)
        elif kind == "button":
            submit()
        else:
            focus(index + 1)
    elif key in ("left", "right") and kind == "choice":
        toggle(field, -1 if key == "left" else 1)
    elif kind == "choice" and key == "space":
        open_choice(field)
    elif kind in ("text", "file"):
        value = str(state.form_values.peek().get(field, ""))
        cursor = min(state.form_cursor.peek(), len(value))
        if key in ("home", "end", "left", "right"):
            cursor = {"home": 0, "end": len(value), "left": max(0, cursor - 1),
                      "right": min(len(value), cursor + 1)}[key]
            state.form_cursor.set(cursor)
            state.form_select_all.set(False)
        elif key in ("backspace", "delete"):
            if state.form_select_all.peek():
                set_value(field, "")
                state.form_cursor.set(0)
            elif key == "backspace" and cursor:
                set_value(field, value[:cursor - 1] + value[cursor:])
                state.form_cursor.set(cursor - 1)
            elif key == "delete":
                set_value(field, value[:cursor] + value[cursor + 1:])
            state.form_select_all.set(False)
        else:
            raw = getattr(event, "sequence", "")
            if len(raw) != 1 or not raw.isprintable():
                raw = getattr(event, "key", "") or getattr(event, "name", "")
                if len(raw) == 1 and getattr(event, "shift", False):
                    raw = raw.upper()
            if raw == "space":
                raw = " "
            if len(raw) == 1 and raw.isprintable():
                insert_text(raw)


def _path(text: str) -> Path | None:
    text = text.strip().strip('"')
    return Path(text).expanduser().resolve() if text else None


def _options(values: dict) -> CrackOptions:
    mode = values.get("mode", "rockyou")
    wordlist = {
        "rockyou": find_wordlist(ASSETS_DIR),
        "quick": find_quick_wordlist(ASSETS_DIR),
    }.get(mode)
    if mode in ("rockyou", "quick") and wordlist is None:
        # The label promises a bundled list; say which files are accepted rather
        # than failing later with a bare path in the message.
        raise ValueError(
            f"Готовый словарь не найден в assets/. Положи туда файл из списка: "
            f"{', '.join(WORDLIST_NAMES)}"
        )
    if mode == "custom":
        wordlist = _path(values.get("wordlist", ""))
        if wordlist is None:
            raise ValueError("Выбери словарь кнопкой «Файл» или укажи его путь")
    try:
        runtime = int(values.get("runtime", ""))
    except (ValueError, TypeError) as exc:
        raise ValueError("Лимит времени: введи целое число секунд") from exc
    options = CrackOptions(wordlist=wordlist, mask=values.get("mask") if mode == "mask" else None,
                           runtime=runtime,
                           use_rules=bool(values.get("rules")) and mode != "mask",
                           rules=_path(values.get("rules_path", "")) if values.get("rules") and mode != "mask" else None,
                           bssid=values.get("bssid", "").strip() or None,
                           deauth=bool(values.get("deauth")))
    options.validate()
    return options


def _check_deauth(values: dict, ready=None) -> None:
    """Refuse a kick that this machine cannot perform, rather than run without it.

    The option would otherwise sit there looking available and quietly do
    nothing, and a capture that waits passively while the user believes the
    network was kicked is the same five minutes as before plus the belief that
    something was tried.
    """
    if not values.get("deauth") or ready is None or ready.iface is None:
        return
    from .. import deauth as deauth_mod

    blocked = deauth_mod.probe(ready.iface)
    if blocked:
        raise ValueError(
            f"Отвалить клиентов не получится: {blocked}. "
            "Захват останется пассивным — сними галку, чтобы не ждать зря."
        )


def _source(values: dict, ready=None):
    """The validated target, plus the readiness checks that still apply."""
    from . import controller

    target = _check_target(values)
    if values.get("source") == "file":
        if ready is not None and not ready.hashcat:
            raise ValueError("hashcat не найден. F1 → Установить компоненты.")
        return target
    network = target
    if ready is None:
        raise ValueError("Доступность захвата ещё не проверена. "
                         "«Проверить» — прочитать адаптер и окружение.")
    if ready.capture_problem:
        raise ValueError(ready.capture_problem)
    if ready.backend and ready.backend.needs_channel and not network.channel:
        raise ValueError("Канал не получен: обнови список сетей через нижнюю панель")
    if not ready.admin or not ready.backend or not ready.iface or not ready.hashcat:
        raise ValueError(controller._capture_blocker(ready))
    _check_deauth(values, ready)
    return network


def start_problem() -> str:
    """Persistent launch status using cached readiness, with no subprocesses."""
    try:
        values = state.form_values.peek()
        _options(values)
        _source(values, state.readiness.peek())
    except (ValueError, OSError) as exc:
        return str(exc)
    return ""


def problem_field(problem: str) -> str:
    text = problem.casefold()
    if "hashcat" in text:
        return "source"
    if "лимит" in text:
        return "runtime"
    if "маск" in text:
        return "mask"
    if "bssid" in text:
        return "bssid" if state.form_values.peek().get("source") == "file" else "source"
    if "правил" in text:
        return "rules_path"
    if "словар" in text:
        return "wordlist" if state.form_values.peek().get("mode") == "custom" else "mode"
    if state.form_values.peek().get("source") == "file":
        return "capture"
    return "source"


def field_errors() -> dict[str, str]:
    """Use existing validators; place their messages at the relevant controls."""
    values = state.form_values.peek()
    errors = {}
    for check in (lambda: _options(values), lambda: _source(values, state.readiness.peek())):
        try:
            check()
        except (ValueError, OSError) as exc:
            problem = str(exc)
            errors[problem_field(problem)] = problem
    if state.form_error.peek():
        problem = state.form_error.peek()
        errors[problem_field(problem)] = problem
    return errors


def submit() -> None:
    """Validate the form and start the run.

    Everything that can be judged from the form itself is checked here, so a
    missing BSSID or an unreadable capture is reported on the spot. The readiness
    probe is not: ``check_readiness`` shells out to netsh twice and tshark twice
    with ten-second timeouts, and running it on the render thread -- which is
    where the form's own key handler lives -- froze the TUI for as long as the
    slowest probe took, with no feedback. It runs on the controller's loop
    instead, and the run continues when the answer is in.
    """
    from . import controller

    values = state.form_values.peek()
    try:
        options = _options(values)
        # Raises for a missing/unreadable capture file and for a target that
        # cannot be attacked at all, before any subprocess is involved.
        _check_target(values)
    except (ValueError, OSError) as exc:
        state.form_error.set(str(exc))
        return
    ready = controller._readiness()
    if values.get("source") != "file" and ready is None:
        controller.start_when_ready(options)
        return
    _launch(options, values, ready)


def _check_target(values: dict):
    """Validate the target without touching readiness."""
    if values.get("source") == "file":
        capture = _path(values.get("capture", ""))
        if capture is None:
            raise ValueError(
                "Нет данных для проверки пароля. «Файл» — выбрать захват "
                "рукопожатия / PMKID (.pcapng, .pcap, .cap, .22000). "
                "Откуда его взять — в справке, раздел «Откуда взять файл захвата»."
            )
        if not capture.is_file():
            raise ValueError(f"Файл захвата не найден: {capture}")
        return capture
    network = state.form_network.peek()
    if network is None:
        raise ValueError("Сначала выбери свою сеть в списке или используй готовый файл")
    if not network.crackable:
        raise ValueError("Для выбранной схемы защиты этот подбор недоступен")
    if not network.bssid:
        raise ValueError(
            "BSSID не получен: вернись к списку, выбери «Обновить» и снова выбери сеть"
        )
    return network


def _launch(options: CrackOptions, values: dict, ready) -> None:
    """Apply the validated options and start, with ``ready`` already probed."""
    from . import controller

    try:
        target = _source(values, ready)
    except (ValueError, OSError) as exc:
        state.form_error.set(str(exc))
        return
    controller.configure_cracking(options)
    if values.get("source") == "file":
        controller.open_capture(target, choose_target=True)
    else:
        controller.start_attack(target)


def open_help() -> None:
    state.help_scroll.set(0)
    navigation.push("method_help")


def close_help() -> None:
    """Leave the help, keeping every field exactly as it was typed.

    Help is a detour, not a step: losing a half-written mask on the way back
    would make it something nobody opens twice.
    """
    navigation.back("crack_form")


def scroll_help(step: int) -> None:
    maximum = max(0, state.help_lines.peek() - state.help_page.peek())
    state.help_scroll.set(max(0, min(maximum, state.help_scroll.peek() + step)))


def help_page_step() -> int:
    return max(1, state.help_page.peek())


def help_key(event) -> None:
    """The help screen's keys, split so the action bar reuses the same parts."""
    if state.phase.peek() != "method_help":
        return
    event.stop_propagation()
    key = (getattr(event, "name", "") or getattr(event, "code", "")).lower()
    if key in controls.ESCAPE:
        close_help()
        return
    page = help_page_step()
    if key in ("up", "down", "pageup", "pagedown"):
        scroll_help({"up": -1, "down": 1, "pageup": -page, "pagedown": page}[key] * getattr(event, "repeat_count", 1))
    elif key == "home":
        scroll_help(-state.help_scroll.peek())
    elif key == "end":
        scroll_help(state.help_lines.peek())


def open_picker_current() -> None:
    """The «Файл» action: pick a file for whatever the cursor is on.

    Named apart from :func:`open_picker_for` so the menu action reads as a
    deliberate operation for the currently selected field.
    """
    rows = fields()
    index = min(state.form_focus.peek(), len(rows) - 1)
    open_picker_for(rows[index][0])


def open_picker_for(field: str) -> None:
    """Open the file picker for the selected or currently relevant field.

    The cursor starts on «Источник» and the form opens in live-capture mode,
    where the capture field is hidden. The file action reveals that field when
    the current mode needs it.
    """
    if field in FILE_FIELDS:
        open_picker(field)
        return
    values = state.form_values.peek()
    keys = [row[0] for row in fields()]
    # Pick the file field that belongs to the mode currently on screen, so the
    # file action does not open a picker for something the form will not submit.
    if values.get("mode") == "custom" and "wordlist" in keys:
        focus(keys.index("wordlist"))
        open_picker("wordlist")
        return
    if values.get("rules") and "rules_path" in keys:
        focus(keys.index("rules_path"))
        open_picker("rules_path")
        return
    if "capture" in keys:
        focus(keys.index("capture"))
        open_picker("capture")
        return
    if values.get("source") == "live":
        # No capture field is showing, so reveal it rather than refusing. The
        # mode switch is visible immediately afterwards, in the same field the
        # cursor was already on.
        set_value("source", "file")
        open_picker("capture")
        return
    state.form_error.set(
        "Кнопка «Файл» выбирает: захват, свой словарь или файл правил. "
        "Сейчас в форме нет ни одного из них — переключи Источник или Подбор."
    )


#: Where the chosen file goes. ``None`` means the historical behaviour: fill the
#: field and go back to the form. A callable means the screen that opened the
#: picker wants to act on the file itself -- picking a capture from the result
#: or the audit screen has to *start* the run, not fill a form field three
#: screens away.
_after_pick: Optional[Callable[[Path], None]] = None


def open_picker(field: str) -> None:
    global _after_pick
    # Any other route into the picker is a form field: clear the routing so a
    # previous "pick and run" cannot hijack this one.
    _after_pick = None
    state.file_field.set(field)
    current = _path(str(state.form_values.peek().get(field, "")))
    directory = current if current and current.is_dir() else current.parent if current else ROOT
    while not directory.is_dir() and directory != directory.parent:
        directory = directory.parent
    list_directory(directory)
    navigation.push("file_picker")


def pick_file_directly(on_pick: Callable[[Path], None], field: str = "capture") -> None:
    """Open the picker and hand the chosen file straight to ``on_pick``.

    Used by the screens whose whole message is "live capture cannot run here, use
    a file instead": making the user navigate to the parameters form first meant
    four keystrokes of menu walking to hand over one file, and the form then
    wanted Enter on the start button as well.
    """
    open_picker(field)
    global _after_pick
    _after_pick = on_pick


def list_directory(directory: Path) -> None:
    allowed = {"capture": {".pcap", ".pcapng", ".cap", ".22000", ".hc22000"},
               "wordlist": {".txt", ".lst", ".dic"}, "rules_path": {".rule"}}[state.file_field.peek()]
    try:
        entries = sorted((p for p in directory.iterdir() if p.is_dir() or p.suffix.lower() in allowed),
                         key=lambda p: (not p.is_dir(), p.name.lower()))
        if directory.parent != directory:
            entries.insert(0, directory.parent)
        state.file_directory.set(str(directory))
        state.file_entries.set(entries)
        state.file_selected.set(0)
        state.file_error.set("")
    except OSError as exc:
        state.file_error.set(f"Не удалось открыть папку: {exc}")


def choose_file() -> None:
    global _after_pick
    entries = state.file_entries.peek()
    index = state.file_selected.peek()
    if not 0 <= index < len(entries):
        return
    path = entries[index]
    if path.is_dir():
        list_directory(path)
        return
    after, _after_pick = _after_pick, None
    set_value(state.file_field.peek(), str(path))
    state.form_cursor.set(len(str(path)))
    if after is not None:
        after(path)
        return
    navigation.back("crack_form")


def close_picker() -> None:
    """Leave the picker, keeping whatever was already typed in the field."""
    global _after_pick
    _after_pick = None
    navigation.back("crack_form")


def list_parent() -> None:
    """Go up one directory in the file picker."""
    previous = Path(state.file_directory.peek())
    list_directory(previous.parent)
    entries = state.file_entries.peek()
    if previous in entries:
        state.file_selected.set(entries.index(previous))


def move_selection(step: int) -> None:
    entries = state.file_entries.peek()
    state.file_selected.set(max(0, min(len(entries) - 1,
                                       state.file_selected.peek() + step)))


def picker_key(event) -> None:
    """The picker's key handling, split so the action bar can reuse each part.

    Every branch is a named function above, because the bar's buttons do the same
    things and two copies of "go to the parent directory" would eventually differ.
    """
    if state.phase.peek() != "file_picker":
        return
    if hasattr(event, "stop_propagation"):
        event.stop_propagation()
    key = (getattr(event, "name", "") or getattr(event, "code", "")).lower()
    if key in controls.ESCAPE:
        close_picker()
    elif key == "left":
        list_parent()
    elif key == "backspace":
        list_parent()
    elif key in CHOOSE:
        choose_file()
    elif key in ("up", "down", "pageup", "pagedown"):
        page = controls.list_page("file_picker")
        move_selection({"up": -1, "down": 1, "pageup": -page, "pagedown": page}[key] * getattr(event, "repeat_count", 1))
    elif key == "home":
        state.file_selected.set(0)
    elif key == "end":
        state.file_selected.set(max(0, len(state.file_entries.peek()) - 1))
