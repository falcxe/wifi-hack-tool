"""Reusable searchable selection dialogs with exclusive input and restored focus.

Pattern reference (Python implementation, no TypeScript copied):
anomalyco/opencode, commit 3865c696efc97f30a34ea55b1d0ea4c26d939ecd,
packages/tui/src/ui/dialog.tsx and ui/dialog-select.tsx.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from opentui import Box, Column, Row, Text, click_handler, component
from opentui.hooks import use_terminal_dimensions
from opentui.signals import Signal

from .actions import Action, key_of
from . import controls, motion
from .theme import ACCENT, TEXT_SECONDARY, SURFACE, ERROR, TEXT_PRIMARY
from .widgets import col, edit_preview, truncate


@dataclass(frozen=True)
class Dialog:
    title: str
    items: tuple[Action, ...]
    selected: int = 0
    query: str = ""
    searchable: bool = True
    palette: bool = False
    query_cursor: int = 0
    query_focus: bool = False


stack: Signal = Signal([], name="dialog_stack")
page: Signal = Signal(8, name="dialog_page")


def active() -> bool:
    return bool(stack.peek())


def clear() -> None:
    stack.set([])


def close() -> None:
    stack.set(stack.peek()[:-1])


def _set(**changes) -> None:
    layers = stack.peek()
    if layers:
        stack.set([*layers[:-1], replace(layers[-1], **changes)])


def open_select(title: str, items: list[Action], *, selected: int = 0,
                searchable: bool = True, palette: bool = False) -> None:
    motion.forget("dialog")
    selected = max(0, min(len(items) - 1, selected))
    if items and not items[selected].enabled:
        selected = next((i for i, item in enumerate(items) if item.enabled), selected)
    stack.set([*stack.peek(), Dialog(title, tuple(items), selected,
                                    searchable=searchable, palette=palette)])


def _score(item: Action, query: str) -> int | None:
    label = item.label.casefold()
    body = f"{label} {item.description} {item.category}".casefold()
    terms = query.casefold().split()
    if all(term in body for term in terms):
        return 0 if all(term in label for term in terms) else 1
    # Also accept an abbreviation/subsequence, as a small fuzzy-search fallback.
    cursor = 0
    for char in "".join(terms):
        found = label.find(char, cursor)
        if found < 0:
            return None
        cursor = found + 1
    return 2


def filtered(dialog: Dialog | None = None) -> list[Action]:
    dialog = dialog or stack.peek()[-1]
    if not dialog.query.strip():
        return list(dialog.items)
    scored = [(_score(item, dialog.query), i, item)
              for i, item in enumerate(dialog.items)]
    return [item for _, _, item in sorted(
        (row for row in scored if row[0] is not None), key=lambda row: (row[0], row[1])
    )]


def set_query(query: str) -> None:
    _set(query=query[:160], query_cursor=min(160, len(query)), query_focus=True, selected=0)
    items = filtered()
    _set(selected=next((i for i, item in enumerate(items) if item.enabled), 0))


def move(delta: int) -> None:
    dialog = stack.peek()[-1]
    items = filtered(dialog)
    if not items:
        return
    current = min(dialog.selected, len(items) - 1)
    direction = 1 if delta > 0 else -1
    candidate = ((current + delta) % len(items) if abs(delta) == 1 else
                 max(0, min(len(items) - 1, current + delta)))
    for _ in items:
        if items[candidate].enabled:
            _set(selected=candidate)
            return
        candidate = (candidate + direction) % len(items)


def submit(index: int | None = None) -> None:
    if not active():
        return
    dialog = stack.peek()[-1]
    items = filtered(dialog)
    index = dialog.selected if index is None else index
    if not 0 <= index < len(items) or not items[index].enabled:
        return
    action = items[index]
    # Close before running, so a callback can open a new dialog. The same key
    # remains consumed by the root dispatcher even after the screen changes.
    if dialog.palette:
        clear()
    else:
        close()
    action.run()


def handle_key(event) -> bool:
    if not active():
        return False
    event.stop_propagation()
    if hasattr(event, "prevent_default"):
        event.prevent_default()
    key = key_of(event)
    ctrl = bool(getattr(event, "ctrl", False))
    if key in controls.ESCAPE or (ctrl and key == "c"):
        close()
    elif key in ("f1", "menu"):
        close()
    elif key in ("up", "down") or (ctrl and key in ("n", "p")):
        _set(query_focus=False)
        move(-1 if key in ("up", "p") else 1)
    elif controls.is_tab(event):
        _set(query_focus=False)
        move(controls.tab_delta(event))
    elif key in ("pageup", "pagedown"):
        _set(query_focus=False)
        move(-page.peek() if key == "pageup" else page.peek())
    elif key in ("home", "end") and not stack.peek()[-1].query_focus:
        items = filtered()
        enabled = [i for i, item in enumerate(items) if item.enabled]
        if enabled:
            _set(selected=enabled[0] if key == "home" else enabled[-1])
    elif key in ("enter", "return"):
        submit()
    elif stack.peek()[-1].searchable:
        dialog = stack.peek()[-1]
        query, cursor = dialog.query, min(dialog.query_cursor, len(dialog.query))
        if key in ("left", "right", "home", "end"):
            _set(query_focus=True, query_cursor={"left": max(0, cursor - 1), "right": min(len(query), cursor + 1),
                                                "home": 0, "end": len(query)}[key])
            return True
        if key == "backspace":
            if cursor:
                set_query(query[:cursor - 1] + query[cursor:])
                _set(query_cursor=cursor - 1)
        elif key == "delete":
            set_query(query[:cursor] + query[cursor + 1:])
            _set(query_cursor=cursor)
        elif ctrl and key in ("a", "u"):
            set_query("")
        elif not (ctrl or getattr(event, "alt", False) or getattr(event, "meta", False)):
            raw = getattr(event, "sequence", "") or key
            raw = " " if raw == "space" else raw
            if len(raw) == 1 and raw.isprintable():
                set_query(query[:cursor] + raw + query[cursor:])
                _set(query_cursor=min(160, cursor + 1))
    return True


def handle_paste(event) -> bool:
    if not active():
        return False
    event.stop_propagation()
    if stack.peek()[-1].searchable:
        text = getattr(event, "text", "")
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        dialog = stack.peek()[-1]
        value = " ".join(str(text).splitlines())
        set_query(dialog.query[:dialog.query_cursor] + value + dialog.query[dialog.query_cursor:])
        _set(query_cursor=min(160, dialog.query_cursor + len(value)))
    return True


def _scroll(event) -> None:
    event.stop_propagation()
    direction = getattr(event, "scroll_direction", "")
    if active() and direction in ("up", "down"):
        _set(query_focus=False)
        delta = max(1, abs(getattr(event, "scroll_delta", 1))) * 3
        move(delta if direction == "down" else -delta)


@component
def DialogLayer() -> Box:
    width, height = use_terminal_dimensions()
    layers = stack()
    if not layers:
        return Box(position="absolute", width=0, height=0)
    dialog = layers[-1]
    items = filtered(dialog)
    selected = min(dialog.selected, max(0, len(items) - 1))
    dialog_width = max(16, min(68, width - 4))
    inner = max(8, dialog_width - 4)
    fixed = 6 if dialog.searchable else 5
    room = max(1, min(10, height - 4 - fixed, max(1, len(items))))
    if page.peek() != room:
        page.set(room)
    token = (dialog.title, id(dialog.items), dialog.query, width, height)
    _, indices = motion.window("dialog", len(items), room, selected, token=token)
    rows = []
    for index in indices:
        item = items[index]
        highlighted = index == selected
        marker = "›" if highlighted else "" if item.enabled else "×"
        color = TEXT_SECONDARY if not item.enabled else ERROR if item.danger else TEXT_PRIMARY
        rows.append(motion.paint(Row(
            col(marker, 2, fg=ACCENT if item.enabled else TEXT_SECONDARY),
            col(truncate(item.label, inner - 2), inner - 2,
                fg=color, bold=highlighted and item.enabled),
            height=1, flex_shrink=0,
            on_mouse_down=click_handler(lambda *_, at=index: submit(at)),
        ), "dialog", selected, index, token=token,
                                        surface=SURFACE, animate=False))
    if not rows:
        rows = [Text("Ничего не найдено", fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
    content = [
        Row(col(truncate(dialog.title, inner - 4), inner - 4, fg=TEXT_PRIMARY, bold=True),
            col("Esc", 4, fg=TEXT_SECONDARY, on_mouse_down=click_handler(close))),
        Text("─" * inner, fg=TEXT_SECONDARY, height=1, flex_shrink=0, wrap_mode="none"),
    ]
    if dialog.searchable:
        query_view = (edit_preview(dialog.query, dialog.query_cursor, inner - 2) if dialog.query_focus else
                      truncate(dialog.query, inner - 2))
        content += [Text("/ " + (query_view or "Поиск…"),
                         fg=TEXT_PRIMARY if dialog.query else TEXT_SECONDARY, height=1, wrap_mode="none"),
                    ]
    content += [Column(*rows, height=room, flex_shrink=0),
                Row(col("↑↓ Tab · Enter выбрать", inner - 6, fg=TEXT_SECONDARY),
                    col(f"{selected + 1 if items else 0}/{len(items)}", 6, fg=TEXT_SECONDARY))]
    modal_height = room + fixed
    def inside(event):
        event.stop_propagation()
    return Box(
        Box(Column(*content), width=dialog_width, height=modal_height,
            position="absolute", left=max(0, (width - dialog_width) // 2),
            top=max(1, (height - modal_height) // 3), padding_x=1,
            border=True, border_style="single", border_color=ACCENT,
            background_color=SURFACE, on_mouse_down=inside, on_mouse_scroll=_scroll),
        position="absolute", top=0, left=0, width=width, height=height,
        z_index=3000, on_mouse_down=click_handler(close), on_mouse_scroll=inside,
    )
