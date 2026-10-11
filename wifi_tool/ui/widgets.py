"""Small reusable presentational components.

Layout notes learned from opentui 0.1.2 and encoded here so screens stay
readable:

* ``Text`` content is **rstripped**, so ``"label".ljust(n)`` does not pad.
  Aligned columns must use fixed-width boxes (``col()``) instead.
* Spacing and separators use fixed-width boxes rather than text padding.
"""
from __future__ import annotations

from opentui import Box, Column, Row, Text, click_handler
from opentui.structs import display_width

from .theme import ACCENT, OUTLINE, TEXT_SECONDARY, FOCUS_SURFACE, MAX_WORKSPACE_WIDTH, TEXT_PRIMARY
from . import motion


def col(text, width: int, *, fg: str = TEXT_SECONDARY, bold: bool = False, **kwargs) -> Box:
    """A fixed-width text column -- the building block of aligned rows.

    ``flex_shrink=0`` is mandatory on the inner Text: without it a long value is
    allowed to shrink to zero inside a Row, and the leftover glyphs get painted
    over the neighbouring column instead of being clipped.
    """
    return Box(
        Text(str(text), fg=fg, bold=bold, flex_shrink=0, wrap_mode="none"),
        fixed_width=width,
        flex_shrink=0,
        **kwargs,
    )


def truncate(text: str, width: int) -> str:
    """Cut ``text`` to ``width`` display columns, marking the cut with ``…``.

    A banner line that is allowed to wrap costs an extra terminal row, which on a
    short screen is the difference between the key-hint bar being visible and
    being pushed off the bottom. Headline text is truncated instead.
    """
    width = max(0, width)
    if not width:
        return ""
    if display_width(text) <= width:
        return text
    out = ""
    for ch in text:
        if display_width(out + ch) > width - 1:
            break
        out += ch
    return out.rstrip() + "…"


def truncate_middle(text: str, width: int) -> str:
    """Keep both ends of a filename so long shared prefixes remain distinct."""
    width = max(0, width)
    if not width:
        return ""
    if display_width(text) <= width:
        return text
    head_room = (width - 1) // 2
    tail_room = width - 1 - head_room
    head = ""
    for character in text:
        if display_width(head + character) > head_room:
            break
        head += character
    tail = ""
    for character in reversed(text):
        if display_width(character + tail) > tail_room:
            break
        tail = character + tail
    return head + "…" + tail


def wrap(text: str, width: int) -> list[str]:
    """Wrap by terminal cells, including long filenames and CJK names."""
    width = max(1, width)
    lines: list[str] = []
    for paragraph in text.splitlines():
        if not paragraph.strip():
            lines.append("")
            continue
        current = ""
        for word in paragraph.split(" "):
            candidate = f"{current} {word}".strip() if current else word
            if display_width(candidate) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            while display_width(word) > width:
                cut = 0
                cells = 0
                for character in word:
                    size = display_width(character)
                    if cells + size > width:
                        break
                    cells += size
                    cut += 1
                # A double-cell glyph cannot fit a one-cell viewport.
                if not cut:
                    word = word[1:]
                    lines.append("…")
                else:
                    lines.append(word[:cut])
                    word = word[cut:]
            current = word
        if current:
            lines.append(current)
    return lines


def spinner_frame(tick: int) -> str:
    frames = ("|", "/", "-", "\\")
    return frames[tick % len(frames)]


# Every screen shares the same compact workspace chrome.
WORKSPACE_HEADER_HEIGHT = 3


def workspace_header(title: str, context: str = "", *, width: int) -> Box:
    from .. import build_stamp

    stamp = f"v{build_stamp()}" if width >= 70 else "WiFi Tool"
    inner = max(8, width - 4)
    return Box(
        Column(
            Row(col(truncate(title, max(4, inner - len(stamp) - 1)),
                    max(4, inner - len(stamp)), fg=TEXT_PRIMARY, bold=True),
                col(stamp, len(stamp), fg=ACCENT)),
            Text(truncate(context, inner), fg=TEXT_SECONDARY, height=1,
                 flex_shrink=0, wrap_mode="none"),
            Text("─" * inner, fg=OUTLINE, height=1, flex_shrink=0, wrap_mode="none"),
        ),
        height=WORKSPACE_HEADER_HEIGHT, padding_x=2, padding_top=0,
        flex_shrink=0, overflow="hidden",
    )


def workspace_section(title: str, *children, **kwargs) -> Box:
    rows = ([Text(title, fg=TEXT_SECONDARY, bold=True, height=1,
                  flex_shrink=0, wrap_mode="none")] if title else [])
    return Box(Column(*rows, *children), padding_x=2,
               overflow="hidden", **kwargs)


def workspace_action(label: str, run, *, width: int, key: str = "Enter",
                     enabled: bool = True, selected: bool = True,
                     danger: bool = False) -> Box:
    """An explicit, one-row primary action, anchored above the footer."""
    from .theme import ERROR

    color = TEXT_SECONDARY if not enabled else ERROR if danger else ACCENT
    content = truncate(f"{key}  {label}" if key else label, max(8, width - 4))
    return Box(
        Text(content, fg=color, bold=enabled, height=1, wrap_mode="none"),
        padding_x=2, height=1, flex_shrink=0,
        background_color=FOCUS_SURFACE if selected else None,
        on_mouse_down=click_handler(run) if enabled else None,
    )


def workspace(*children, width: int, height: int) -> Box:
    """Bound secondary workspace width without changing terminal coordinates."""
    return Box(Column(*children, width=min(width, MAX_WORKSPACE_WIDTH), height=height),
               width=width, height=height, align_items="center")


def _scroll_indicator(total: int, room: int, start: int, height: int):
    if total <= room or height < 1:
        return []
    thumb = max(1, round(height * room / total))
    at = round((height - thumb) * max(0, min(start, total - room)) / max(1, total - room))
    return [Box(Column(*[Text("│", fg=ACCENT if at <= i < at + thumb else OUTLINE,
                              bold=at <= i < at + thumb, height=1, flex_shrink=0,
                              wrap_mode="none") for i in range(height)]),
                position="absolute", right=0, top=1, width=1, height=height)]


def list_viewport(title: str, *children, height: int, focused: bool, on_focus=None, on_scroll=None,
                  scroll: tuple[int, int, int] | None = None,
                  border_style: str = "single") -> Box:
    indicator = _scroll_indicator(*scroll, height - 2) if scroll else []
    return Box(Column(*children), *indicator, border=True, border_style=border_style,
               border_color=ACCENT if focused else OUTLINE, title=f" {title} ",
               padding_x=1, height=height, flex_shrink=0, overflow="hidden",
               on_mouse_down=click_handler(on_focus) if on_focus else None,
               on_mouse_scroll=on_scroll)


def action_list(screen: str, actions, *, width: int, room: int | None = None,
                regions: tuple[str, ...] = (), default: str = "") -> Box:
    from . import controls

    choices = [*regions, *(controls.action_id(action) for action in actions)]
    current = controls.focused(screen, choices, default=default)
    selected = next((i for i, action in enumerate(actions)
                     if controls.action_id(action) == current), 0)
    room = max(1, min(len(actions), room or len(actions)))
    token = (width, tuple(controls.action_id(action) for action in actions))
    _, indices = motion.window("actions:" + screen, len(actions), room, selected, token=token)
    active = current not in regions
    rows = []
    for index in indices:
        action = actions[index]
        focused = active and index == selected
        color = TEXT_SECONDARY if not action.enabled else ACCENT if focused else TEXT_PRIMARY
        rows.append(motion.paint(Row(
            col("›" if focused else "×" if not action.enabled else "", 2, fg=color),
            col(truncate(("× " if focused and not action.enabled else "") + action.label, max(8, width - 6)), max(8, width - 6),
                fg=color, bold=focused),
            height=1, flex_shrink=0,
            on_mouse_down=click_handler(lambda *_, item=action: controls.activate(screen, item)),
        ), "actions:" + screen, selected if active else None,
                                        index, token=token))
    return workspace_section("", Column(*rows), height=len(rows), flex_shrink=0)


def workspace_footer(*, width: int, hint: str = "Esc/← назад") -> Box:
    inner = max(8, width - 4)
    return Box(
        Text(truncate(hint, inner), fg=TEXT_SECONDARY, height=1, wrap_mode="none"),
        padding_x=2, height=1, flex_shrink=0,
    )


def workspace_log(lines: list[str], width: int, height: int, offset: int,
                  *, focused: bool = False, on_focus=None,
                  border_style: str = "single") -> Box:
    room = max(1, height - 2)
    end = len(lines) - min(max(0, offset), max(0, len(lines) - room))
    start = max(0, end - room)
    start, indices = motion.window("log", len(lines), room, None, target=start,
                                    token=(width, height, hash(tuple(lines))))
    end = min(len(lines), start + room)
    title = "Журнал"
    if lines:
        title += f"  {start + 1}–{end}/{len(lines)}"
    title += " · пауза, End ↓" if offset else " · слежение"
    visible = [Text(truncate(line, max(8, width - 4)),
                    fg=TEXT_PRIMARY if focused else TEXT_SECONDARY,
                    height=1, flex_shrink=0, wrap_mode="none")
               for line in (lines[index] for index in indices)]
    if not visible:
        visible = [Text("Пока пусто", fg=TEXT_SECONDARY, height=1, wrap_mode="none")]
    return Box(Column(*visible), *_scroll_indicator(len(lines), room, start, height - 2),
               border=True, border_style=border_style,
               border_color=ACCENT if focused else OUTLINE,
               title=f" {truncate(title, width - 8)} ", padding_x=1,
               height=height, flex_shrink=0, overflow="hidden",
               on_mouse_down=click_handler(on_focus) if on_focus else None)


def text_line(text: str, width: int, *, color: str = TEXT_SECONDARY, bold: bool = False) -> Text:
    return Text(truncate(text, width), fg=color, bold=bold, height=1,
                flex_shrink=0, wrap_mode="none")


def edit_preview(value: str, cursor: int, width: int) -> str:
    """Scroll an editable value by cells so the insertion cursor stays visible."""
    cursor = max(0, min(cursor, len(value)))
    start = cursor
    while start and display_width(value[start - 1:cursor]) <= max(0, width - 3):
        start -= 1
    # Consolas lacks U+258F; an ASCII cursor works in the Windows console too.
    return truncate(("…" if start else "") + value[start:cursor] + "|" + value[cursor:], width)


def secret_lines(lines: list[str], secret: str, revealed: bool) -> list[str]:
    """Result logs can repeat the recovered value; hide those occurrences too."""
    if not secret or revealed:
        return lines
    return [line.replace(secret, "[скрыто]") for line in lines]
