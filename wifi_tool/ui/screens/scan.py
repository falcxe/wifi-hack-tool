"""Network inventory with searchable columns and persistent keyboard focus."""
from __future__ import annotations

from opentui import Box, Column, Row, click_handler, component
from opentui.hooks import use_keyboard, use_paste, use_terminal_dimensions

from .. import controls, dialogs, motion, state
from ..actions import Action, group_actions, key_of
from ..controller import go_to_setup, open_audit, quit_app, request_rescan
from ..theme import (ACCENT, OUTLINE, TEXT_SECONDARY, MAX_WORKSPACE_WIDTH,
                     ERROR, TEXT_PRIMARY, SUCCESS, WARNING, auth_color, signal_bar)
from ..widgets import (col, edit_preview, list_viewport, text_line,
                       truncate, workspace, workspace_footer, workspace_header,
                       workspace_section, wrap)


def filtered_networks() -> list[tuple[int, object]]:
    terms = state.scan_query.peek().casefold().split()
    return [(i, net) for i, net in enumerate(state.networks.peek())
            if all(term in f"{net.label} {net.bssid} {net.auth} {net.protection} {net.channel}".casefold()
                   for term in terms)]


def ensure_selection() -> None:
    items = filtered_networks()
    if state.selected.peek() not in [i for i, _ in items]:
        state.selected.set(next((i for i, net in items if state.network_identity(net) == state.scan_anchor.peek()),
                                items[0][0] if items else -1))


def set_query(query: str) -> None:
    current = state.selected_network()
    if current:
        state.scan_anchor.set(state.network_identity(current))
    state.scan_query.set(query.replace("\r", "").replace("\n", "")[:160])
    state.scan_query_cursor.set(len(state.scan_query.peek()))
    state.network_scroll_offset.set(0)
    ensure_selection()


def focus_search() -> None:
    controls.set_focus("scan", "search")
    state.scan_query_cursor.set(len(state.scan_query.peek()))


def _choices() -> list[str]:
    return ["list", "search"]


def _paste(event) -> None:
    if state.phase.peek() != "scan" or controls.peek_focus("scan", _choices(), default="list") != "search":
        return
    query, cursor = state.scan_query.peek(), state.scan_query_cursor.peek()
    value = getattr(event, "text", "")
    value = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    value = value.replace("\r", "").replace("\n", "")
    set_query(query[:cursor] + value + query[cursor:])
    state.scan_query_cursor.set(min(160, cursor + len(value)))
    event.stop_propagation()


def _widths(term_width: int) -> dict[str, int]:
    available = max(20, term_width - 4)
    widths = {"mark": 2, "signal": 11, "ssid": 16, "bssid": 0,
              "enc": 0, "auth": 9, "clients": 6}
    if available >= 70:
        widths.update(bssid=18, enc=8)
    if available >= 94:
        widths["auth"] = 20
    widths["ssid"] = max(8, min(32, available - sum(v for k, v in widths.items() if k != "ssid")))
    return widths


def _stations(net):
    """What the saved captures said about the devices behind this network."""
    key = (net.bssid or "").replace(":", "").lower()
    return state.station_counts.peek().get(key)


def _clients_cell(net) -> str:
    """The device count, and a mark when the hash is already in hand.

    A number alone answers "how many were there when we last looked", which is
    the useful half; the mark answers the half that actually decides what to
    attack -- a network whose handshake is already on disk needs no capture at
    all.
    """
    info = _stations(net)
    if info is None:
        return "—"
    mark = "✓" if info.has_hash else "·"
    return f"{mark}{info.devices}"


def _clients_color(net) -> str:
    info = _stations(net)
    if info is None:
        return TEXT_SECONDARY
    return SUCCESS if info.has_hash else (WARNING if not info.devices else TEXT_PRIMARY)


def _window_start(total: int, selected: int, visible_rows: int, current: int) -> int:
    room = max(1, visible_rows)
    start = max(0, min(current, max(0, total - room)))
    if selected < start:
        start = selected
    elif selected >= start + room:
        start = selected - room + 1
    return max(0, min(start, max(0, total - room)))


def min_list_rows(height: int) -> int:
    return max(1, min(4, height - 14))


def _select_and_scroll(index: int, visible_rows: int) -> None:
    items = filtered_networks()
    if not items:
        return
    position = max(0, min(len(items) - 1, index))
    state.selected.set(items[position][0])
    state.scan_notice.set("")
    state.network_scroll_offset.set(_window_start(len(items), position, visible_rows,
                                                state.network_scroll_offset.peek()))


def scan_actions() -> list[Action]:
    from ..commands import saved_action

    return group_actions([
        Action("Отчёт", open_audit, primary=True, enabled=state.selected_network() is not None, category="Основное"),
        Action("Обновить", request_rescan, enabled=not state.scanning.peek(), category="Основное"),
        Action("Поиск сетей", focus_search, category="Список и поиск"),
        Action("Сбросить поиск", lambda: set_query(""), enabled=bool(state.scan_query.peek()), category="Список и поиск"),
        Action("Параметры", go_to_setup, category="Настройки"),
        Action("Подробности ошибки", _show_error, enabled=bool(state.scan_error.peek()), category="Сведения"),
        *saved_action(),
        Action("Выход", quit_app, danger=True, category="Приложение"),
    ])


def _show_error() -> None:
    from .. import controller
    width = min(64, getattr(controller._renderer, "width", 68) - 8)
    dialogs.open_select("Ошибка сканирования", [Action(line, lambda: None)
                        for line in wrap(state.scan_error.peek(), width)], searchable=False)


def _on_key(event, visible_rows: int = 1) -> None:
    if state.phase.peek() != "scan":
        return
    event.stop_propagation()
    key = key_of(event)
    focus = controls.peek_focus("scan", _choices(), default="list")
    if key in controls.ESCAPE:
        if focus == "search":
            controls.set_focus("scan", "list")
        else:
            from ..commands import open_menu
            open_menu()
        return
    if controls.handle_action_key(event, "scan", [], regions=("list", "search"), default="list"):
        return
    if focus == "search" and key in ("up", "down", "pageup", "pagedown"):
        controls.set_focus("scan", "list")
        focus = "list"
    if focus == "search":
        query, cursor = state.scan_query.peek(), state.scan_query_cursor.peek()
        if key in ("enter", "return"):
            controls.set_focus("scan", "list")
        elif key in ("left", "right", "home", "end"):
            state.scan_query_cursor.set({"left": max(0, cursor - 1), "right": min(len(query), cursor + 1),
                                         "home": 0, "end": len(query)}[key])
        elif key in ("backspace", "delete"):
            if key == "backspace" and cursor:
                set_query(query[:cursor - 1] + query[cursor:])
                state.scan_query_cursor.set(cursor - 1)
            elif key == "delete":
                set_query(query[:cursor] + query[cursor + 1:])
                state.scan_query_cursor.set(cursor)
        elif not any(getattr(event, flag, False) for flag in ("ctrl", "alt", "meta")):
            raw = getattr(event, "sequence", "") or getattr(event, "key", "")
            raw = " " if raw == "space" else raw
            if len(raw) == 1 and raw.isprintable():
                set_query(query[:cursor] + raw + query[cursor:])
                state.scan_query_cursor.set(min(160, cursor + 1))
        return
    if focus != "list":
        return
    items = filtered_networks()
    position = next((j for j, (i, _) in enumerate(items) if i == state.selected.peek()), 0)
    delta = {"up": -1, "down": 1, "pageup": -visible_rows, "pagedown": visible_rows}.get(key)
    if delta is not None:
        _select_and_scroll(position + delta * getattr(event, "repeat_count", 1), visible_rows)
    elif key in ("home", "end"):
        _select_and_scroll(0 if key == "home" else len(items) - 1, visible_rows)
    elif key in ("enter", "return"):
        open_audit()


_visible_rows = 1


def _screen_key(event) -> None:
    _on_key(event, _visible_rows)


def _screen_scroll(event) -> None:
    if state.phase.peek() != "scan" or dialogs.active():
        return
    event.stop_propagation()
    direction = getattr(event, "scroll_direction", "")
    if direction not in ("up", "down"):
        return
    controls.set_focus("scan", "list")
    items = filtered_networks()
    if not items:
        return
    room = max(1, _visible_rows)
    position = next((j for j, (i, _) in enumerate(items) if i == state.selected.peek()), 0)
    start = _window_start(len(items), position, room, state.network_scroll_offset.peek())
    delta = max(1, abs(getattr(event, "scroll_delta", 1))) * 3
    start = max(0, min(max(0, len(items) - room), start + (delta if direction == "down" else -delta)))
    # Keep the selected network inside the scrolled viewport so the next arrow
    # or Enter acts on a visible row instead of snapping back to the old page.
    position = max(start, min(position, start + room - 1, len(items) - 1))
    state.selected.set(items[position][0])
    state.scan_notice.set("")
    state.network_scroll_offset.set(start)


def _security(net) -> str:
    auth = net.auth.lower()
    if net.is_open:
        return "Открытая"
    if "enterprise" in auth:
        return "Enterprise"
    return "WPA3" if "wpa3" in auth else "WPA2" if "wpa2" in auth else "WEP" if net.is_wep else "WPA"


def _details(net, width: int, height: int, notice: str = "") -> Box:
    inner = width - 4
    if net is None:
        rows = [text_line("Сеть не выбрана", inner)]
    else:
        verdict = "открытая сеть" if net.is_open else "устаревший алгоритм" if net.is_wep or "tkip" in net.haystack else (
            "объявлен WPA3" if "wpa3" in net.auth.lower() else "объявлен WPA2" if "wpa2" in net.auth.lower() else "данных мало")
        rows = [text_line(net.label, inner, color=TEXT_PRIMARY, bold=True), text_line(verdict, inner, color=auth_color(net.auth))]
        if height >= 5:
            rows += [text_line(net.bssid or "BSSID неизвестен", inner),
                     text_line(f"{net.auth or '—'} · {net.protection or '—'}", inner),
                     text_line(f"Канал {net.channel or '—'} · сигнал {net.signal}%", inner)]
        if height >= 8:
            rows += [text_line(net.radio or "Тип радио не объявлен", inner),
                     text_line("Enter: сведения и доступные действия", inner)]
    if notice:
        rows = rows[:max(0, height - 2)] + [text_line(notice, inner, color=WARNING)]
    return workspace_section("О выбранной сети", *rows[:height - 1], width=width, height=height, flex_shrink=0)


@component
def ScanScreen() -> Box:
    terminal_width, height = use_terminal_dimensions()
    width = min(terminal_width, MAX_WORKSPACE_WIDTH)
    nets = state.networks()
    state.selected()
    state.network_scroll_offset()
    query, notice = state.scan_query(), state.scan_notice()
    scanning, error = state.scanning(), state.scan_error()
    use_keyboard(_screen_key)
    use_paste(_paste)
    items = filtered_networks()
    focus = controls.focused("scan", _choices(), default="list")
    wide = width >= 120
    body_height = height - 5
    framed_detail = height >= 24
    detail_height = 0 if wide else 3 if not framed_detail else 8
    list_width = width - 40 if wide else width
    list_height = body_height - detail_height
    room = max(1, list_height - 3)
    if items:
        list_height = min(list_height, len(items) + 3)
        room = max(1, list_height - 3)
    body_height = (max(8, list_height) if wide else list_height + detail_height)
    global _visible_rows
    _visible_rows = room
    controls.list_page("scan", room)
    selected_pos = next((j for j, (i, _) in enumerate(items) if i == state.selected.peek()), 0)
    start = _window_start(len(items), selected_pos, room, state.network_scroll_offset.peek())
    token = (width, height, id(nets), query)
    start, indices = motion.window("scan", len(items), room, selected_pos, token=token, target=start)
    widths = _widths(list_width)
    headings = [col("", 2), col("Сеть / SSID", widths["ssid"]),
                col("Сигнал", widths["signal"])]
    if widths["bssid"]:
        headings.append(col("BSSID", widths["bssid"]))
    if widths["enc"]:
        headings.append(col("Шифр", widths["enc"]))
    headings.append(col("Защита", widths["auth"]))
    headings.append(col("Устр.", widths["clients"]))
    rows = [Row(*headings, height=1, flex_shrink=0)]
    for position in indices:
        index, net = items[position]
        selected = index == state.selected.peek()
        def choose(*_, i=index):
            controls.set_focus("scan", "list")
            state.selected.set(i)
        meter, meter_color = signal_bar(net.signal)
        cells = [col("›" if selected and focus == "list" else "•" if selected else "", 2, fg=ACCENT),
                 col(truncate(net.label, widths["ssid"] - 1), widths["ssid"], fg=TEXT_PRIMARY, bold=selected),
                  col(f"{meter} {net.signal}%", widths["signal"], fg=meter_color)]
        if widths["bssid"]:
            cells.append(col(net.bssid, widths["bssid"]))
        if widths["enc"]:
            cells.append(col(net.protection or "—", widths["enc"]))
        cells.append(col(truncate(net.auth if widths["auth"] >= 20 else _security(net), widths["auth"] - 1),
                         widths["auth"], fg=auth_color(net.auth)))
        cells.append(col(_clients_cell(net), widths["clients"],
                         fg=_clients_color(net)))
        rows.append(motion.paint(Row(*cells, height=1, flex_shrink=0,
                        on_mouse_down=click_handler(choose)), "scan", selected_pos, position, token=token,
                                                    focused=focus == "list", zebra=True))
    if not items:
        if error:
            rows = [text_line("[!] Сканирование недоступно", list_width - 4, color=ERROR, bold=True)]
            rows += [text_line(line, list_width - 4, color=WARNING) for line in wrap(error, list_width - 4)[:max(1, room - 1)]]
        elif scanning:
            rows = [text_line("Сканирую эфир…", list_width - 4, color=ACCENT), text_line("Список появится после поиска", list_width - 4)]
        else:
            rows = [text_line("Нет совпадений" if query else "Сети не найдены", list_width - 4, color=WARNING),
                    text_line("Измените поиск или сбросьте его" if query else "F1 → Обновить: повторить поиск", list_width - 4)]
    list_title = f"Сети ({len(items)})" + (f" из {len(nets)}" if query else "")
    if len(items) > room:
        list_title += f" · {start + 1}–{min(start + room, len(items))}"
    listing = list_viewport(list_title, *rows,
                            height=list_height, focused=focus == "list", scroll=(len(items), room, start),
                            border_style="rounded",
                            on_focus=lambda: controls.set_focus("scan", "list"),
                            on_scroll=_screen_scroll)
    detail = _details(state.selected_network(), 38 if wide else width - 2 if framed_detail else width,
                      body_height - 2 if wide else detail_height - 2 if framed_detail else detail_height,
                      notice or (error if items else ""))
    if wide or framed_detail:
        detail = Box(detail, width=40 if wide else width,
                     height=body_height if wide else detail_height,
                     border=True, border_style="rounded", border_color=OUTLINE,
                     flex_shrink=0, overflow="hidden")
    body = Row(Box(listing, width=list_width, height=body_height), detail, height=body_height, flex_shrink=0) if wide else (
        Column(listing, detail, height=body_height, flex_shrink=0))
    adapter = state.adapter()
    context = "Обновление…" if scanning else "Поиск завершён" if nets else "Ожидание сетей"
    if adapter:
        context += " · " + adapter.description
    value = edit_preview(query, state.scan_query_cursor(), width - 14) if focus == "search" else query or "SSID, BSSID, защита…"
    search = Row(col("/ Поиск", 10, fg=ACCENT if focus == "search" else TEXT_SECONDARY), col(value, width - 14, fg=TEXT_PRIMARY if query or focus == "search" else TEXT_SECONDARY),
                 height=1, flex_shrink=0, padding_x=2, on_mouse_down=click_handler(focus_search))
    hint = "↑↓ список · Esc · ←→ · Tab" if focus == "search" else "Enter отчёт · ↑↓/колесо · Tab · / поиск"
    if focus == "list" and width >= 80:
        hint += " · PgUp/PgDn · Home/End"
    return workspace(workspace_header("Сети", context, width=width), search, body,
                     Box(flex_grow=1), workspace_footer(width=width, hint=hint), width=terminal_width, height=height)
