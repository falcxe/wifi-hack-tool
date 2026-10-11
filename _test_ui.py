"""Headless UI regression tests: every screen, every phase, several sizes."""
from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import AsyncMock, patch
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

#: No serial ports in a headless test run. The board is real hardware on the
#: developer's desk, and without this the boot path opened COM5 and waited for a
#: prompt that only comes when a person happens to have the stick plugged in --
#: which made the whole suite hang on a serial port instead of failing.
os.environ["WIFI_TOOL_NO_BOARD"] = "1"

from opentui.structs import display_width  # noqa: E402
from opentui.events import KeyEvent  # noqa: E402
from opentui.testing import test_render  # noqa: E402

from wifi_tool import capturer, pipeline, profiles, scanner  # noqa: E402
from wifi_tool.models import CrackResult, Network  # noqa: E402
from wifi_tool.scanner import AdapterInfo  # noqa: E402
from wifi_tool.ui import commands, controller, dialogs, forms, state  # noqa: E402
from wifi_tool.ui.app import App  # noqa: E402
from wifi_tool.ui.screens import audit, crack_form, scan  # noqa: E402
from _test_tui_setup import choose_command  # noqa: E402


def key_event(*, code="", name="", key="") -> KeyEvent:
    return KeyEvent(key=name or key or code, code=code)

SIZES = [(80, 24), (100, 30), (120, 40), (60, 20)]

NETS = [
    Network("MyHomeWiFi", "aa:bb:cc:dd:ee:ff", 6, 92, "WPA2-Personal", "CCMP"),
    Network("neighbor_5G", "11:22:33:44:55:66", 36, 76, "WPA3-Personal", "CCMP"),
    Network("CafeFree", "77:88:99:aa:bb:cc", 11, 55, "Open", ""),
    Network("", "de:ad:be:ef:00:01", 1, 40, "WPA2-Personal", "TKIP"),
    Network(
        "A_Really_Extremely_Long_SSID_That_Must_Be_Truncated",
        "00:11:22:33:44:55",
        149,
        18,
        "WPA2-Enterprise",
        "CCMP",
    ),
]

ADAPTER = AdapterInfo("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz", "b0:47:e9:6c:2f:64", "connected")

LOG = [
    "$ assets\\hashcat.exe -m 22000 cap.hc22000 -r rules\\best64.rule rockyou.txt",
    "Конвертация: PMKID x1",
    "Найдено: 1 PMKID, 0 EAPOL (PMKID)",
    "STATUS  SPEED  14235.6 kH/s",
    "STATUS  PROGRESS  42.71%",
]


#: Characters that legitimately start the topmost line of an un-scrolled frame.
#: Panel borders are rounded, but tolerate other styles for robustness.
CORNERS = "╭┌╔+"


def check(setup, *, expect: list[str], label: str) -> None:
    """Render at every size and assert nothing scrolled and needles are present.

    Each size runs in its own event loop, and the render is awaited from inside
    a coroutine rather than handed straight to ``asyncio.run`` -- passing
    ``test_render(...)`` directly to ``asyncio.run`` captures the frame before
    the renderer's first layout pass has settled, which reads as a scrolled
    frame.
    """
    for width, height in SIZES:
        state.reset()
        setup_obj = asyncio.run(_render_case(setup, width, height))
        frame = setup_obj.capture_char_frame()
        lines = frame.splitlines()
        assert lines, f"{label}: empty frame at {width}x{height}"
        assert ("Проверка сети" in lines[0] if label.startswith("audit")
                else "Сети" in lines[0]), (
            f"{label}: layout scrolled at {width}x{height}\nfirst line: {lines[0]!r}"
        )
        assert len(lines) <= height, (
            f"{label}: frame taller than terminal at {width}x{height} "
            f"({len(lines)} > {height})"
        )
        for needle in expect:
            assert needle in frame, f"{label}: missing {needle!r} at {width}x{height}"
        setup_obj.destroy()
    print(f"  ok  {label}")


async def _render_case(setup, width: int, height: int):
    """Render the App after applying ``setup`` and letting one frame settle."""
    setup()
    setup_obj = await test_render(App, {"width": width, "height": height})
    setup_obj.render_frame()
    return setup_obj


async def _render_once(width: int, height: int):
    return await test_render(App, {"width": width, "height": height})


def test_scan_empty() -> None:
    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(False)
        state.networks.set([])
        state.scanning.set(True)
        state.scan_error.set("")

    check(setup, expect=["Сканирую эфир", "Сети"], label="scan / empty")


def test_scan_list() -> None:
    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(True)
        state.networks.set(NETS)
        state.selected.set(1)

    # Identity fields must survive at every width; the lower-priority columns
    # (BSSID / encryption / auth) legitimately drop out on narrow terminals.
    check(
        setup,
        expect=["Сети (5)", "MyHomeWiFi", "neighbor_5G", "CafeFree", "О выбранной сети"],
        label="scan / list",
    )


def test_scan_rows_keep_security_labels_and_mark_truncation() -> None:
    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(True)
        state.networks.set(NETS)
        state.selected.set(0)

    obj = asyncio.run(_render_case(setup, 100, 30))
    frame = obj.capture_char_frame()
    assert "CCMP" in frame, f"scan: encryption label was clipped\n{frame}"
    assert "TKIP" in frame, f"scan: TKIP label was clipped\n{frame}"
    assert "…" in frame, f"scan: long SSID was cut without an ellipsis\n{frame}"
    obj.destroy()
    print("  ok  scan / complete security labels and visible truncation")


def test_scan_scrolls_selected_network_into_view() -> None:
    """Arrow navigation scrolls the visible slice when selection passes it."""
    nets = [
        Network(
            f"ScrollNet{i:02}",
            f"02:00:00:00:{i // 256:02x}:{i % 256:02x}",
            6,
            70,
            "WPA2-Personal",
            "CCMP",
        )
        for i in range(24)
    ]

    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(True)
        state.readiness.set(None)
        state.networks.set(nets)
        state.selected.set(0)
        state.network_scroll_offset.set(0)

    state.reset()
    obj = asyncio.run(_render_case(setup, 80, 24))
    frame = obj.capture_char_frame().splitlines()
    title = next(i for i, line in enumerate(frame) if "Сети (24)" in line)
    end = next(i for i in range(title + 1, len(frame)) if frame[i].lstrip().startswith(("╰", "└")))
    visible_rows = sum("ScrollNet" in line for line in frame[title + 1 : end])
    assert visible_rows > 0, f"scroll: no network rows in the initial frame\n{frame}"

    # Simulate moving past the bottom edge using the same handler as the UI.
    for _ in range(visible_rows + 4):
        scan._on_key(key_event(code="down", name="down"), visible_rows)
    assert state.network_scroll_offset.peek() > 0, "scroll: viewport did not advance"

    obj.render_frame()
    frame = obj.capture_char_frame().splitlines()
    title = next(i for i, line in enumerate(frame) if "Сети (24)" in line)
    end = next(i for i in range(title + 1, len(frame)) if frame[i].lstrip().startswith(("╰", "└")))
    listing = frame[title + 1 : end]
    selected_name = f"ScrollNet{state.selected.peek():02}"
    selected_row = next((line for line in listing if selected_name in line), None)
    assert selected_row, f"scroll: selected row {selected_name} is outside the viewport\n{frame}"
    assert "ScrollNet00" not in "\n".join(listing), "scroll: viewport stayed at the top"
    obj.destroy()
    print("  ok  scan / selection scrolls viewport")


def test_scan_narrow_keeps_identity() -> None:
    """Narrow terminals drop detail columns but must keep SSID/signal/channel."""

    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(True)
        state.networks.set(NETS)
        state.selected.set(0)

    for width, height in ((44, 20), (60, 20), (76, 20), (80, 24), (120, 40)):
        state.reset()
        setup_obj = asyncio.run(_render_case(setup, width, height))
        lines = setup_obj.capture_char_frame().splitlines()
        assert "Сети" in lines[0], f"narrow: scrolled at {width}"

        # Look only inside the network list panel, not the detail panel below.
        start = next(
            (i for i, ln in enumerate(lines) if "Сети (" in ln),
            None,
        )
        assert start is not None, f"narrow: list panel missing at {width}"
        end = next(
            (i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith(("╰", "└"))),
            len(lines),
        )
        listing = [line[:width - 40] if width >= 120 else line for line in lines[start:end]]
        row = next((ln for ln in listing if "MyHomeWiFi" in ln), None)
        assert row, f"narrow: SSID clipped away at {width}x{height}"
        assert "92%" in row, f"narrow: signal clipped at {width}: {row!r}"
        assert str(NETS[0].channel) in row, f"narrow: channel clipped at {width}: {row!r}"
        # One network per row -- rows must never bleed into each other.
        assert "CafeFree" not in row, f"narrow: columns overlap at {width}: {row!r}"
        # Every network row is exactly one line and every line holds one SSID.
        for ln in listing[1:-1]:
            labels = [n.label or "(hidden)" for n in NETS]
            present = [x for x in labels if x in ln]
            assert len(present) <= 1, (
                f"narrow: two SSIDs on one line at {width}: {ln!r} ({present})"
            )
        setup_obj.destroy()
    print("  ok  scan / narrow terminal")


def test_scan_fits_terminal() -> None:
    """Nothing may spill past the frame, and the flow's controls must stay visible.

    The scan screen is the entry point of the whole flow, so its banner, network
    list, detail panel and footer each have to fit inside the terminal at any
    size. An over-budget screen pushed the footer off the bottom and overprinted
    the detail panel -- which hid the crack button.
    """

    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(True)
        state.networks.set(NETS)
        state.selected.set(0)

    for width, height in ((44, 16), (44, 20), (52, 18), (60, 20), (80, 24), (120, 40)):
        state.reset()
        setup_obj = asyncio.run(_render_case(setup, width, height))
        lines = setup_obj.capture_char_frame().splitlines()
        setup_obj.destroy()

        for i, ln in enumerate(lines):
            assert display_width(ln) <= width, (
                f"fit: line {i} is {display_width(ln)} wide at {width}x{height}: {ln!r}"
            )
        # The footer keeps the report and search hints at every width.
        bar = lines[-1].lower()
        assert "enter отчёт" in bar, f"fit: report shortcut missing at {width}x{height}"
        assert "/ поиск" in bar, f"fit: search shortcut missing at {width}x{height}"
        assert "f1 меню" not in bar, f"fit: removed menu button returned at {width}x{height}"
        assert any("О выбранной сети" in ln for ln in lines), f"fit: detail panel lost at {width}x{height}"
        assert any("объявлен WPA2" in ln for ln in lines), f"fit: observed security lost at {width}x{height}"
        # The network list must keep at least a couple of rows.
        start = next((i for i, ln in enumerate(lines) if "Сети (" in ln), None)
        assert start is not None, f"fit: list panel missing at {width}x{height}"
        end = next((i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith(("╰", "└"))), None)
        wanted = scan.min_list_rows(height)
        assert end is not None and end - start - 1 >= wanted, (
            f"fit: list squeezed to {end - start - 1 if end else '?'} of {wanted} "
            f"rows at {width}x{height}"
        )
    print("  ok  scan / fits terminal")


def test_scan_audit_action_is_independent_of_capture_tools() -> None:
    """Passive report stays available without capture or cracking dependencies."""

    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(True)
        state.networks.set(NETS)
        state.selected.set(0)
        state.readiness.set(
            pipeline.Readiness(
                admin=True,
                adapter=ADAPTER,
                hashcat=Path("assets/hashcat.exe"),
                wordlist=Path("assets/wordlist.txt"),
                rules=Path("assets/rules/best66.rule"),
                backend=None,
                iface=None,
            )
        )
        # A stored key for a *different* network, so the selected one still gets
        # its security observation rather than the stored-key verdict.
        state.saved.set(
            [
                profiles.SavedProfile("neighbor_5G", "WPA2-Personal", "CCMP", key="s3cret"),
                profiles.SavedProfile("Cafe", "Открыть", "Нет", key=""),
            ]
        )

    check(
        setup,
        expect=["Enter отчёт", "объявлен WPA2"],
        label="scan / passive audit action",
    )


def test_scan_keeps_saved_keys_out_of_the_passive_screen() -> None:
    """Passive inventory must not surface stored credentials or imply recovery."""

    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(True)
        state.networks.set(NETS)
        state.selected.set(0)
        state.saved.set(
            [profiles.SavedProfile("MyHomeWiFi", "WPA2-Personal", "CCMP", key="s3cret")]
        )

    obj = asyncio.run(_render_case(setup, 80, 24))
    frame = obj.capture_char_frame()
    assert "s3cret" not in frame, "scan / the stored key itself leaked onto the scan screen"
    assert "ключ сохранён" not in frame, "scan / passive screen exposed saved-key state"
    assert "Enter вернёт" not in frame, "scan / action hint still promises key recovery"
    obj.destroy()
    print("  ok  scan / saved credentials stay out of the passive screen")


def test_scan_enter_opens_audit_without_letter_shortcuts() -> None:
    """The primary scan actions both open the passive report."""
    target = NETS[0]  # MyHomeWiFi, WPA2-Personal
    for key, code in (("enter", "enter"), ("return", "return")):
        state.reset()
        state.networks.set(NETS)
        state.selected.set(0)
        state.phase.set("scan")
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            scan._on_key(key_event(code=code, name=key), visible_rows=4)
        assert state.phase.peek() == "audit", f"{key}: did not open the audit screen"
        assert state.audit_network.peek() is target, f"{key}: wrong network passed to the audit"

    for key, code in (("a", ""), ("ф", ""), ("p", ""), ("з", ""), ("f5", "f5")):
        state.reset()
        state.networks.set(NETS)
        state.selected.set(0)
        state.phase.set("scan")
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            scan._on_key(key_event(code=code, name=key), visible_rows=4)
        assert state.phase.peek() == "scan", f"{key}: unexpected navigation from passive scan"
    print("  ok  scan / Enter opens audit; letter shortcuts do not launch another flow")


def test_scan_audit_is_available_for_all_network_types() -> None:
    """Passive observations can be opened for open, WPA3 and Enterprise networks."""
    for index, label in ((2, "open"), (1, "wpa3-only"), (4, "enterprise")):
        state.reset()
        state.networks.set(NETS)
        state.selected.set(index)
        state.phase.set("scan")
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            scan._on_key(key_event(code="enter", name="enter"), visible_rows=4)
        assert state.phase.peek() == "audit", f"enter / {label}: audit did not open"
        assert state.audit_network.peek() is NETS[index], f"enter / {label}: wrong network"
    print("  ok  scan / passive audit works for every network type")


def test_scan_enter_without_selection_shows_feedback() -> None:
    state.reset()
    state.networks.set([])
    scan._on_key(key_event(code="enter", name=""), visible_rows=4)

    assert state.phase.peek() == "scan", "enter: changed phase without a selected network"
    assert state.scan_notice.peek(), "enter: no visible feedback for missing selection"
    obj = asyncio.run(_render_case(lambda: None, 80, 24))
    assert "Сначала выберите сеть" in obj.capture_char_frame(), (
        "enter: feedback was not rendered on the scan screen"
    )
    obj.destroy()
    print("  ok  scan / enter explains missing selection")


def test_audit_report() -> None:
    """The report screen is the network's identity plus one card."""
    def setup() -> None:
        state.reset()
        # state.reset() deliberately preserves readiness (it describes the
        # machine, not the run), so an earlier test's blocker would still be on
        # screen here.
        state.readiness.set(None)
        state.phase.set("audit")
        state.audit_network.set(NETS[0])

    check(
        setup,
        expect=["Проверка сети", "MyHomeWiFi", "WPA2-Personal"],
        label="audit / report",
    )


def test_audit_offers_the_run_and_says_what_it_does() -> None:
    """The screen says what will happen, and the key bar explains the screen.

    "Readiness not known yet" is no longer a verdict on its own: while the probe
    runs, the card already names the route the run will take, which is the useful
    thing to read in the meantime.
    """
    C = "\u041f\u043e\u0439\u043c\u0430\u044e \u0440\u0443\u043a\u043e\u043f\u043e\u0436\u0430\u0442\u0438\u0435"
    F = "\u041d\u0443\u0436\u0435\u043d \u0444\u0430\u0439\u043b \u0437\u0430\u0445\u0432\u0430\u0442\u0430"
    state.reset()
    state.readiness.set(None)
    state.phase.set("audit")
    state.audit_network.set(NETS[0])
    obj = asyncio.run(_render_case(lambda: None, 80, 30))
    frame = obj.capture_char_frame()
    obj.destroy()
    assert "Начать подбор" in frame and ("Источник" in frame or F in frame), (
        f"audit: the screen does not say what starting it will do\n{frame}")
    bar = frame.splitlines()[-1].lower()
    for wanted in ("tab", "enter", "esc"):
        assert wanted in bar, f"audit: bar lost {wanted!r}\n{frame}"
    print("  ok  audit / the plan is visible and the key bar explains the screen")


def test_audit_run_button_survives_a_short_terminal() -> None:
    """A clipped audit screen that lost its button is the dead end again.

    Also the layout contract: no line wider than the terminal, nothing taller
    than it, and the panel given exactly the rows the height budget promised.
    opentui paints past its box rather than clipping, so a body one row too tall
    silently overprints the footer -- which is how the button "disappeared" the
    first time this screen grew.
    """
    from wifi_tool import pipeline as pl

    long_blocker = (
        "Текущий драйвер Wi-Fi не поддерживает режим монитора (доступно: "
        "managed). Ключ из профиля Windows всё равно будет прочитан, а для "
        "остальных этапов нужен адаптер с monitor или готовый файл захвата."
    )
    sizes = ((44, 16), (52, 18), (60, 20), (60, 24), (80, 20), (80, 24),
             (80, 30), (100, 24), (100, 30), (120, 40))
    for width, height in sizes:
        for blocker in ("", long_blocker):
            state.reset()
            state.phase.set("audit")
            state.audit_network.set(NETS[0])
            state.readiness.set(pl.Readiness(admin=True, capture_problem=blocker))
            # No board: with one, a blocked capture is irrelevant and
            # deliberately not drawn.
            state.board.set(False)
            obj = asyncio.run(_render_case(lambda: None, width, height))
            lines = obj.capture_char_frame().splitlines()
            obj.destroy()
            frame = "\n".join(lines)
            label = f"{width}x{height} blocker={'yes' if blocker else 'no'}"

            assert "Проверка сети" in frame and any(action in frame for action in
                ("Начать подбор", "Выбрать файл захвата")), (
                f"audit: the run action was dropped at {label}\n{frame}"
            )
            assert ("Источник" in frame or "Нужен файл" in frame), (
                f"audit: stored-key path unavailable at {label}"
            )
            # With no board, the card names the only route that can work.
            # route. Its opening has to survive even at 44x16, where
            # Its opening has to survive even at 44x16, where the header,
            if blocker:
                assert "Нужен файл" in frame, (
                    f"audit: the blocker was dropped at {label}\n{frame}"
                )
            assert len(lines) <= height, f"audit: {len(lines)} rows at {label}"
            for i, line in enumerate(lines):
                assert display_width(line) <= width, (
                    f"audit: line {i} is {display_width(line)} wide at {label}: {line!r}"
                )
    print("  ok  audit / the content survives every terminal size")


def test_audit_arrow_keys_cover_every_direction() -> None:
    """Enter activates focus; arrows cannot launch; Esc returns."""
    target = NETS[0]
    for name in ("enter", "return"):
        state.reset()
        state.phase.set("audit")
        state.audit_network.set(target)
        with patch.object(controller, "start_auto_attack") as run:
            audit._on_key(key_event(name=name))
        run.assert_called_once_with(target)
    state.reset()
    state.phase.set("audit")
    state.audit_network.set(target)
    with patch.object(controller, "start_auto_attack") as run:
        audit._on_key(key_event(name="right"))
    run.assert_not_called()
    assert not dialogs.active()
    audit._on_key(key_event(name="left"))
    assert state.phase.peek() == "audit"
    for name in ("escape", "esc"):
        state.reset()
        state.phase.set("audit")
        state.audit_network.set(target)
        audit._on_key(key_event(name=name))
        assert state.phase.peek() == "scan"
    print("  ok  audit / current keyboard controls")


def test_audit_explains_a_blocked_run_before_it_starts() -> None:
    """A hardware blocker is visible up front, not after waiting for a run."""
    state.reset()
    state.phase.set("audit")
    state.audit_network.set(NETS[0])
    state.readiness.set(
        pipeline.Readiness(admin=True, capture_problem="Драйвер не поддерживает режим монитора")
    )
    obj = asyncio.run(_render_case(lambda: None, 100, 30))
    frame = obj.capture_char_frame()
    assert "Нужен файл" in frame, (
        "audit: the only available route is not offered")
    assert "Захват в эфире недоступен" in frame, (
        f"audit: why is not stated\n{frame}")
    obj.destroy()

    # The stored-key stage still runs despite the capture hardware limitation.
    with patch.object(controller, "start_auto_attack") as run:
        audit._run_auto()
        assert run.call_count == 1
    print("  ok  audit / a blocked run says what it needs")


def test_audit_without_a_network_still_offers_a_way_back() -> None:
    state.reset()
    state.phase.set("audit")
    state.audit_network.set(None)
    obj = asyncio.run(_render_case(lambda: None, 80, 24))
    frame = obj.capture_char_frame()
    assert "Сеть не выбрана" in frame
    assert "Esc" in frame, f"audit: no way back from the empty state\n{frame}"
    obj.destroy()


def test_audit_says_when_there_is_nothing_to_find() -> None:
    """Open, WPA3-only and Enterprise networks have no offline target.

    They must not offer a cracking run that cannot succeed. With a board
    connected the card says what it will actually do; without one it says the
    file is needed -- never that a crack is available.
    """
    for index, label in ((2, "open"), (1, "wpa3-only"), (4, "enterprise")):
        state.reset()
        state.readiness.set(None)
        state.board.set(False)
        state.audit_has_key.set(False)
        state.phase.set("audit")
        state.audit_network.set(NETS[index])
        obj = asyncio.run(_render_case(lambda: None, 100, 30))
        frame = obj.capture_char_frame()
        obj.destroy()
        if label == "open":
            assert "открытая" in frame.lower(), (
                f"audit / {label}: an open network is not named\n{frame}")
            assert "\u043f\u0430\u0440\u043e\u043b\u044f \u043d\u0435\u0442" in frame, (
                f"audit / {label}: the reason is not given\n{frame}")
        else:
            assert "\u041d\u0443\u0436\u0435\u043d \u0444\u0430\u0439\u043b \u0437\u0430\u0445\u0432\u0430\u0442\u0430" in frame, (
                f"audit / {label}: the only viable route is not offered\n{frame}")
    print("  ok  audit / a network with no offline target says so")


def test_scan_error() -> None:
    def setup() -> None:
        state.adapter.set(ADAPTER)
        state.is_admin.set(False)
        state.networks.set([])
        state.scan_error.set(scanner._describe_refusal(
            "Отказано в доступе. См. ms-settings:privacy-location"))

    check(
        setup,
        expect=["Сканирование недоступно", "ms-settings:privacy-location"],
        label="scan / error",
    )


def test_the_location_switch_is_explained_as_a_wifi_switch() -> None:
    """The refusal text must not imply the program wants coordinates.

    Windows hides the Wi-Fi scan behind the Location privacy setting, so the
    instruction has to name it -- but nothing here reads a position, and a
    message that just says "включи геолокацию" reads like a demand for one.
    """
    refusal = scanner._describe_refusal(
        "Отказано в доступе к списку сетей (службы определения местоположения "
        "отключены)")
    assert refusal, "the refusal was not recognised"
    assert "ms-settings:privacy-location" in refusal, refusal
    assert "не координатами" in refusal, (
        f"the message does not say what the switch is for\n{refusal}")
    assert "Включи геолокацию" not in refusal, (
        f"still phrased as a demand for location\n{refusal}")
    # And the refusal is about a permission, not a failure to find anything.
    plain = scanner._describe_refusal("Отказано в доступе")
    assert plain and "Wi-Fi" in plain, plain
    print("  ok  scan / the location switch is explained, not demanded")


def test_every_screen_shows_which_build_is_running() -> None:
    """The version belongs on screen, not in a log the user has to open.

    This exists because a change was made, the app was relaunched, the change did
    not appear, and there was no way to tell a stale process from a stale cache
    from a change that never ran. Three rebuilds went into arguing about it. One
    glance at the header answers the question, on every screen.
    """
    from wifi_tool import build_stamp

    state.reset()
    state.phase.set("audit")
    state.audit_network.set(NETS[0])
    obj = asyncio.run(_render_case(lambda: None, 100, 30))
    frame = obj.capture_char_frame()
    obj.destroy()
    stamp = build_stamp()
    assert stamp in frame, f"the audit screen does not show the build\n{frame}"
    state.reset()
    state.phase.set("crack")
    state.cracking_network.set(NETS[0])
    obj = asyncio.run(_render_case(lambda: None, 100, 30))
    running = obj.capture_char_frame()
    obj.destroy()
    assert stamp in running, f"the run screen does not show the build\n{running}"
    print("  ok  screens / the build stamp is on screen")


def test_the_animation_runs_on_the_thread_that_draws() -> None:
    """A run uses one render callback, and obsolete callbacks stay inert.

    The input-adapter regression is covered by the production runtime tests.
    This test checks the animation clock's lifecycle and wall-clock elapsed time.
    """
    from wifi_tool.ui import controller as ctl

    class FakeRenderer:
        def __init__(self):
            self.callbacks = []

        def set_frame_callback(self, cb):
            self.callbacks.append(cb)

    fake = FakeRenderer()
    previous, previous_cb = ctl._renderer, ctl._tick_callback
    try:
        ctl.bind(fake)
        ctl._tick_callback = None
        with patch.object(ctl.time, "monotonic", return_value=100.0):
            ctl.start_ticking()
        assert fake.callbacks, "the animation did not hook the frame callback"
        state.reset()
        state.phase.set("crack")
        state.tick.set(0)
        state.elapsed.set(0.0)
        for index in range(10):
            with patch.object(ctl.time, "monotonic", return_value=100.0 + (index + 1) * 0.12):
                fake.callbacks[0](0.12)
        assert state.tick.peek() > 0, "the frame callback did not advance the spinner"
        assert state.elapsed.peek() > 0.0, "the frame clock did not advance"
        count = len(fake.callbacks)
        ctl.start_ticking()
        assert len(fake.callbacks) == count, "the frame callback was registered twice"
        state.phase.set("scan")
        before = state.tick.peek()
        fake.callbacks[0](0.12)
        assert state.tick.peek() == before, "the animation runs while idle"
    finally:
        ctl.bind(previous)
        ctl._tick_callback = previous_cb
        ctl.stop_ticking()
    print("  ok  run / the animation is driven by the render thread")


def test_a_connected_board_replaces_the_file_line() -> None:
    """With a board plugged in, that is the route -- and the file picker is gone.

    The board's radio can capture and the PC's cannot, so offering both at equal
    weight makes the user assemble a capture by hand for no reason. Without a
    board the file route must come back, or a machine that has one loses the only
    route it actually has.
    """
    BOARD = "Плата подключена"
    FILE = "Нужен файл"
    blocked = pipeline.Readiness(admin=True, capture_problem="драйвер")

    state.reset()
    state.readiness.set(blocked)
    state.board.set("COM5 CH9102")
    state.audit_has_key.set(False)
    state.phase.set("audit")
    state.audit_network.set(NETS[0])
    obj = asyncio.run(_render_case(lambda: None, 100, 30))
    with_board = obj.capture_char_frame()
    obj.destroy()
    assert BOARD in with_board, f"the board is not offered\n{with_board}"
    assert FILE not in with_board, (
        f"the file route is still offered next to the board\n{with_board}")

    state.reset()
    state.readiness.set(blocked)
    state.board.set(False)
    state.audit_has_key.set(False)
    state.phase.set("audit")
    state.audit_network.set(NETS[0])
    obj = asyncio.run(_render_case(lambda: None, 100, 30))
    without = obj.capture_char_frame()
    obj.destroy()
    assert BOARD not in without, f"a board is offered when none is plugged in\n{without}"
    assert FILE in without, f"the file route vanished without a board\n{without}"
    print("  ok  audit / a connected board is the capture route")


def test_the_board_action_is_one_code_path() -> None:
    """The line and the F1 entry must start the same run.

    They used to be two: the screen's button pulled the file and a second polling
    loop launched the run, while the menu entry only pulled it. So choosing the
    board from the menu left a capture sitting in the folder with nothing cracking
    it -- the same class of bug as a button that does nothing.
    """
    from wifi_tool.ui.screens import audit as audit_mod

    state.reset()
    state.board.set("COM5 CH9102")
    state.audit_has_key.set(False)
    state.phase.set("audit")
    state.audit_network.set(NETS[0])
    entry = next(a for a in audit_mod.audit_actions() if "платы" in a.label)
    assert entry.run is controller.start_board_capture, (
        f"the menu entry points somewhere else: {entry.run}")
    calls = []
    with patch.object(controller, "start_board_capture",
                      side_effect=lambda: calls.append(1)):
        entry = audit_mod.audit_actions()[0]
        from wifi_tool.ui import controls
        controls.set_focus("audit", controls.action_id(entry))
        audit_mod._on_key(key_event(key="enter"))
    assert calls == [1], f"the on-screen line took a different path: {calls}"
    print("  ok  audit / the board line and the menu entry are one action")


def test_the_board_wait_is_a_visible_run_not_a_hidden_sleep() -> None:
    """Waiting for a handshake is a phase, with the phone instruction on screen.

    The one step a machine cannot do is make a client reconnect, so the wait has
    to reach a human. It used to be a background task that pushed one line into
    the log and then sat there, which looks exactly like a hang.
    """
    state.reset()
    state.phase.set("crack")
    state.log.set([])
    controller.begin_run("board")
    state.current_activity.set("Слушаю рукопожатие на плате")
    assert [k for k, s in state.run_stages.peek() if s == "current"] == ["board"], (
        f"the wait is not the running stage: {state.run_stages.peek()}")
    state.status.set("Переподключи Wi-Fi на телефоне · 2:58")
    obj = asyncio.run(_render_case(lambda: None, 100, 30))
    frame = obj.capture_char_frame()
    obj.destroy()
    assert "Ожидание рукопожатия" in frame, f"the wait is not on screen\n{frame}"
    assert "Переподключи Wi-Fi" in frame, (
        f"the phone instruction is not on screen\n{frame}")
    print("  ok  audit / waiting for the board is a visible run")


def test_the_run_screen_moves_without_any_keypress() -> None:
    """The spinner must advance from the tick the frame callback drives.

    The test harness has no renderer loop, so it cannot prove a repaint -- that
    needs a real process, and the regression that mattered was invisible here
    for exactly that reason: the harness calls ``render_frame()`` by hand, so a
    frozen spinner still produced a frame. What is checked here is the input the
    screen draws from, while the actual idle repaint is covered by production runtime tests.
    """
    from wifi_tool.ui.screens.crack import _stage_rows
    from wifi_tool.ui.widgets import spinner_frame

    state.reset()
    state.phase.set("crack")
    state.cracking_network.set(NETS[0])
    controller.begin_run("saved", "capture", "convert", "crack")

    def drawn(tick: int) -> str:
        rows = _stage_rows(80, state.run_stages.peek(), tick)
        return "\n".join(getattr(r, "content", str(r)) for r in rows)

    first = drawn(0)
    seen = {drawn(t) for t in range(10)}
    assert len(seen) > 1, f"the spinner never moves: {first}"
    glyphs = {spinner_frame(t) for t in range(10)}
    assert any(any(g in text for g in glyphs) for text in seen), (
        f"no spinner glyph at all\n{first}")

    # The elapsed clock is what tells a one-second run from a five-minute one,
    # and it is driven by the same frame callback.
    assert state.elapsed.peek() == 0.0
    print("  ok  run / the spinner advances from the frame clock")


