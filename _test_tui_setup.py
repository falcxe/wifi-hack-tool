"""Keyboard, paste, file-picker and layout coverage for the TUI audit flow.

Where a test needs to prove something about what the *real* terminal delivers,
it drives ``TestInputHandler`` (see :func:`native_input`) rather than the mock
harness. That distinction matters: the mock fabricates events a real terminal
cannot produce, and ``test_no_ctrl_combination_reaches_the_app`` exists because
a feature bound to Ctrl+A passed every mock-driven test while doing nothing.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from opentui.structs import display_width
from opentui.testing import test_render
from opentui.input.event_loop import TestInputHandler
from opentui.renderer._session import bind_event_loop

from wifi_tool import cracker, hc22000, pipeline
from wifi_tool.models import Network
from wifi_tool.options import CrackOptions
from wifi_tool.ui import controller, dialogs, forms, state
from wifi_tool.ui.app import App

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "tests" / "fixtures" / "wpa2_psk_12345678.pcapng"


def native_input(setup):
    """Bind once just like the production terminal, rather than MockInput."""
    handler = TestInputHandler()
    handler.start()
    bind_event_loop(
        setup.renderer,
        SimpleNamespace(input_handler=handler, on_frame=lambda cb: None),
    )
    return handler


def field_index(name: str) -> int:
    return [row[0] for row in forms.fields()].index(name)


def choose_command(setup, label: str, native=None) -> None:
    """Drive the current command menu through keyboard/paste input."""
    if native:
        native.feed("\x1bOP")
    else:
        setup.mock_input.press_key("f1")
    setup.render_frame()
    assert dialogs.active(), "F1 did not open the command menu"
    if native:
        native.feed("\x1b[200~" + label + "\x1b[201~")
    else:
        setup.mock_input.paste_text(label)
    setup.render_frame()
    assert dialogs.filtered()[0].label == label
    if native:
        native.feed("\r")
    else:
        setup.mock_input.press_enter()
    setup.render_frame()


class SetupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Navigation tests exercise UI contracts without running machine probes.
        spawn = patch.object(controller, "_spawn", side_effect=lambda coro: coro.close())
        spawn.start()
        self.addCleanup(spawn.stop)
        state.reset()
        state.readiness.set(None)
        forms.open_form()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(controller.configure_cracking, CrackOptions())

    async def render(self, width=80, height=24):
        setup = await test_render(App, {"width": width, "height": height})
        setup.render_frame()
        self.addCleanup(setup.destroy)
        return setup

    # --- layout -----------------------------------------------------------

    async def test_form_layout_at_small_terminal_sizes(self):
        for mode in ("rockyou", "quick", "custom", "mask"):
            for width, height in ((60, 20), (80, 24), (100, 30)):
                forms.open_form()
                forms.set_value("mode", mode)
                forms.set_value("rules", True)
                setup = await self.render(width, height)
                frame = setup.capture_char_frame()
                self.assertLessEqual(len(frame.splitlines()), height)
                self.assertIn("Параметры", frame.splitlines()[0])
                self.assertIn("Начать подбор", frame)
                self.assertNotIn("F1 меню", frame)
                self.assertTrue(frame.splitlines()[-1].strip())
                self.assertIn("Лимит, сек", frame)
                self.assertTrue(
                    all(display_width(line) <= width for line in frame.splitlines())
                )
                setup.destroy()

    # --- text entry -------------------------------------------------------

    async def test_preserves_uppercase_mask_editing_and_paste(self):
        forms.set_value("mode", "mask")
        forms.focus(field_index("mask"))
        setup = await self.render()
        # Use the reachable clear command; Backspace at Home is a no-op.
        choose_command(setup, "Очистить поле")
        setup.render_frame()
        self.assertEqual(state.form_values.peek()["mask"], "")
        setup.mock_input.type_text("MyHome?d?d")
        setup.render_frame()
        self.assertEqual(state.form_values.peek()["mask"], "MyHome?d?d")
        choose_command(setup, "Очистить поле")
        setup.mock_input.paste_text("Домашний пароль")
        setup.render_frame()
        self.assertEqual(state.form_values.peek()["mask"], "Домашний пароль")
        setup.mock_input.press_arrow("left")
        setup.mock_input.press_backspace()
        setup.render_frame()
        self.assertEqual(state.form_values.peek()["mask"], "Домашний пароь")

    async def test_no_ctrl_combination_reaches_the_app(self):
        """opentui 0.1.2 drops every Ctrl combination -- so nothing may rely on one.

        Found the hard way: the form bound Ctrl+A to "select all" and Ctrl+U to
        "clear", both unreachable, and the mock input harness fabricated events
        the real terminal cannot produce, so the tests agreed while the feature
        did nothing. This drives the *production* input handler so the claim
        stays honest -- and asserts a plain key still arrives, so the test cannot
        pass by proving nothing.
        """
        forms.set_value("mode", "mask")
        forms.focus(field_index("mask"))
        setup = await self.render()
        native = native_input(setup)
        self.addCleanup(native.stop)

        with patch.object(controller, "quit_app") as quit_app:
            for sequence in (chr(1), chr(21), chr(23)):  # Ctrl+A, Ctrl+U, Ctrl+W
                native.feed(sequence)
                setup.render_frame()
            quit_app.assert_not_called()
            native.feed("z")  # a plain key must still get through
            setup.render_frame()
        self.assertTrue(
            state.form_values.peek()["mask"].endswith("z"),
            f"ctrl test is vacuous: a plain key did not register either "
            f"({state.form_values.peek()['mask']!r})",
        )

        # The reachable way to empty a field is what the docs promise instead.
        forms.set_value("mask", "")
        forms.focus(field_index("mask"))
        setup.mock_input.type_text("MyHome?d?d")
        setup.mock_input.press_key("home")
        setup.mock_input.press_backspace()
        setup.render_frame()
        self.assertEqual(state.form_values.peek()["mask"], "MyHome?d?d")
        choose_command(setup, "Очистить поле", native=native)
        self.assertEqual(state.form_values.peek()["mask"], "",
                         "The F1 clear command must work with production input")

    # --- file picker ------------------------------------------------------

    async def test_file_picker_filters_and_returns_selected_file(self):
        directory = Path(self.tmp.name)
        wanted = directory / "my capture.pcapng"
        wanted.write_bytes(b"fixture")
        (directory / "irrelevant.exe").write_bytes(b"do not execute")
        (directory / "folder").mkdir()
        forms.open_picker("capture")
        forms.list_directory(directory)
        setup = await self.render()
        entries = state.file_entries.peek()
        self.assertIn(wanted, entries)
        self.assertNotIn(directory / "irrelevant.exe", entries)
        state.file_selected.set(entries.index(wanted))
        setup.render_frame()
        setup.mock_input.press_enter()
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "crack_form")
        self.assertEqual(state.form_values.peek()["capture"], str(wanted))

    async def test_picker_navigation_and_escape(self):
        forms.open_picker("capture")
        setup = await self.render()
        directory = Path(state.file_directory.peek())
        setup.mock_input.press_backspace()
        self.assertEqual(Path(state.file_directory.peek()), directory.parent)
        setup.mock_input.press_escape()
        self.assertEqual(state.phase.peek(), "crack_form")

    async def test_file_command_from_start_button_opens_capture_picker(self):
        forms.focus(len(forms.fields()) - 1)
        setup = await self.render()
        native = native_input(setup)
        self.addCleanup(native.stop)
        choose_command(setup, "Файл", native)
        self.assertEqual(state.phase.peek(), "file_picker")
        self.assertEqual(state.file_field.peek(), "capture")

    async def test_file_command_reveals_hidden_capture_field(self):
        """The menu can reveal the capture field from a live source."""
        own = Network("Own", "aa:bb:cc:dd:ee:ff", channel=6, auth="WPA2-Personal")
        forms.open_form(own)
        # "live" source: there is no capture row at all until the source changes.
        self.assertNotIn("capture", [row[0] for row in forms.fields()])
        forms.focus(0)
        setup = await self.render()
        choose_command(setup, "Файл")
        self.assertEqual(state.phase.peek(), "file_picker")
        self.assertEqual(state.file_field.peek(), "capture")
        self.assertEqual(state.form_values.peek()["source"], "file")

    # --- submitting -------------------------------------------------------

    async def test_defaults_need_no_dictionary_selection(self):
        self.assertTrue(forms.ROCKYOU.is_file())
        self.assertTrue(forms.QUICK.is_file())
        capture = Path(self.tmp.name) / "own.pcapng"
        capture.write_bytes(b"fixture")
        forms.set_value("capture", str(capture))
        forms.focus(len(forms.fields()) - 1)
        setup = await self.render()
        with patch.object(controller, "open_capture") as start:
            setup.mock_input.press_enter()
        self.assertEqual(start.call_args.args, (capture,))
        self.assertTrue(start.call_args.kwargs["choose_target"])
        self.assertEqual(controller._crack_options.wordlist, forms.ROCKYOU)
        self.assertFalse(controller._crack_options.use_rules)

    async def test_validation_keeps_form_open(self):
        forms.set_value("runtime", "0")
        forms.focus(len(forms.fields()) - 1)
        setup = await self.render()
        with patch.object(controller, "open_capture") as start:
            setup.mock_input.press_enter()
        start.assert_not_called()
        self.assertEqual(state.phase.peek(), "crack_form")
        self.assertIn("положительным", state.form_error.peek())

    async def test_file_blocker_explains_missing_wpa_data(self):
        setup = await self.render(100, 30)
        self.assertIn("Выберите файл захвата", setup.capture_char_frame())
        self.assertIn("EAPOL / PMKID", setup.capture_char_frame())
        forms.focus(len(forms.fields()) - 1)
        with patch.object(controller, "open_capture") as start:
            setup.mock_input.press_enter()
        start.assert_not_called()
        self.assertIn("рукопожатия / PMKID", state.form_error.peek())

    # --- live capture blockers --------------------------------------------

    async def test_live_capture_unavailable_is_visible_before_start(self):
        forms.open_form(Network("Own", "aa:bb:cc:dd:ee:ff", auth="WPA2-Personal"))
        forms.set_value("source", "live")
        with patch.object(controller, "_readiness",
                          return_value=pipeline.Readiness(admin=False)), \
                patch.object(controller, "start_attack") as start:
            forms.submit()
        start.assert_not_called()
        self.assertIn("администратора", state.form_error.peek())

    async def test_live_capture_missing_bssid_is_visible_before_start(self):
        forms.open_form(Network("Own", "", auth="WPA2-Personal"))
        forms.set_value("source", "live")
        with patch.object(controller, "_readiness", return_value=pipeline.Readiness()), \
                patch.object(controller, "start_attack") as start:
            forms.submit()
        start.assert_not_called()
        self.assertIn("BSSID не получен", state.form_error.peek())

    async def test_capture_driver_problem_shown_before_live_launch(self):
        own = Network("Own", "aa:bb:cc:dd:ee:ff", auth="WPA2-Personal")
        ready = pipeline.Readiness(
            admin=True, capture_problem="Npcap: поддержка raw 802.11 выключена"
        )
        state.readiness.set(ready)
        forms.open_form(own)
        self.assertIn("Npcap", forms.start_problem())
        forms.set_value("source", "live")
        with patch.object(controller, "_readiness", return_value=ready), \
                patch.object(controller, "start_attack") as start:
            forms.submit()
        start.assert_not_called()
        self.assertIn("Npcap", state.form_error.peek())

    async def test_selected_network_does_not_silently_fall_back_to_file(self):
        own = Network("Own", "aa:bb:cc:dd:ee:ff", auth="WPA2-Personal")
        state.readiness.set(pipeline.Readiness(
            admin=True,
            capture_problem="Драйвер не поддерживает режим монитора",
        ))
        forms.open_form(own)
        self.assertEqual(state.form_values.peek()["source"], "live")
        forms.set_value("mode", "quick")
        setup = await self.render(100, 30)
        frame = setup.capture_char_frame()
        self.assertIn("Начать подбор", frame)
        self.assertIn("режим монитора", frame)
        self.assertNotIn("Выбери файл захвата через F2", frame)

    async def test_inactive_capture_screen_does_not_cancel_file_picker(self):
        from opentui.events import KeyEvent

        from wifi_tool.ui.screens.crack import _on_key

        forms.open_picker("capture")
        with patch.object(controller, "cancel_attack") as cancel:
            _on_key(KeyEvent(key="escape", code="escape"))
        cancel.assert_not_called()
        self.assertEqual(state.phase.peek(), "file_picker")

    # --- navigation between screens ---------------------------------------

    async def test_main_screen_opens_password_setup_from_the_audit(self):
        """The scan screen stays passive; the form is behind the audit screen."""
        own = Network("Own", "aa:bb:cc:dd:ee:ff", channel=6, auth="WPA2-Personal")
        state.phase.set("scan")
        state.networks.set([own])
        state.selected.set(0)
        setup = await self.render()
        setup.mock_input.press_key("p")
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "scan",
                         "P launched a flow from the passive list")

        setup.mock_input.press_enter()
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "audit")
        choose_command(setup, "Параметры")
        self.assertEqual(state.phase.peek(), "crack_form")
        self.assertIn("RockYou WPA", setup.capture_char_frame())
        self.assertEqual(state.form_values.peek()["capture"], "")

    async def test_production_input_scan_audit_parameters_and_paste(self):
        # The former mocks read hooks afresh on every key, hiding the real
        # runtime failure where only scan screen handlers were ever bound.
        own = Network("Own", "aa:bb:cc:dd:ee:ff", channel=44, auth="WPA2-Personal")
        state.phase.set("scan")
        state.networks.set([own])
        state.selected.set(0)
        setup = await self.render()
        native = native_input(setup)
        self.addCleanup(native.stop)
        for opener in ("\r",):
            state.phase.set("scan")
            setup.render_frame()
            native.feed(opener)
            setup.render_frame()
            self.assertEqual(state.phase.peek(), "audit",
                             f"{opener!r} did not open the audit")
            self.assertIs(state.audit_network.peek(), own)
            native.feed("\x1b")
            setup.render_frame()
            self.assertEqual(state.phase.peek(), "scan")
        for _ in range(1):
            state.phase.set("audit")
            state.audit_network.set(own)
            setup.render_frame()
            choose_command(setup, "Параметры", native)
            self.assertEqual(state.phase.peek(), "crack_form")
            self.assertIs(state.form_network.peek(), own)
            self.assertEqual(state.form_values.peek()["capture"], "")
            self.assertEqual(state.form_values.peek()["source"], "live")
            native.feed("\r")      # source choices
            native.feed("\x1b[A") # live -> file
            native.feed("\r")
            native.feed("\t")     # capture field
            native.feed("\x1b[200~C:\\Own\\capture.pcapng\x1b[201~")
            self.assertEqual(state.form_values.peek()["capture"],
                             r"C:\Own\capture.pcapng")

    async def test_production_input_menu_starts_run_from_the_audit(self):
        """F1 opens commands; Enter activates the primary run action."""
        own = Network("Own", "aa:bb:cc:dd:ee:ff", channel=44, auth="WPA2-Personal")
        state.phase.set("scan")
        state.networks.set([own])
        state.selected.set(0)
        setup = await self.render()
        native = native_input(setup)
        self.addCleanup(native.stop)
        native.feed("\r")
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "audit")
        frame = setup.capture_char_frame()
        self.assertTrue(
            "Начать подбор" in frame
            or "Нужен файл" in frame
            or "Открытая" in frame,
            f"audit screen says nothing about the run:\n{frame}")
        with patch.object(controller, "_spawn") as spawn:
            native.feed("\x1bOP")  # F1
            setup.render_frame()
            self.assertTrue(dialogs.active())
            spawn.assert_not_called()
            native.feed("\r")
            setup.render_frame()
        spawn.assert_called_once()
        self.assertEqual(getattr(spawn.call_args.args[0], "__name__", ""),
                         "run_auto_attack")
        spawn.call_args.args[0].close()
        self.assertEqual(state.phase.peek(), "crack")
        self.assertIs(state.cracking_network.peek(), own)
        # While a run is in flight, stopping it is the action that has to be
        # visible -- it is the only thing usually wanted here.
        self.assertIn("Остановить", setup.capture_char_frame())

    async def test_escape_returns_from_the_audit_to_the_list(self):
        own = Network("Own", "aa:bb:cc:dd:ee:ff", channel=44, auth="WPA2-Personal")
        state.phase.set("scan")
        state.networks.set([own])
        state.selected.set(0)
        setup = await self.render()
        native = native_input(setup)
        self.addCleanup(native.stop)
        native.feed("\r")
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "audit")
        native.feed("\x1b")  # Esc
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "scan")

    async def test_production_input_file_picker_and_launch_only_once(self):
        own = Network("Own", "aa:bb:cc:dd:ee:ff", channel=6, auth="WPA2-Personal")
        state.phase.set("scan")
        state.networks.set([own])
        state.selected.set(0)
        capture = Path(self.tmp.name) / "Own.pcapng"
        capture.write_bytes(b"fixture")
        setup = await self.render()
        native = native_input(setup)
        self.addCleanup(native.stop)
        native.feed("\r")   # scan -> audit
        setup.render_frame()
        choose_command(setup, "Параметры", native)
        self.assertEqual(state.phase.peek(), "crack_form")
        choose_command(setup, "Файл", native)
        self.assertEqual(state.phase.peek(), "file_picker")
        forms.list_directory(capture.parent)
        state.file_selected.set(state.file_entries.peek().index(capture))
        setup.render_frame()
        native.feed("\r")
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "crack_form")
        self.assertEqual(state.form_values.peek()["capture"], str(capture))
        forms.focus(len(forms.fields()) - 1)
        setup.render_frame()
        with patch.object(controller, "open_capture") as start:
            native.feed("\r")
        start.assert_called_once_with(capture, choose_target=True)

    async def test_multiple_networks_are_selected_in_tui(self):
        capture = Path(self.tmp.name) / "own.22000"
        capture.write_text("fixture", encoding="utf-8")
        records = ["WPA*01*" + "00" * 16 + f"*{ap}*000000000000*4f776e***"
                   for ap in ("aabbccddeeff", "112233445566")]
        report = hc22000.ConversionReport(pmkid=records)
        with patch.object(pipeline, "convert_capture",
                          AsyncMock(return_value=(capture, report))):
            await controller._open_capture(capture, choose_target=True)
        self.assertEqual(state.phase.peek(), "capture_targets")
        setup = await self.render(60, 20)
        self.assertIn("Выбрать сеть", setup.capture_char_frame())
        setup.mock_input.press_arrow("down")
        setup.render_frame()
        expected = state.capture_targets.peek()[1].bssid
        with patch.object(controller, "open_capture") as start:
            setup.mock_input.press_enter()
        self.assertEqual(controller._crack_options.bssid, expected)
        start.assert_called_once()

    # --- help -------------------------------------------------------------

    async def test_native_help_pages_and_return_preserve_parameters(self):
        forms.set_value("mode", "mask")
        forms.set_value("mask", "Course?d?d")
        before = dict(state.form_values.peek())
        setup = await self.render(80, 24)
        native = native_input(setup)
        self.addCleanup(native.stop)
        choose_command(setup, "Справка", native)
        self.assertEqual(state.phase.peek(), "method_help")
        self.assertIn("Данные для запуска", setup.capture_char_frame())
        seen = setup.capture_char_frame()
        for _ in range(20):
            native.feed("\x1b[6~")
            setup.render_frame()
            seen += setup.capture_char_frame()
        for method in ("RockYou WPA", "Быстрый словарь", "Свой словарь", "Маска",
                       "Мутации", "Сохранённые сети"):
            self.assertIn(method, seen)
        self.assertIn("Плюс:", seen)
        self.assertIn("Минус:", seen)
        native.feed("\x1b")
        setup.render_frame()
        self.assertEqual(state.phase.peek(), "crack_form")
        self.assertEqual(state.form_values.peek(), before)

    async def test_help_fits_small_and_large_terminals(self):
        for width, height in ((60, 20), (80, 24), (100, 30)):
            forms.open_help()
            setup = await self.render(width, height)
            for position in (0, 20, 999):
                state.help_scroll.set(position)
                setup.render_frame()
                frame = setup.capture_char_frame()
                self.assertLessEqual(len(frame.splitlines()), height)
                self.assertTrue(all(display_width(line) <= width
                                    for line in frame.splitlines()))
                self.assertIn("esc назад", frame.splitlines()[-1].lower())


async def real_tui_fixture_check():
    """Select a file and the built-in list through TUI keys, then use real hashcat."""
    hashcat = cracker.find_hashcat()
    if hashcat is None or not FIXTURE.is_file():
        print("SKIP real TUI fixture: hashcat or fixture missing")
        return
    state.reset()
    forms.open_form()
    setup = await test_render(App, {"width": 80, "height": 24})
    setup.render_frame()
    native = native_input(setup)
    real_crack = cracker.crack
    isolated = tempfile.TemporaryDirectory()

    async def fresh_crack(*args, **kwargs):
        kwargs["potfile"] = Path(isolated.name) / "fresh.potfile"
        return await real_crack(*args, **kwargs)

    try:
        native.feed("\x1b[200~" + str(FIXTURE) + "\x1b[201~")
        assert state.form_values.peek()["mode"] == "rockyou"
        ready = pipeline.Readiness(hashcat=hashcat, wordlist=forms.ROCKYOU)
        with patch.object(pipeline, "check_readiness", return_value=ready), \
                patch.object(cracker, "crack", side_effect=fresh_crack):
            forms.focus(len(forms.fields()) - 1)
            setup.render_frame()
            native.feed("\r")
            started = time.monotonic()
            while state.phase.peek() != "result":
                if time.monotonic() - started > 45:
                    controller.stop_pending()
                    raise AssertionError("TUI fixture did not finish in 45 seconds")
                await asyncio.sleep(0.1)
                setup.render_frame()
        result = state.result.peek()
        assert result.success and result.password == "12345678", result.error
        assert "Пароль найден" in setup.capture_char_frame()
        print(f"REAL TUI FLOW OK: file -> built-in dictionary -> result "
              f"in {result.elapsed:.1f}s")
    finally:
        native.stop()
        setup.destroy()
        controller.stop_pending()
        isolated.cleanup()


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SetupTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    asyncio.run(real_tui_fixture_check())
