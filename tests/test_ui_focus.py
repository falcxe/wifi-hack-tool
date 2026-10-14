"""Production-parser keyboard and renderer mouse coverage for secondary focus."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from opentui.testing import test_render

from .test_secondary_ui import FIXTURE, NETWORK, ROOT, setup_case
from .test_tui_setup import field_index, native_input
from wifi_tool import profiles
from wifi_tool.models import CrackResult, RunRequest
from wifi_tool.options import CrackOptions
from wifi_tool.ui import commands, controls, controller, dialogs, forms, state
from wifi_tool.ui.app import App
from wifi_tool.ui.screens import audit, crack_form, result, saved


def text_point(frame: str, label: str, *, marked: bool = False) -> tuple[int, int]:
    for row, line in enumerate(frame.splitlines()):
        if label in line and (not marked or "›" in line):
            return line.index(label) + 1, row
    raise AssertionError(f"Missing control {label!r}\n{frame}")


class FocusTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(dialogs.clear)
        self.addCleanup(controller.stop_ticking)
        self.spawn = patch.object(controller, "_spawn", side_effect=lambda coro: coro.close())
        self.spawn.start()
        self.addCleanup(self.spawn.stop)
        self.clock = patch.object(controller, "start_ticking")
        self.clock.start()
        self.addCleanup(self.clock.stop)
        # The focus tests move the cursor between menu rows, and two of them
        # use «Ключи» as the row in the middle of the list. With the connection
        # history switched off that row is gone by design, so the switch goes
        # back on here: what is under test is focus, not the switch. The switch
        # itself has its own tests in test_auto.py.
        self.history = patch.object(profiles, "HISTORY_ENABLED", True)
        self.history.start()
        self.addCleanup(self.history.stop)

    async def render(self, case: str, width: int = 80, height: int = 24):
        setup_case(case, self.directory)
        view = await test_render(App, {"width": width, "height": height})
        view.render_frame()
        native = native_input(view)
        self.addCleanup(view.destroy)
        self.addCleanup(native.stop)
        return view, native

    def feed(self, view, native, sequence: str):
        native.feed(sequence)
        view.render_frame()

    async def test_audit_focus_native_tab_reverse_enter_and_right_noop(self):
        view, native = await self.render("audit")
        state.board.set("fixture board")
        with patch.object(controller, "start_board_capture") as board, patch.object(audit, "_open_parameters") as params:
            view.render_frame()
            self.assertIn("› Захват с платы", view.capture_char_frame())
            self.assertEqual([a.label for a in audit.audit_actions()].count("Захват с платы"), 1)
            self.assertNotIn("Захват адаптером", view.capture_char_frame())
            self.feed(view, native, "\t")
            self.assertIn("› Файл захвата", view.capture_char_frame())
            self.feed(view, native, "\t")
            self.assertIn("› Параметры", view.capture_char_frame())
            self.feed(view, native, "\r")
            params.assert_called_once()
            board.assert_not_called()
            self.feed(view, native, "\x1b[Z\x1b[Z")
            self.assertIn("› Захват с платы", view.capture_char_frame())
            self.feed(view, native, "\x1b[C")
            self.assertFalse(dialogs.active())
            board.assert_not_called()
            self.feed(view, native, "\r")
            board.assert_called_once()

    async def test_disabled_action_is_skipped_and_focus_survives_modal(self):
        view, native = await self.render("audit")
        self.feed(view, native, "\t")
        self.assertIn("› Параметры", view.capture_char_frame())
        self.feed(view, native, "\t")
        self.assertIn("› Подробности сети", view.capture_char_frame())
        self.feed(view, native, "\t")
        self.assertIn("› Назад к сетям", view.capture_char_frame())
        selected = state.control_focus.peek()["audit"]
        self.feed(view, native, "\x1bOP")
        self.assertIn("Команды", view.capture_char_frame())
        self.assertNotIn("Основное", view.capture_char_frame())
        self.assertNotIn("Источники", view.capture_char_frame())
        self.assertNotIn("Настройки", view.capture_char_frame())
        self.assertNotIn("Изменить источник данных и параметры подбора", view.capture_char_frame())
        self.feed(view, native, "\x1b[F")
        self.assertIn("› Выход", view.capture_char_frame())
        self.feed(view, native, "\x1b[Z")
        self.assertIn("› Ключи", view.capture_char_frame())
        self.feed(view, native, "\x1b[H\t")
        self.assertIn("› Параметры", view.capture_char_frame())
        self.assertTrue(dialogs.active())
        self.feed(view, native, "\x1b")
        self.assertFalse(dialogs.active())
        self.assertEqual(state.control_focus.peek()["audit"], selected)
        self.assertIn("› Назад к сетям", view.capture_char_frame())
        with patch.object(audit, "_capture_only") as capture:
            view.mock_mouse.click(*text_point(view.capture_char_frame(), "Захват адаптером"))
            capture.assert_not_called()

    async def test_form_arrows_edit_at_boundaries_tab_wraps_and_start_activates_once(self):
        view, native = await self.render("form")
        forms.set_value("mode", "mask")
        forms.focus(field_index("mask"))
        state.form_cursor.set(0)
        self.feed(view, native, "\x1b[D")
        self.assertEqual(state.phase.peek(), "crack_form")
        self.assertEqual(state.form_cursor.peek(), 0)
        forms.focus(field_index("capture"))
        state.form_cursor.set(0)
        self.feed(view, native, "\x1b[D")
        self.assertEqual(state.phase.peek(), "crack_form")
        self.feed(view, native, "\x1b[C")
        self.assertEqual(state.form_cursor.peek(), 1)
        self.assertFalse(dialogs.active())
        forms.focus(field_index("mode"))
        self.feed(view, native, "\x1b[D")
        self.assertEqual(state.form_values.peek()["mode"], "custom")
        forms.focus(len(forms.fields()) - 1)
        self.feed(view, native, "\t")
        self.assertEqual(state.form_focus.peek(), 0)
        self.feed(view, native, "\x1b[Z")
        self.assertEqual(state.form_focus.peek(), len(forms.fields()) - 1)
        with patch.object(forms, "start_problem", return_value=""), patch.object(forms, "submit") as submit:
            self.feed(view, native, "\x1b[C")
            submit.assert_not_called()
            self.assertFalse(dialogs.active())
            self.feed(view, native, "\r")
            submit.assert_called_once()

    async def test_form_after_mount_menu_mouse_and_idle_layer_do_not_intercept(self):
        view, native = await self.render("form", 160, 40)
        before = dict(state.form_values.peek())
        forms.focus(field_index("runtime"))
        view.render_frame()
        self.feed(view, native, "\x1bOP")
        self.assertIn("Команды", view.capture_char_frame())
        native.feed("\x1b[200~Справка\x1b[201~")
        view.render_frame()
        self.assertIn("› Справка", view.capture_char_frame())
        view.mock_mouse.click(*text_point(view.capture_char_frame(), "Справка", marked=True))
        view.render_frame()
        self.assertEqual(state.phase.peek(), "method_help")
        self.assertFalse(dialogs.active())
        view.mock_mouse.click(*text_point(view.capture_char_frame(), "Закрыть"))
        view.render_frame()
        self.assertEqual(state.phase.peek(), "crack_form")
        self.assertEqual(state.form_values.peek(), before)
        self.assertEqual(state.form_focus.peek(), field_index("runtime"))
        view.mock_mouse.click(*text_point(view.capture_char_frame(), "Лимит, сек"))
        view.render_frame()
        self.assertEqual(state.form_focus.peek(), field_index("runtime"))
        self.assertFalse(dialogs.active())

    async def test_home_menu_keyboard_mouse_selection_and_passive_audit_enter(self):
        state.reset()
        state.readiness.set(None)
        state.networks.set([NETWORK])
        view = await test_render(App, {"width": 80, "height": 24})
        view.render_frame()
        native = native_input(view)
        self.addCleanup(view.destroy)
        self.addCleanup(native.stop)
        self.assertNotIn("F1 меню", view.capture_char_frame())
        self.feed(view, native, "\x1bOP")
        self.assertTrue(dialogs.active())
        self.assertIn("Команды", view.capture_char_frame())
        dialogs.set_query("Ключи")
        view.render_frame()
        view.mock_mouse.click(*text_point(view.capture_char_frame(), "Ключи", marked=True))
        view.render_frame()
        self.assertEqual(state.phase.peek(), "saved")
        self.assertFalse(dialogs.active())
        state.phase.set("scan")
        view.render_frame()
        view.mock_mouse.click(*text_point(view.capture_char_frame(), NETWORK.label, marked=True))
        view.render_frame()
        self.assertEqual(state.control_focus.peek()["scan"], "list")
        self.feed(view, native, "\r")
        self.assertEqual(state.phase.peek(), "audit")
        self.assertIs(state.audit_network.peek(), NETWORK)

    async def test_saved_list_tab_uses_action_focus_and_mouse_activates_same_row(self):
        view, native = await self.render("saved")
        cursor = state.saved_selected.peek()
        with patch.object(saved, "refresh_saved") as refresh:
            self.feed(view, native, "\t\t\t")
            self.assertIn("› Обновить", view.capture_char_frame())
            self.feed(view, native, "\r")
            refresh.assert_called_once()
            self.assertEqual(state.saved_selected.peek(), cursor)
        self.feed(view, native, "\x1b[Z\x1b[Z\x1b[Z")
        self.assertEqual(state.control_focus.peek()["saved"], "list")
        self.feed(view, native, "\x1b[A")
        self.assertEqual(state.saved_selected.peek(), cursor - 1)
        with patch.object(saved, "open_audit") as open_network:
            label = f"Saved{cursor - 1:02}"
            view.mock_mouse.click(*text_point(view.capture_char_frame(), label))
            open_network.assert_called_once()
            self.assertEqual(open_network.call_args.args[0].ssid, label)

    async def test_file_and_target_regions_tab_enter_and_reverse(self):
        for case, screen, label, target in (
            ("file-picker", "file_picker", "Выбрать файл", forms),
            ("targets", "capture_targets", "Выбрать сеть", controller),
        ):
            with self.subTest(case=case):
                view, native = await self.render(case)
                method = "choose_file" if case == "file-picker" else "choose_capture_target"
                with patch.object(target, method) as choose:
                    self.feed(view, native, "\t")
                    if case == "file-picker":
                        self.assertEqual(state.control_focus.peek()[screen], "list")
                        self.assertNotIn("Действия", view.capture_char_frame())
                    else:
                        self.assertIn("› " + label, view.capture_char_frame())
                    self.feed(view, native, "\r")
                    choose.assert_called_once()
                    self.feed(view, native, "\x1b[Z")
                    self.assertEqual(state.control_focus.peek()[screen], "list")

    async def test_running_log_enter_is_noop_scroll_stays_put_and_stop_is_focused(self):
        view, native = await self.render("running")
        state.run_source.set("board")
        state.run_context.set(NETWORK.label)
        state.current_activity.set("Ожидание рукопожатия")
        view.render_frame()
        self.assertIn("Захват с платы", view.capture_char_frame().splitlines()[0])
        self.assertNotIn("Этап 1/1", view.capture_char_frame())
        self.feed(view, native, "\r\x1b[C")
        self.assertFalse(dialogs.active())
        self.feed(view, native, "\x1b[A")
        before = [line for line in view.capture_char_frame().splitlines() if "fixture log line" in line]
        offset = state.log_scroll.peek()
        state.push_log("fixture added line")
        view.render_frame()
        self.assertEqual(state.log_scroll.peek(), offset + 1)
        self.assertEqual(before, [line for line in view.capture_char_frame().splitlines() if "fixture log line" in line])
        self.feed(view, native, "\x1b[F")
        self.assertEqual(state.log_scroll.peek(), 0)
        self.assertIn("fixture added line", view.capture_char_frame())
        self.feed(view, native, "\t")
        self.assertIn("› Остановить ожидание", view.capture_char_frame())
        with patch.object(controller, "cancel_attack") as cancel:
            self.feed(view, native, "\r")
            self.assertIn("Остановить ожидание?", view.capture_char_frame())
            cancel.assert_not_called()
            self.feed(view, native, "\x1b[C")
            self.assertTrue(dialogs.active())
            cancel.assert_not_called()
            self.feed(view, native, "\t")
            self.assertIn("› Остановить ожидание", view.capture_char_frame())
            self.feed(view, native, "\x1b[Z")
            self.assertIn("› Продолжить ожидание", view.capture_char_frame())
            self.feed(view, native, "\t\r")
            cancel.assert_called_once()
            self.assertFalse(dialogs.active())

    async def test_result_action_focus_retry_and_log_region(self):
        view, native = await self.render("result-failure")
        state.result.set(CrackResult(network=NETWORK, method="захват", error="Захват остановлен",
                                    request=RunRequest(mode="board", options=CrackOptions())))
        view.render_frame()
        self.assertIn("Повторить захват", view.capture_char_frame())
        with patch.object(controller, "retry_result") as retry:
            self.assertIn("› Повторить захват", view.capture_char_frame())
            self.feed(view, native, "\x1b[C")
            retry.assert_not_called()
            self.feed(view, native, "\r")
            retry.assert_called_once_with(state.result.peek())
        actions = result.result_actions()
        for _ in range(len(actions)):
            self.feed(view, native, "\t")
        self.assertEqual(state.control_focus.peek()["result"], "log")
        self.feed(view, native, "\r")
        self.assertFalse(dialogs.active())

    async def test_completed_run_result_redraws_with_session_input(self):
        view, native = await self.render("running")
        completed = CrackResult(
            network=NETWORK, success=True, password="fixture-key",
            method="ключ Windows", log=[f"completed log line {i:02}" for i in range(40)],
        )
        request = RunRequest("file", CrackOptions(), capture_path=str(FIXTURE))
        await asyncio.to_thread(controller._show_completed_result, completed, request)
        view.render_frame()
        self.assertIn("Пароль найден", view.capture_char_frame())
        self.assertIn("› Повторить подбор", view.capture_char_frame())

        self.feed(view, native, "\x1b[B")
        self.assertEqual(state.control_focus.peek()["result"], "action:Параметры")
        self.assertIn("› Параметры", view.capture_char_frame())
        self.feed(view, native, "\x1b[A")
        self.assertIn("› Повторить подбор", view.capture_char_frame())
        self.feed(view, native, "\t")
        self.assertIn("› Параметры", view.capture_char_frame())
        self.feed(view, native, "\x1b[Z")
        self.assertIn("› Повторить подбор", view.capture_char_frame())
        with patch.object(controller, "retry_result") as retry:
            self.feed(view, native, "\r")
            retry.assert_called_once_with(state.result.peek())

        for _ in range(len(result.result_actions())):
            self.feed(view, native, "\t")
        self.assertEqual(state.control_focus.peek()["result"], "log")
        self.assertIn("↑↓ журнал", view.capture_char_frame())
        before = view.capture_char_frame()
        self.feed(view, native, "\x1b[A")
        self.assertEqual(state.log_scroll.peek(), 1)
        self.assertNotEqual(before, view.capture_char_frame())

        self.feed(view, native, "\x1b")
        self.assertEqual(state.phase.peek(), "scan")
        self.assertIn("Сети", view.capture_char_frame().splitlines()[0])


if __name__ == "__main__":
    unittest.main()
