"""Fixture-only interaction and layout regressions for the unified workspace."""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from opentui.structs import display_width
from opentui.testing import test_render

from _test_tui_setup import FIXTURE, choose_command, field_index, native_input
from wifi_tool import cracker, pipeline, profiles
from wifi_tool.models import CrackResult, Network, RunRequest
from wifi_tool.options import CrackOptions
from wifi_tool.ui import commands, controller, controls, dialogs, forms, navigation, state
from wifi_tool.ui.actions import Action
from wifi_tool.ui.app import App
from wifi_tool.ui.screens import result, saved, scan
from wifi_tool.ui.screens import audit
from wifi_tool.ui.screens.crack import _capture_rows
from wifi_tool.ui.widgets import edit_preview, truncate, truncate_middle, wrap

SIZES = ((44, 16), (60, 20), (80, 24), (100, 30), (120, 40), (160, 40))
NETS = [Network(f"Сеть_{i:02}", f"02:00:00:00:00:{i:02x}", 6, 70, "WPA2-Personal", "CCMP")
        for i in range(40)]


class RedesignTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        controller.stop_ticking()
        state.reset()
        state.readiness.set(None)
        state.adapter.set(None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(controller.stop_ticking)
        self.addCleanup(dialogs.clear)
        spawn = patch.object(controller, "_spawn", side_effect=lambda coro: coro.close())
        spawn.start()
        self.addCleanup(spawn.stop)

    async def render(self, width=80, height=24):
        view = await test_render(App, {"width": width, "height": height})
        view.render_frame()
        native = native_input(view)
        self.addCleanup(view.destroy)
        self.addCleanup(native.stop)
        return view, native

    def feed(self, view, native, raw):
        native.feed(raw)
        view.render_frame()

    async def test_search_paste_once_text_cursor_and_empty_state(self):
        state.networks.set(NETS)
        state.selected.set(17)
        view, native = await self.render(44, 16)
        self.feed(view, native, "/\x1b[200~Сеть_17\x1b[201~")
        self.assertEqual(state.scan_query.peek(), "Сеть_17")
        self.assertEqual(state.selected.peek(), 17)
        self.assertIn("Сеть_17", view.capture_char_frame())
        self.feed(view, native, "\x1b[H\x7f")
        self.assertEqual(state.scan_query.peek(), "Сеть_17")
        self.feed(view, native, "\x1b[F/")
        self.assertEqual(state.scan_query.peek(), "Сеть_17/")
        self.assertIn("Нет совпадений", view.capture_char_frame())
        self.assertIsNone(state.selected_network())
        scan.set_query("")
        self.assertEqual(state.selected.peek(), 17)
        self.feed(view, native, "\r")
        self.assertEqual(state.control_focus.peek()["scan"], "list")
        self.feed(view, native, "\x1b[6~")
        self.assertEqual(state.selected.peek(), 17 + controls.list_page("scan"))

    async def test_scan_tab_cycles_only_visible_regions_and_menu_keeps_selection(self):
        state.networks.set(NETS)
        view, native = await self.render()
        self.feed(view, native, "\t")
        self.assertEqual(state.control_focus.peek()["scan"], "search")
        self.feed(view, native, "\t")
        self.assertEqual(state.control_focus.peek()["scan"], "list")
        self.assertIn("› Сеть_00", view.capture_char_frame())
        self.assertNotIn("Действия", view.capture_char_frame())
        selected = state.selected.peek()
        self.feed(view, native, "\x1b[B")
        self.assertEqual(state.selected.peek(), selected + 1)
        selected = state.selected.peek()
        before = state.control_focus.peek()
        self.feed(view, native, "\x1bOP")
        self.feed(view, native, "\x1b[200~nothing matches\x1b[201~")
        self.assertEqual(state.selected.peek(), selected)
        self.assertEqual(state.scan_query.peek(), "")
        self.feed(view, native, "\x1b")
        self.assertEqual(state.control_focus.peek(), before)

    async def test_network_arrows_leave_search_and_scroll_past_first_page(self):
        state.networks.set(NETS)
        view, native = await self.render(44, 16)
        self.feed(view, native, "/\x1b[200~Сеть\x1b[201~")
        self.assertEqual(state.control_focus.peek()["scan"], "search")
        self.feed(view, native, "\x1b[B")
        self.assertEqual(state.control_focus.peek()["scan"], "list")
        self.assertEqual(state.selected.peek(), 1)
        for index in range(2, len(NETS)):
            self.feed(view, native, "\x1b[B")
            self.assertEqual(state.selected.peek(), index)
            self.assertIn(f"› {NETS[index].ssid}", view.capture_char_frame())
        self.assertGreater(state.network_scroll_offset.peek(), 0)
        self.feed(view, native, "/\x1b[5~")
        self.assertEqual(state.control_focus.peek()["scan"], "list")
        self.assertEqual(state.selected.peek(), len(NETS) - 1 - controls.list_page("scan"))
        self.assertEqual(state.scan_query.peek(), "Сеть")

    async def test_network_wheel_scrolls_viewport_and_respects_filter_and_edges(self):
        state.networks.set(NETS)
        view, native = await self.render()
        down, up = "\x1b[<65;5;7M", "\x1b[<64;5;7M"
        self.feed(view, native, down)
        self.assertEqual(state.network_scroll_offset.peek(), 3)
        self.assertNotIn("› Сеть_00", view.capture_char_frame())
        self.assertIn("› Сеть_03", view.capture_char_frame())
        for _ in range(len(NETS)):
            self.feed(view, native, down)
        self.assertEqual(state.network_scroll_offset.peek(), len(NETS) - controls.list_page("scan"))
        self.assertIn("Сеть_39", view.capture_char_frame())
        for _ in range(len(NETS)):
            self.feed(view, native, up)
        self.assertEqual(state.network_scroll_offset.peek(), 0)
        self.assertLess(state.selected.peek(), controls.list_page("scan"))
        self.assertIn(f"› {NETS[state.selected.peek()].ssid}", view.capture_char_frame())

        self.feed(view, native, "/\x1b[200~Сеть_3\x1b[201~")
        self.assertEqual(state.selected.peek(), 30)
        self.feed(view, native, down)
        self.assertEqual(state.control_focus.peek()["scan"], "list")
        self.assertEqual(state.selected.peek(), 32)
        self.assertIn("› Сеть_32", view.capture_char_frame())
        self.feed(view, native, "\x1b[F")
        self.assertEqual(state.selected.peek(), 39)
        self.assertIn("› Сеть_39", view.capture_char_frame())
        self.feed(view, native, "/\x1b[200~no matches\x1b[201~")
        self.feed(view, native, down)
        self.assertEqual(state.selected.peek(), -1)
        self.assertIn("Нет совпадений", view.capture_char_frame())

    async def test_network_wheel_does_not_leak_through_a_dialog(self):
        state.networks.set(NETS)
        view, native = await self.render()
        dialogs.open_select("Сохранённые захваты", [Action(f"Сеть_{i:02}", lambda: None)
                                                   for i in range(40)])
        view.render_frame()
        self.feed(view, native, "\x1b[<65;10;8M")
        self.assertEqual(dialogs.stack.peek()[-1].selected, 3)
        self.assertEqual(state.selected.peek(), 0)
        self.assertEqual(state.network_scroll_offset.peek(), 0)
        self.feed(view, native, "\x1b[<65;2;7M")
        self.assertEqual(dialogs.stack.peek()[-1].selected, 3)
        self.assertEqual(state.selected.peek(), 0)
        self.assertEqual(state.network_scroll_offset.peek(), 0)
        self.feed(view, native, "\x1b[<64;10;8M")
        self.assertEqual(dialogs.stack.peek()[-1].selected, 0)

    async def test_modal_search_has_text_editing_without_leaking_to_network_list(self):
        state.networks.set(NETS)
        state.selected.set(9)
        view, native = await self.render()
        dialogs.open_select("Команды fixture", [Action("alpha", lambda: None), Action("beta", lambda: None)])
        view.render_frame()
        self.feed(view, native, "\x1b[200~ALPHA\x1b[201~")
        self.feed(view, native, "\x1b[H\x1b[3~\x1b[C\x7f\x1b[FX")
        self.assertEqual(dialogs.stack.peek()[-1].query, "PHAX")
        self.assertEqual(state.scan_query.peek(), "")
        self.assertEqual(state.selected.peek(), 9)
        self.feed(view, native, "\x1b")
        self.assertFalse(dialogs.active())

    async def test_refresh_and_back_restore_network_identity_and_focus(self):
        state.networks.set(NETS)
        state.selected.set(31)
        state.network_scroll_offset.set(25)
        controls.set_focus("scan", "search")
        scan.set_query("Сеть")
        navigation.push("audit")
        reordered = [replace(net, signal=95) for net in reversed(NETS)]
        with patch.object(pipeline, "scan_networks", AsyncMock(return_value=reordered)):
            await controller.start_scan()
        navigation.back()
        self.assertEqual(state.network_identity(state.selected_network()), state.network_identity(NETS[31]))
        self.assertEqual(state.scan_query.peek(), "Сеть")
        self.assertEqual(state.control_focus.peek()["scan"], "search")

    async def test_resize_keeps_selected_row_visible_at_every_requested_size(self):
        state.networks.set(NETS)
        state.selected.set(39)
        view, native = await self.render()
        for width, height in SIZES:
            with self.subTest(width=width, height=height):
                view.resize(width, height)
                view.render_frame()
                frame = view.capture_char_frame()
                self.assertIn("› Сеть_39", frame)
                self.assertIn("Enter отчёт", frame.splitlines()[-1])
                self.assertNotIn("F1 меню", frame)
                self.assertNotIn("Действия", frame)
                self.assertTrue(all(display_width(line) <= width for line in frame.splitlines()))
                self.assertEqual(state.selected.peek(), 39)

    async def test_background_readiness_can_disable_action_without_moving_focus(self):
        state.phase.set("audit")
        state.audit_network.set(NETS[0])
        state.audit_has_key.set(False)
        state.readiness.set(pipeline.Readiness(admin=True, backend=SimpleNamespace(), iface=SimpleNamespace()))
        controls.set_focus("audit", "action:Захват адаптером")
        view, native = await self.render()
        self.assertIn("› Захват адаптером", view.capture_char_frame())
        state.readiness.set(pipeline.Readiness(admin=True, capture_problem="Драйвер недоступен"))
        view.render_frame()
        self.assertIn("› × Захват адаптером", view.capture_char_frame())
        self.assertEqual(state.control_focus.peek()["audit"], "action:Захват адаптером")
        with patch.object(audit, "_capture_only") as capture:
            self.feed(view, native, "\r")
            capture.assert_not_called()
        self.feed(view, native, "\t")
        self.assertIn("› Параметры", view.capture_char_frame())
        self.feed(view, native, "\t")
        self.assertIn("› Подробности сети", view.capture_char_frame())

    async def test_long_cyrillic_and_cjk_rows_keep_columns_separate(self):
        name = "Домашняя网络_очень_длинное_имя_сети"
        state.networks.set([replace(NETS[0], ssid=name, signal=88), replace(NETS[1], ssid="Соседняя_5G")])
        for width, height in SIZES:
            view, native = await self.render(width, height)
            frame = view.capture_char_frame()
            first = next(line for line in frame.splitlines() if "› Домашняя" in line)
            self.assertIn("88%", first)
            self.assertNotIn("Соседняя_5G", first)
            self.assertIn("Соседняя_5G", frame)
            self.assertTrue(all(display_width(line) <= width for line in frame.splitlines()))
            native.stop()
            view.destroy()

    async def test_scan_loading_empty_no_matches_and_error_fit(self):
        for width, height in SIZES:
            for mode in ("loading", "empty", "search", "error"):
                with self.subTest(width=width, height=height, mode=mode):
                    state.reset()
                    state.adapter.set(None)
                    state.scanning.set(mode == "loading")
                    state.scan_error.set("Нет доступа к Wi-Fi. Проверьте разрешение в Windows и повторите поиск." if mode == "error" else "")
                    if mode == "search":
                        state.networks.set(NETS)
                        scan.set_query("несуществующая сеть")
                    view, native = await self.render(width, height)
                    frame = view.capture_char_frame()
                    expected = {"loading": "Сканирую эфир", "empty": "Сети не найдены",
                                "search": "Нет совпадений", "error": "Сканирование недоступно"}[mode]
                    self.assertIn(expected, frame)
                    self.assertIn("Enter отчёт", frame.splitlines()[-1])
                    self.assertNotIn("F1 меню", frame)
                    self.assertTrue(all(display_width(line) <= width for line in frame.splitlines()))
                    native.stop()
                    view.destroy()

    async def test_parameters_disclosure_inline_error_and_anchored_start(self):
        forms.open_form(capture=str(FIXTURE))
        self.assertNotIn("rules", [row[0] for row in forms.fields()])
        view, native = await self.render(44, 16)
        forms.focus(field_index("advanced"))
        self.feed(view, native, "\r")
        self.assertIn("rules", [row[0] for row in forms.fields()])
        forms.set_value("runtime", "invalid")
        forms.focus(field_index("runtime"))
        view.render_frame()
        frame = view.capture_char_frame()
        self.assertIn("Лимит, сек", frame)
        self.assertIn("! Лимит времени", frame)
        self.assertIn("Начать подбор", frame)
        forms.focus(len(forms.fields()) - 1)
        self.feed(view, native, "\r")
        self.assertEqual(state.phase.peek(), "crack_form")
        with patch.object(forms, "start_problem", return_value=""), patch.object(forms, "submit") as submit:
            self.feed(view, native, "\r")
            submit.assert_called_once()

    async def test_tab_reaches_start_and_launches_once_at_all_requested_sizes(self):
        for width, height in SIZES:
            forms.open_form(capture=str(FIXTURE))
            forms.set_value("mode", "mask")
            view, native = await self.render(width, height)
            count = len(forms.fields()) - state.form_focus.peek() - 1
            self.feed(view, native, "\t" * count)
            self.assertEqual(forms.fields()[state.form_focus.peek()][0], "start")
            self.assertIn("Enter  Начать подбор", view.capture_char_frame())
            with patch.object(forms, "submit") as submit:
                self.feed(view, native, "\r")
                submit.assert_called_once()
            native.stop()
            view.destroy()

    async def test_component_install_and_saved_profile_errors_offer_next_step(self):
        forms.open_form(capture=str(FIXTURE))
        with patch("wifi_tool.installer.install_all", AsyncMock(side_effect=OSError("fixture connection failed"))):
            await controller._install(None)
        self.assertEqual(state.install_state.peek(), "idle")
        self.assertIn("Повторите установку через F1", state.form_error.peek())
        state.phase.set("saved")
        with patch.object(profiles, "read_all", side_effect=OSError("fixture profile unavailable")):
            await controller._load_saved()
        view, native = await self.render(44, 16)
        self.assertIn("Не удалось прочитать профили", view.capture_char_frame())
        self.assertIn("Обновить", view.capture_char_frame())

    async def test_readiness_recovery_updates_launch_without_stale_cached_error(self):
        state.readiness.set(pipeline.Readiness(admin=True, capture_problem="fixture driver unavailable"))
        forms.open_form(NETS[0])
        forms.set_value("mode", "mask")
        self.assertIn("fixture driver unavailable", forms.start_problem())
        forms.focus(field_index("mask"))
        view, native = await self.render()
        focus = state.form_focus.peek()
        state.readiness.set(pipeline.Readiness(admin=True, hashcat=FIXTURE,
                            backend=SimpleNamespace(needs_channel=False), iface=SimpleNamespace()))
        view.render_frame()
        self.assertEqual(forms.start_problem(), "")
        self.assertEqual(state.form_error.peek(), "")
        self.assertEqual(state.form_focus.peek(), focus)

    async def test_known_missing_hashcat_blocks_file_launch_before_operation(self):
        forms.open_form(capture=str(FIXTURE))
        forms.set_value("mode", "mask")
        state.readiness.set(pipeline.Readiness())
        self.assertIn("hashcat не найден", forms.start_problem())
        forms.focus(len(forms.fields()) - 1)
        view, native = await self.render(44, 16)
        with patch.object(forms, "submit") as submit:
            self.feed(view, native, "\r")
            submit.assert_not_called()
        self.assertEqual(state.phase.peek(), "crack_form")

    async def test_capture_progress_uses_original_request_duration(self):
        request = RunRequest("capture", CrackOptions(), capture_seconds=120)
        with patch.object(controller, "probe_readiness", AsyncMock(return_value=pipeline.Readiness())), \
                patch.object(pipeline, "obtain_hashes", AsyncMock(side_effect=pipeline.PipelineError("fixture"))):
            await controller.run_capture_only(NETS[0], request=request)
        self.assertEqual(state.capture_total.peek(), 120)
        self.assertIn("50.0%", _capture_rows(40, 60, 0, False)[1].content)

    async def test_empty_historical_log_does_not_show_unrelated_live_messages(self):
        state.phase.set("result")
        state.result.set(CrackResult(NETS[0], error="fixture", log=[]))
        state.log.set(["unrelated message"])
        view, native = await self.render()
        self.assertNotIn("unrelated message", view.capture_char_frame())
        self.assertIn("Пока пусто", view.capture_char_frame())

    async def test_help_and_picker_keep_form_text_cursor_and_expansion(self):
        forms.open_form(capture=str(FIXTURE))
        forms.set_value("mode", "mask")
        forms.set_value("mask", "Пример?d?d")
        forms.focus(field_index("mask"))
        state.form_cursor.set(3)
        state.form_advanced.set(True)
        view, native = await self.render()
        values = dict(state.form_values.peek())
        forms.open_help()
        view.render_frame()
        self.feed(view, native, "\x1b")
        self.assertEqual(state.form_values.peek(), values)
        self.assertEqual(state.form_cursor.peek(), 3)
        self.assertTrue(state.form_advanced.peek())
        forms.open_picker_for("capture")
        view.render_frame()
        self.feed(view, native, "\x1b")
        self.assertEqual(state.form_values.peek(), values)
        self.assertEqual(state.form_cursor.peek(), 3)

    async def test_secret_hidden_in_verdict_and_historical_log_until_explicit_action(self):
        secret = "секрет with spaces:123"
        state.phase.set("result")
        state.result.set(CrackResult(NETS[0], password=secret, success=True,
                                    log=["Historical: " + secret]))
        state.log.set(["unrelated live log"])
        view, native = await self.render()
        frame = view.capture_char_frame()
        self.assertNotIn(secret, frame)
        self.assertIn("Historical: [скрыто]", frame)
        choose_command(view, "Показать пароль", native=native)
        self.assertIn(secret, view.capture_char_frame())
        self.assertIn("› Скрыть пароль", view.capture_char_frame())
        self.feed(view, native, "\r")
        self.assertNotIn(secret, view.capture_char_frame())
        result._toggle_password()
        forms.open_help()
        view.render_frame()
        self.feed(view, native, "\x1b")
        self.assertNotIn(secret, view.capture_char_frame())
        self.assertIn("› Показать пароль", view.capture_char_frame())

    async def test_saved_secret_hidden_and_profile_identity_survives_refresh(self):
        state.phase.set("saved")
        items = [profiles.SavedProfile("Одна", "WPA2-Personal", key="first-secret"),
                 profiles.SavedProfile("Другая", "WPA2-Personal", key="selected-secret")]
        state.saved.set(items)
        state.saved_selected.set(1)
        view, native = await self.render()
        self.assertNotIn("selected-secret", view.capture_char_frame())
        choose_command(view, "Показать ключ", native=native)
        self.assertIn("selected-secret", view.capture_char_frame())
        self.feed(view, native, "\r")
        self.assertNotIn("selected-secret", view.capture_char_frame())
        with patch.object(profiles, "read_all", return_value=list(reversed(items))):
            await controller._load_saved()
        self.assertEqual(saved._selected_profile().name, "Другая")

    async def test_scroll_freezes_tail_through_bounded_buffer_then_end_resumes(self):
        state.phase.set("crack")
        state.cracking_network.set(NETS[0])
        state.log.set([f"line {i:03}" for i in range(399)])
        view, native = await self.render(44, 16)
        self.feed(view, native, "\x1b[5~")
        visible = [line for line in view.capture_char_frame().splitlines() if "line " in line]
        for i in range(399, 404):
            state.push_log(f"line {i:03}")
            view.render_frame()
        self.assertEqual(visible, [line for line in view.capture_char_frame().splitlines() if "line " in line])
        self.assertIn("пауза", view.capture_char_frame())
        self.feed(view, native, "\x1b[F")
        self.assertIn("line 403", view.capture_char_frame())
        self.assertIn("слежение", view.capture_char_frame())

    async def test_real_status_current_stage_and_stopping_survive_compact_layout(self):
        state.phase.set("crack")
        state.cracking_network.set(NETS[0])
        controller.begin_run("saved", "capture", "convert", "crack")
        controller._on_phase("crack")
        controller._on_stage(2, 6, "RockYou WPA")
        controller._on_status(cracker.HashStatus(progress=42.5, candidates="1000", speed="684 kH/s", eta="1м 20с"))
        view, native = await self.render(44, 16)
        frame = view.capture_char_frame()
        self.assertIn("42.5%", frame)
        self.assertIn("684 kH/s", frame)
        self.assertIn("ETA ~1м 20с", frame)
        self.feed(view, native, "\x1b")
        self.assertTrue(dialogs.active())
        self.feed(view, native, "\t\r")
        self.assertTrue(state.cancelled.peek())
        self.assertIn("Остановка…", view.capture_char_frame())

    def test_cell_width_wrapping_truncation_and_path_cursor(self):
        self.assertEqual(edit_preview("тест", 2, 10), "те|ст")
        value = "Домашняя网络_длинное_имя_сети"
        for width in (1, 4, 8, 20, 36):
            self.assertLessEqual(display_width(truncate(value, width)), width)
            self.assertLessEqual(display_width(truncate_middle(value, width)), width)
            self.assertTrue(all(display_width(line) <= width for line in wrap(value + " " + value, width)))
            self.assertLessEqual(display_width(edit_preview(value, 12, width)), width)


if __name__ == "__main__":
    unittest.main()
