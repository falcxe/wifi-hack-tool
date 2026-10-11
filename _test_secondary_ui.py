"""Safe layout fixtures for every secondary screen; no hardware or subprocesses."""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["WIFI_TOOL_NO_BOARD"] = "1"

from opentui.structs import display_width
from opentui.testing import test_render

from wifi_tool import pipeline, profiles
from wifi_tool.models import CrackResult, Network
from wifi_tool.ui import controller, dialogs, forms, state
from wifi_tool.ui.actions import Action
from wifi_tool.ui.app import App
from wifi_tool.ui.screens.crack import _capture_rows

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "tests" / "fixtures" / "wpa2_psk_12345678.pcapng"
SIZES = ((44, 16), (52, 18), (60, 20), (80, 24), (100, 30), (120, 40), (160, 40))
NETWORK = Network("Home Wi-Fi", "aa:bb:cc:dd:ee:ff", 6, 80, "WPA2-Personal", "CCMP")


def setup_case(case: str, directory: Path) -> tuple[str, str]:
    """Return the expected title and primary action for a deterministic fixture."""
    state.reset()
    state.readiness.set(None)
    state.saved.set([])
    state.saved_loading.set(False)
    if case == "board-audit":
        setup_case("audit", directory)
        state.board.set("fixture board")
        return "Проверка сети", "Захват с платы"
    if case == "board-wait":
        setup_case("running", directory)
        state.run_source.set("board")
        state.run_context.set(NETWORK.label)
        state.board_deadline.set(time.monotonic() + 171)
        state.current_activity.set("Ожидание рукопожатия")
        state.status.set("Переподключите Wi-Fi на своём устройстве")
        state.run_stages.set([("board", "current")])
        state.log.set(["[плата] Ожидание рукопожатия…", "[плата] 14с · тестовые данные"])
        return "Захват с платы", "Остановить ожидание"
    if case == "audit":
        state.phase.set("audit")
        state.audit_network.set(NETWORK)
        state.audit_has_key.set(False)
        state.readiness.set(pipeline.Readiness(admin=True, capture_problem="Нет режима монитора"))
        return "Проверка сети", "Выбрать файл захвата"
    if case.startswith("saved"):
        state.phase.set("saved")
        if case == "saved-loading":
            state.saved_loading.set(True)
        elif case == "saved":
            state.saved.set([profiles.SavedProfile(f"Saved{i:02}", "WPA2-Personal", key="fixture-key")
                             for i in range(40)])
            state.saved_selected.set(39)
        return "Сохранённые сети", "Открыть сеть"
    if case.startswith("form"):
        forms.open_form(capture=str(FIXTURE) if case != "form-empty" else "")
        if case == "form":
            forms.set_value("mode", "custom")
            forms.set_value("wordlist", str(ROOT / "assets" / "wordlist.txt"))
            forms.set_value("rules", True)
            forms.focus(len(forms.fields()) - 1)
        elif case == "form-install":
            state.install_state.set("working")
            state.install_progress.set("Проверка загрузки…")
            state.log.set([f"fixture install line {i}" for i in range(40)])
        return "Параметры", "" if case == "form-install" else "Начать подбор"
    if case.startswith("running"):
        state.phase.set("crack")
        state.cracking_network.set(NETWORK)
        state.log.set([f"fixture log line {i}" for i in range(40)])
        state.elapsed.set(17)
        if case == "running-capture":
            state.capture_left.set(controller.CAPTURE_SECONDS // 2)
            state.capture_bytes.set(128000)
            return "Захват", "Остановить"
        state.run_stages.set([("saved", "done"), ("capture", "done"),
                              ("convert", "done"), ("quick", "done"),
                              ("crack", "current"), ("mask", "pending")])
        state.current_activity.set("crack")
        state.progress.set(42.5)
        state.status.set("Проверка вариантов…")
        return "Подбор", "Остановить"
    if case.startswith("result"):
        state.phase.set("result")
        if case != "result-empty":
            state.result.set(CrackResult(
                network=NETWORK, success=case == "result-success",
                password="fixture password with spaces and Unicode тест" if case == "result-success" else "",
                error="Файл не содержит пригодных данных WPA2. " * 4 if case == "result-failure" else "",
                method="Словарь", elapsed=17,
                log=[f"fixture result line {i}" for i in range(40)],
            ))
        return "Результат", ("Показать пароль" if case == "result-success" else
                             "Файл захвата" if case == "result-failure" else "К списку сетей")
    if case == "file-picker":
        state.phase.set("file_picker")
        state.file_directory.set(str(directory))
        state.file_entries.set([directory / f"capture{i:02}.pcapng" for i in range(40)])
        state.file_selected.set(39)
        state.file_error.set("")
        return "Выбор файла", "Выбрать файл"
    if case == "targets":
        state.phase.set("capture_targets")
        state.capture_targets.set([Network(f"Target{i:02}", f"02:00:00:00:00:{i:02x}")
                                   for i in range(40)])
        state.capture_selected.set(39)
        return "Сеть из файла", "Выбрать сеть"
    if case == "help":
        state.phase.set("method_help")
        state.help_scroll.set(0)
        return "Справка", ""
    raise ValueError(case)


CASES = ("audit", "board-audit", "board-wait", "saved", "saved-empty", "saved-loading", "form", "form-empty",
         "form-install", "running", "running-capture", "result-success",
         "result-failure", "result-empty", "file-picker", "targets", "help")


class SecondaryLayoutTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(controller.stop_ticking)
        self.addCleanup(dialogs.clear)

    async def test_every_secondary_state_fits_and_keeps_its_action(self):
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            for case in CASES:
                for width, height in SIZES:
                    with self.subTest(case=case, width=width, height=height):
                        title, action = setup_case(case, self.directory)
                        rendered = await test_render(App, {"width": width, "height": height})
                        try:
                            rendered.render_frame()
                            frame = rendered.capture_char_frame()
                            lines = frame.splitlines()
                            self.assertIn(title, lines[0])
                            self.assertLessEqual(len(lines), height)
                            self.assertTrue(all(display_width(line) <= width for line in lines))
                            self.assertNotIn("F1 меню", frame)
                            self.assertTrue(lines[-1].strip())
                            if action and case != "file-picker":
                                self.assertIn(action, frame)
                            if case == "board-wait":
                                self.assertIn(NETWORK.label, frame)
                                self.assertNotIn("Этап 1/1", frame)
                                self.assertNotIn("Файл захвата", frame)
                            if case == "board-audit":
                                self.assertEqual(frame.count("Захват с платы"), 1)
                            if case == "saved":
                                self.assertIn("Saved39", frame)
                            if case == "file-picker":
                                self.assertIn("capture39", frame)
                                self.assertNotIn("Действия", frame)
                                self.assertIn("Enter выбор", lines[-1])
                            self.assertNotIn("Действия", frame)
                            self.assertNotIn("Основное", frame)
                            self.assertNotIn("Переходы", frame)
                            if case == "targets":
                                self.assertIn("Target39", frame)
                        finally:
                            rendered.destroy()

    async def test_dialogs_fit_search_and_confirmation_in_compact_terminals(self):
        for searchable in (False, True):
            for width, height in SIZES:
                with self.subTest(searchable=searchable, width=width, height=height):
                    setup_case("audit", self.directory)
                    dialogs.open_select("Команды", [Action(f"Действие {i:02}", lambda: None)
                                                    for i in range(20)],
                                        selected=19, searchable=searchable)
                    rendered = await test_render(App, {"width": width, "height": height})
                    try:
                        rendered.render_frame()
                        frame = rendered.capture_char_frame()
                        self.assertIn("Действие 19", frame)
                        self.assertIn("Enter выбрать", frame)
                        self.assertTrue(all(display_width(line) <= width for line in frame.splitlines()))
                        if searchable:
                            dialogs.set_query("no matching fixture")
                            rendered.render_frame()
                            self.assertIn("Ничего не найдено", rendered.capture_char_frame())
                    finally:
                        rendered.destroy()

    def test_capture_progress_uses_percent(self):
        rows = _capture_rows(40, controller.CAPTURE_SECONDS // 2, 0, False)
        self.assertIn("50.0%", rows[1].content)

    async def test_file_picker_keeps_distinct_long_basenames(self):
        for width, height in SIZES[:2]:
            with self.subTest(width=width, height=height):
                setup_case("file-picker", self.directory)
                state.file_entries.set([
                    self.directory / "wpa3_transition_wpa3client_24ghz.pcapng",
                    self.directory / "wpa3_transition_wpa3client_5ghz.pcapng",
                ])
                state.file_selected.set(0)
                rendered = await test_render(App, {"width": width, "height": height})
                try:
                    rendered.render_frame()
                    frame = rendered.capture_char_frame()
                    self.assertIn("24ghz.pcapng", frame)
                    self.assertIn("5ghz.pcapng", frame)
                    names = [line.strip() for line in frame.splitlines() if "ghz.pcapng" in line]
                    self.assertEqual(len(set(names)), 2)
                finally:
                    rendered.destroy()

    def test_file_readiness_omits_hardware_and_mask_omits_dictionary(self):
        from wifi_tool.ui.screens.crack_form import _check_rows

        forms.open_form(capture=str(FIXTURE))
        ready = pipeline.Readiness(admin=False)
        self.assertEqual([row[1] for row in _check_rows(ready)], ["hashcat", "словарь"])
        forms.set_value("mode", "mask")
        self.assertEqual([row[1] for row in _check_rows(ready)], ["hashcat"])


if __name__ == "__main__":
    unittest.main()
