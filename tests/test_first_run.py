"""The first-run screen: choice, readiness wording, and what each choice opens.

Written against the promise the screen makes out loud -- *pick one of three,
understand whether it will work, know what happens next*. Each test below is
one clause of that promise, because a first-run screen that fails any of them
is worse than no screen: a wrong first click costs a beginner the whole tool.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from opentui.structs import display_width
from opentui.testing import test_render

from wifi_tool import first_run, pipeline
from wifi_tool.scanner import AdapterInfo
from wifi_tool.ui import controller, navigation, plain, state
from wifi_tool.ui.app import App
from wifi_tool.ui.screens import start

ROOT = Path(__file__).resolve().parent.parent

#: A machine where everything works: rights held, adapter present, tools and
#: dictionary installed. The happy path has to be boring.
READY_OK = pipeline.Readiness(
    admin=True,
    adapter=AdapterInfo("Wi-Fi", "Intel(R) Wi-Fi 6E AX211", "b0:47", "connected"),
    hashcat=ROOT / "assets" / "hashcat-7.1.2" / "hashcat.exe",
    wordlist=ROOT / "assets" / "rockyou-wpa.txt",
    backend=SimpleNamespace(exe=ROOT / "assets" / "tshark.exe"),
    iface=SimpleNamespace(index=3, name="\\Device\\NPF_{Wi-Fi}"),
)

#: A laptop with the built-in Intel card: rights held, tools installed, and an
#: adapter whose driver cannot record the air. The most common real machine.
READY_NO_CAPTURE = pipeline.Readiness(
    admin=True,
    adapter=AdapterInfo("Wi-Fi", "Intel(R) Wi-Fi 6E AX211", "b0:47", "connected"),
    hashcat=ROOT / "assets" / "hashcat-7.1.2" / "hashcat.exe",
    wordlist=ROOT / "assets" / "rockyou-wpa.txt",
    backend=SimpleNamespace(exe=ROOT / "assets" / "tshark.exe"),
    iface=SimpleNamespace(index=3, name="\\Device\\NPF_{Wi-Fi}"),
    capture_problem="Текущий драйвер не поддерживает режим монитора",
    problems=["Текущий драйвер не поддерживает режим монитора"],
)

#: Nothing installed, nothing permitted. A clone run from the README by someone
#: who skipped a step.
READY_EMPTY = pipeline.Readiness()


def ready_with_problem(problem: str) -> pipeline.Readiness:
    r = pipeline.Readiness(
        admin=True,
        adapter=READY_OK.adapter,
        hashcat=READY_OK.hashcat,
        wordlist=READY_OK.wordlist,
        backend=READY_OK.backend,
        iface=READY_OK.iface,
    )
    r.capture_problem = problem
    r.problems.append(problem)
    return r


class PlainWordingTests(unittest.TestCase):
    """The wording itself: plain where it is read, exact where it is looked up."""

    def test_user_facing_lines_carry_no_tool_names(self):
        """No jargon in the lines a first-time user has to act on.

        Every row of every scenario is checked, not a sample: the jargon tends
        to come back in whichever row nobody re-reads.
        """
        offenders = []
        for ready in (READY_OK, READY_NO_CAPTURE, READY_EMPTY, None):
            for scenario in first_run.SCENARIOS:
                for fact in plain.facts(ready, scenario, board=None):
                    for word in (fact.title, fact.status, fact.todo,
                                 plain.headline(ready, scenario),
                                 plain.next_step(ready, scenario)):
                        lowered = word.casefold()
                        for banned in plain.JARGON:
                            if banned in lowered:
                                offenders.append(f"{scenario}/{fact.title}: {banned} in {word!r}")
        self.assertEqual(offenders, [], "технические термины в тексте для пользователя")

    def test_a_missing_component_always_says_what_to_press(self):
        for scenario in first_run.SCENARIOS:
            for fact in plain.facts(READY_EMPTY, scenario):
                if not fact.ok and not fact.optional:
                    self.assertTrue(fact.todo, f"{fact.title} без подсказки")

    def test_an_optional_component_never_blocks_the_scenario(self):
        """The board is a second route, not a requirement.

        Without this, a laptop whose own adapter can capture is told it is not
        ready -- which is the kind of false alarm that makes people distrust
        the whole checklist.
        """
        facts = plain.facts(READY_OK, "network", board=None)
        board = next(f for f in facts if "M5StickC" in f.title)
        self.assertFalse(board.ok)
        self.assertTrue(board.optional)
        self.assertFalse(plain.blocked_for(READY_OK, "network"))
        self.assertEqual(plain.headline(READY_OK, "network"), "Готово. Можно начинать.")
        # With capture impossible the same row becomes the way forward.
        self.assertIn("M5StickC", [f.title for f in plain.facts(READY_NO_CAPTURE, "network")])

    def test_a_capture_blocker_says_which_way_to_go_instead(self):
        headline = plain.headline(READY_NO_CAPTURE, "network")
        self.assertIn("готовый файл", headline.casefold())
        self.assertTrue(plain.blocked_for(READY_NO_CAPTURE, "network"))
        self.assertFalse(plain.blocked_for(READY_NO_CAPTURE, "file"))

    def test_the_file_scenario_never_mentions_live_capture(self):
        """A user who has a file must not be asked about adapters.

        The rows that block the file scenario are only the two that a file
        really needs; anything about the air is noise on that screen.
        """
        titles = [f.title for f in plain.facts(READY_EMPTY, "file")]
        self.assertEqual(titles, ["Программа подбора", "Список частых паролей"])
        self.assertNotIn("Захват в эфире", titles)

    def test_technical_details_keep_the_exact_names_and_paths(self):
        """The plain half must not have swallowed the useful half."""
        ready = ready_with_problem("Npcap: поддержка raw 802.11 выключена")
        lines = plain.technical_lines(ready)
        joined = "\n".join(lines)
        self.assertIn("Npcap: поддержка raw 802.11 выключена", joined)
        self.assertIn("hashcat.exe", joined)
        self.assertIn("rockyou-wpa.txt", joined)
        self.assertIn("tshark.exe", joined)
        self.assertIn("NPF_{Wi-Fi}", joined)

    def test_every_component_state_is_reachable_in_plain_words(self):
        """A first-time user must never meet a state with no explanation.

        Each of these is a machine that really happens; before, each produced a
        blank or a raw driver string on the first screen.
        """
        cases = {
            "admin": pipeline.Readiness(admin=False),
            "no_adapter": pipeline.Readiness(admin=True),
            "no_backend": pipeline.Readiness(admin=True, adapter=READY_OK.adapter),
            "driver": ready_with_problem("драйвер не поддерживает режим монитора"),
            "empty": READY_EMPTY,
        }
        for name, ready in cases.items():
            fact = plain.capture_fact(ready)
            self.assertTrue(fact.status, f"{name}: пустой статус")
            self.assertTrue(fact.todo, f"{name}: нет что делать")
            self.assertNotIn("None", fact.status)
            self.assertTrue(plain.headline(ready, "network"))
            self.assertTrue(plain.next_step(ready, "network"))

    def test_a_probe_still_running_says_so_instead_of_guessing(self):
        self.assertEqual(plain.headline(None, "network"), "Проверяю компьютер…")
        self.assertIn("Подождите", plain.next_step(None, "network"))


class ScenarioChoiceTests(unittest.IsolatedAsyncioTestCase):
    """The screen itself: three rows, one verdict, a route per choice."""

    def setUp(self):
        spawn = patch.object(controller, "_spawn", side_effect=lambda coro: coro.close())
        spawn.start()
        self.addCleanup(spawn.stop)
        state.reset()
        state.readiness.set(READY_OK)
        navigation.reset()
        state.phase.set("start")

    async def render(self, width=100, height=30):
        setup = await test_render(App, {"width": width, "height": height})
        setup.render_frame()
        self.addCleanup(setup.destroy)
        return setup

    # --- what is on screen ------------------------------------------------

    async def test_three_named_scenarios_are_visible_at_every_size(self):
        for width, height in ((60, 20), (80, 24), (100, 30), (120, 40)):
            state.start_details.set(False)
            setup = await self.render(width, height)
            frame = setup.capture_char_frame()
            lines = frame.splitlines()
            self.assertIn("С чего начать", lines[0], f"{width}x{height}: ушёл заголовок")
            self.assertLessEqual(len(lines), height, f"{width}x{height}: экран выше окна")
            for title in plain.TITLES.values():
                self.assertIn(title, frame, f"{width}x{height}: нет «{title}»")
            for line in lines:
                self.assertLessEqual(display_width(line), width,
                                     f"{width}x{height}: строка шире окна")
            setup.destroy()

    async def test_the_verdict_is_present_and_never_truncated_away(self):
        """The checklist must not push its own conclusion off the screen.

        The verdict is the only line that answers "can I do this at all", so it
        is the one line the layout refuses to clip -- everything above it yields.
        """
        for ready in (READY_OK, READY_NO_CAPTURE, READY_EMPTY):
            state.readiness.set(ready)
            for scenario in first_run.SCENARIOS:
                state.scenario_index.set(start.SCENARIOS.index(scenario))
                setup = await self.render(60, 20)
                frame = setup.capture_char_frame()
                self.assertIn(plain.headline(ready, scenario).split("—")[0].strip()[:20],
                              frame, f"{scenario}: вердикт не виден")
                setup.destroy()

    async def test_a_blocked_machine_says_what_to_do_not_just_that_it_is_blocked(self):
        state.readiness.set(READY_NO_CAPTURE)
        setup = await self.render(100, 30)
        frame = setup.capture_char_frame()
        self.assertIn("Что делать:", frame)
        self.assertIn("Подключите адаптер", frame)
        # The driver sentence belongs in the technical section only.
        self.assertNotIn("режим монитора", frame)

    async def test_technical_details_are_hidden_until_asked_for(self):
        state.readiness.set(READY_NO_CAPTURE)
        closed = (await self.render(100, 30)).capture_char_frame()
        self.assertNotIn("NPF_{Wi-Fi}", closed)
        self.assertIn("[+] Раскрыть", closed)
        state.start_details.set(True)
        opened = (await self.render(100, 30)).capture_char_frame()
        self.assertIn("[−] Скрыть", opened)
        self.assertIn("NPF_{Wi-Fi}", opened)
        self.assertIn("режим монитора", opened)

    async def test_arrow_keys_move_the_choice_and_the_checklist_follows(self):
        setup = await self.render(100, 30)
        self.assertIn("Проверка компьютера · Проверить свою сеть", setup.capture_char_frame())
        setup.mock_input.press_key("down")
        setup.render_frame()
        self.assertEqual(state.scenario_index.peek(), 1)
        self.assertIn("Проверка компьютера · Разобрать готовый файл",
                      setup.capture_char_frame())
        setup.mock_input.press_key("down")
        setup.render_frame()
        self.assertIn("Проверка компьютера · Найти сохранённый пароль",
                      setup.capture_char_frame())
        # And back up: a choice is not one-way.
        setup.mock_input.press_key("up")
        setup.render_frame()
        self.assertEqual(state.scenario_index.peek(), 1)

    async def test_the_key_bar_names_the_three_keys_that_work(self):
        frame = (await self.render(100, 30)).capture_char_frame()
        last = frame.splitlines()[-1]
        for key in ("↑↓", "Enter", "Tab", "F1"):
            self.assertIn(key, last)

    async def test_the_command_menu_offers_the_way_out(self):
        """Esc from a screen with no Back must lead somewhere.

        Someone who picked the wrong scenario needs to get back, and "press Esc"
        has to open something, not close the app by accident.
        """
        setup = await self.render(100, 30)
        setup.mock_input.press_key("f1")
        setup.render_frame()
        labels = [item.label for item in __import__(
            "wifi_tool.ui.dialogs", fromlist=["stack"]).filtered()]
        self.assertIn("Пропустить и открыть список сетей", labels)
        self.assertIn("С чего начать", "".join(labels) + "с чего начать")

    # --- what each choice does --------------------------------------------

    async def test_choosing_a_network_opens_the_list_and_explains_the_next_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {first_run.ENV_STATE_DIR: tmp}):
                controller.start_scenario("network")
                self.assertEqual(state.phase.peek(), "scan")
                self.assertIn("Enter", state.scan_notice.peek())
                self.assertEqual(first_run.chosen_scenario(), "network")

    async def test_choosing_a_file_opens_the_picker_without_asking_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {first_run.ENV_STATE_DIR: tmp}), \
                    patch.object(controller, "pick_capture_file") as picker:
                controller.start_scenario("file")
                picker.assert_called_once()
                # Not the welcome screen any more, and the answer is stored.
                self.assertNotEqual(state.phase.peek(), "start")
                self.assertEqual(first_run.chosen_scenario(), "file")

    async def test_choosing_saved_keys_opens_the_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {first_run.ENV_STATE_DIR: tmp}):
                controller.start_scenario("saved")
                self.assertEqual(state.phase.peek(), "saved")
                self.assertEqual(first_run.chosen_scenario(), "saved")

    async def test_an_unknown_scenario_key_falls_back_instead_of_crashing(self):
        """The key can come from a file, a command line or a future version."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {first_run.ENV_STATE_DIR: tmp}):
                controller.start_scenario("нет-такого")
                self.assertEqual(first_run.chosen_scenario(), "network")

    async def test_skipping_is_remembered_too(self):
        """Otherwise "skip" means the same three questions on every launch."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {first_run.ENV_STATE_DIR: tmp}):
                controller.skip_start()
                self.assertFalse(first_run.is_first_run())
                self.assertEqual(state.phase.peek(), "scan")

    async def test_the_welcome_screen_is_reachable_again_from_the_list(self):
        from wifi_tool.ui import commands

        state.phase.set("scan")
        labels = [item.label for item in commands.available()]
        self.assertIn("С чего начать", labels)
        controller.open_start()
        self.assertEqual(state.phase.peek(), "start")


class BootTests(unittest.TestCase):
    """Which screen a launch lands on, and what a bad settings file does."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.dict("os.environ", {first_run.ENV_STATE_DIR: self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _boot_phase(self) -> str:
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            controller.boot()
        return state.phase.peek()

    def test_a_fresh_machine_gets_the_choices(self):
        self.assertTrue(first_run.is_first_run())
        self.assertEqual(self._boot_phase(), "start")

    def test_a_machine_that_answered_goes_straight_to_the_list(self):
        first_run.remember("network")
        self.assertFalse(first_run.is_first_run())
        self.assertEqual(self._boot_phase(), "scan")

    def test_a_corrupt_settings_file_asks_again_rather_than_failing(self):
        first_run.settings_file().parent.mkdir(parents=True, exist_ok=True)
        first_run.settings_file().write_text("{не json", encoding="utf-8")
        self.assertTrue(first_run.is_first_run())
        self.assertEqual(self._boot_phase(), "start")

    def test_a_settings_file_naming_an_unknown_scenario_asks_again(self):
        first_run.save({"scenario": "из будущей версии"})
        self.assertTrue(first_run.is_first_run())

    def test_the_command_line_can_answer_the_question_for_ever(self):
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            controller.boot(scenario="saved")
        self.assertEqual(state.phase.peek(), "saved")
        self.assertEqual(first_run.chosen_scenario(), "saved")
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            controller.boot()
        self.assertEqual(state.phase.peek(), "saved")

    def test_no_welcome_starts_on_the_list_without_asking_again(self):
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            controller.boot(welcome=False)
        self.assertEqual(state.phase.peek(), "scan")
        # ... and the choice was not stored, so the next bare launch still asks.
        self.assertTrue(first_run.is_first_run())

    def test_the_first_launch_does_not_scan_before_the_choice(self):
        """Twenty seconds of radio time nobody asked for yet."""
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            with patch.object(controller, "start_scan") as scan:
                controller.boot()
                scan.assert_not_called()
            with patch.object(controller, "start_scan") as scan:
                controller.boot(welcome=False)
                scan.assert_not_called()  # spawned by bootstrap, not here


if __name__ == "__main__":
    unittest.main()