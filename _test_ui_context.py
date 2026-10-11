"""Operation context and board UI lifecycle, using a stub device only."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from wifi_tool import bruce
from wifi_tool.models import CrackResult, Network, RunRequest
from wifi_tool.options import CrackOptions
from wifi_tool.ui import controller, state


NETWORK = Network("Context fixture", "aa:bb:cc:dd:ee:ff", 6, 80, "WPA2-Personal", "CCMP")


def discard_task(coro):
    coro.close()


def remote_entry(name):
    """A capture sitting on the board, shaped the way the driver reports it."""
    entry = Mock()
    entry.name = name
    entry.path = "/BrucePCAP/handshakes/" + name
    entry.is_dir = False
    entry.size = 2048
    return entry


class ContextTests(unittest.TestCase):
    def setUp(self):
        controller.stop_ticking()
        state.reset()
        state.phase.set("audit")
        state.audit_network.set(NETWORK)
        self.addCleanup(controller.stop_ticking)

    def test_board_view_is_immediate_and_repeated_enter_does_not_spawn_twice(self):
        with patch.object(controller, "_spawn", side_effect=discard_task) as spawn:
            controller.start_board_capture()
            self.assertEqual(state.phase.peek(), "crack")
            self.assertEqual(state.run_source.peek(), "board")
            self.assertEqual(state.run_context.peek(), NETWORK.label)
            self.assertIs(state.cracking_network.peek(), NETWORK)
            self.assertEqual(state.current_activity.peek(), "Подключение к плате")
            controller.start_board_capture()
        spawn.assert_called_once()

    def test_file_entry_clears_previous_board_target_and_capture_data(self):
        state.run_source.set("board")
        state.run_context.set("old network")
        state.cracking_network.set(NETWORK)
        state.board_deadline.set(99999999)
        state.capture_found.set("old handshake")
        state.cancelled.set(True)
        with patch.object(controller, "_spawn", side_effect=discard_task):
            controller.open_capture(Path("capture fixture.pcapng"))
        self.assertEqual(state.run_source.peek(), "file")
        self.assertEqual(state.run_context.peek(), "capture fixture.pcapng")
        self.assertIsNone(state.cracking_network.peek())
        self.assertIsNone(state.board_deadline.peek())
        self.assertEqual(state.capture_found.peek(), "")
        self.assertFalse(state.cancelled.peek())

    def test_live_entry_resets_run_focus_and_stale_capture_status(self):
        state.control_focus.set({"audit": "parameters", "crack": "stop"})
        state.board_deadline.set(999)
        state.capture_left.set(20)
        state.capture_found.set("old data")
        controller._select(NETWORK)
        self.assertEqual(state.run_source.peek(), "live")
        self.assertEqual(state.run_context.peek(), NETWORK.label)
        self.assertIsNone(state.board_deadline.peek())
        self.assertIsNone(state.capture_left.peek())
        self.assertEqual(state.capture_found.peek(), "")
        self.assertNotIn("crack", state.control_focus.peek())
        self.assertEqual(state.control_focus.peek()["audit"], "parameters")

    def test_board_retry_preserves_operation_and_target(self):
        result = CrackResult(network=NETWORK, method="захват",
                             request=RunRequest("board", CrackOptions()))
        with patch.object(controller, "start_board_capture") as board, \
                patch.object(controller, "start_auto_attack") as auto, \
                patch.object(controller, "begin_capture_for") as live:
            controller.retry_result(result)
        board.assert_called_once_with(NETWORK)
        auto.assert_not_called()
        live.assert_not_called()

    def test_board_without_target_does_not_reuse_previous_report_network(self):
        state.phase.set("scan")
        controller._prepare_board_view()
        self.assertIsNone(state.cracking_network.peek())
        self.assertEqual(state.run_context.peek(), "Плата M5StickC")
        controller._board_failure("fixture unavailable")
        self.assertIsNot(state.result.peek().network, NETWORK)

    def test_reset_clears_focus_context_and_deadline(self):
        state.control_focus.set({"audit": "parameters"})
        state.run_source.set("board")
        state.run_context.set(NETWORK.label)
        state.board_deadline.set(999)
        state.reset()
        self.assertEqual(state.control_focus.peek(), {})
        self.assertEqual(state.run_source.peek(), "")
        self.assertEqual(state.run_context.peek(), "")
        self.assertIsNone(state.board_deadline.peek())

    def test_opening_new_network_starts_at_default_action(self):
        state.phase.set("scan")
        state.control_focus.set({"audit": "action:Параметры"})
        state.audit_has_key.set(True)
        with patch.object(controller, "_spawn", side_effect=discard_task):
            controller.open_audit(NETWORK)
        self.assertEqual(state.phase.peek(), "audit")
        self.assertNotIn("audit", state.control_focus.peek())
        self.assertIsNone(state.audit_has_key.peek())


class AuditContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_late_key_lookup_does_not_change_another_network_report(self):
        state.reset()
        self.addCleanup(state.reset)
        state.audit_network.set(NETWORK)
        async def late_lookup(_function, _ssid):
            state.audit_network.set(Network("Another fixture", "11:22:33:44:55:66"))
            state.audit_has_key.set(False)
            return "old fixture key"
        with patch.object(controller.asyncio, "to_thread", side_effect=late_lookup):
            await controller._check_audit_key(NETWORK)
        self.assertFalse(state.audit_has_key.peek())


class BoardLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        controller.stop_ticking()
        state.reset()
        state.phase.set("audit")
        state.audit_network.set(NETWORK)
        controller._prepare_board_view()
        self.addCleanup(controller.stop_ticking)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.board = Mock()
        # The board driver returns the capture list, so an empty one is "none
        # waiting", not a truthiness flag.
        self.board.captures_present.return_value = []
        self.board.pull_capture.return_value = None
        self.board.pull_captures.return_value = []
        for target, value in (("wifi_tool.options.ensure_captures_dir", self.directory),
                              ("wifi_tool.ui.controller._open_board_blocking", self.board)):
            context = patch(target, return_value=value)
            context.start()
            self.addCleanup(context.stop)
        release_patch = patch.object(controller, "_release_board")
        self.release = release_patch.start()
        self.addCleanup(release_patch.stop)

    async def test_missing_device_releases_port_and_returns_capture_result(self):
        state.elapsed.set(3.5)
        with patch.object(controller, "_open_board_blocking", return_value=None):
            await controller._board_capture_run()
        self.release.assert_called_once_with(None)
        self.assertEqual(state.phase.peek(), "result")
        result = state.result.peek()
        self.assertIs(result.network, NETWORK)
        self.assertEqual(result.method, "захват")
        self.assertEqual(result.request.mode, "board")
        self.assertEqual(result.elapsed, 3.5)
        self.assertIsNone(state.board_deadline.peek())
        self.assertFalse(controller._board_busy)

    async def test_connection_exception_clears_busy_state(self):
        with patch.object(controller, "_open_board_blocking", side_effect=bruce.BoardError("fixture busy")):
            await controller._board_capture_run()
        self.assertFalse(controller._board_busy)
        self.assertIn("fixture busy", state.result.peek().error)

    async def test_saved_file_is_read_only_after_capture_stop_and_ready_prompt(self):
        capture = self.directory / "fixture.pcapng"
        capture.write_bytes(b"fixture")
        self.board.captures_present.side_effect = [[], [], [remote_entry("fixture.pcapng")]]
        self.board.start_capture.return_value = "handshake saved"
        self.board.pull_capture.return_value = capture
        with patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        names = [call[0] for call in self.board.method_calls]
        self.assertLess(names.index("stop_capture"), names.index("wait_ready"))
        self.assertLess(names.index("wait_ready"), names.index("captures_present", 2))
        next_run.assert_called_once_with(capture, automatic=True)

    async def test_unresponsive_capture_is_reported_without_querying_busy_console(self):
        self.board.start_capture.return_value = "handshake saved"
        self.board.wait_ready.return_value = False
        with patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        self.assertEqual(self.board.captures_present.call_count, 2)
        self.assertEqual(self.board.start_capture.call_count, 1)
        self.board.pull_capture.assert_not_called()
        next_run.assert_not_called()
        self.assertEqual(state.phase.peek(), "result")
        self.assertIn("останов", state.result.peek().error)
        self.assertFalse(controller._board_busy)
        self.release.assert_called_once_with(self.board)

    async def test_rejected_capture_command_is_not_retried_until_deadline(self):
        self.board.start_capture.side_effect = bruce.BoardCommandError("Command not found")
        with patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        self.assertEqual(self.board.start_capture.call_count, 1)
        self.board.wait_ready.assert_not_called()
        self.board.pull_capture.assert_not_called()
        next_run.assert_not_called()
        self.assertIn("Command not found", state.result.peek().error)
        self.assertFalse(controller._board_busy)

    async def test_new_capture_for_another_bssid_does_not_replace_requested_target(self):
        target = Network("Requested fixture", "aa:bb:cc:dd:ee:ff", 6, 80, "WPA2-Personal", "CCMP")
        other = bruce.RemoteFile("HS_001122334455_Other.pcap", "/other.pcap", 1000)
        wanted = bruce.RemoteFile("HS_AABBCCDDEEFF_Requested.pcap", "/wanted.pcap", 1000)
        state.cracking_network.set(target)
        self.board.captures_present.side_effect = [[], [], [other], [other, wanted]]
        self.board.start_capture.return_value = "Done. Check /BrucePCAP/handshakes"
        capture = self.directory / wanted.name
        capture.write_bytes(b"fixture")
        self.board.pull_capture.return_value = capture
        with patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        self.board.pull_capture.assert_called_once_with(wanted, self.directory)
        next_run.assert_called_once_with(capture, automatic=True)

    async def test_cancel_during_connection_never_starts_device_capture(self):
        state.cancelled.set(True)
        await controller._board_capture_run()
        self.board.start_sniffer.assert_not_called()
        self.board.pull_captures.assert_not_called()
        self.release.assert_called_once_with(self.board)
        self.assertEqual(state.result.peek().error, "Ожидание остановлено")
        self.assertFalse(state.cancelled.peek())

    async def test_cancel_during_device_query_never_starts_capture(self):
        def cancel_query():
            state.cancelled.set(True)
            return []
        self.board.captures_present.side_effect = cancel_query
        await controller._board_capture_run()
        self.board.start_sniffer.assert_not_called()
        self.board.pull_captures.assert_not_called()
        self.release.assert_called_once_with(self.board)
        self.assertEqual(state.result.peek().error, "Ожидание остановлено")

    async def test_wait_publishes_deadline_and_cancel_does_not_read_or_start_next_task(self):
        calls = []

        def query():
            calls.append(1)
            if len(calls) < 3:      # what was on the board, then the pre-flight
                return []
            self.assertIsNotNone(state.board_deadline.peek())
            self.assertEqual(state.run_context.peek(), NETWORK.label)
            # The PC commands the board to capture for this target, so the screen
            # says the board is deauthing -- not the old "do it on the stick".
            self.assertEqual(state.status.peek(),
                             "Ждём переподключения клиента и запись файла")
            state.cancelled.set(True)
            return []

        self.board.captures_present.side_effect = query
        with patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        # The sniffer is a different route entirely; this one never starts it.
        self.board.start_sniffer.assert_not_called()
        self.board.pull_captures.assert_not_called()
        next_run.assert_not_called()
        self.assertEqual(state.result.peek().error, "Ожидание остановлено")
        self.assertIsNone(state.board_deadline.peek())
        self.release.assert_called_once_with(self.board)

    async def test_cancel_while_reading_does_not_start_a_file_job(self):
        capture = self.directory / "fixture.pcapng"
        capture.write_bytes(b"fixture")
        # Nothing on the board at first, the capture appears on the next poll.
        # Listed once to remember what was there, once by the pre-flight check
        # for a handshake this run could use instead of asking for a new one,
        # and once by the poll itself.
        self.board.captures_present.side_effect = [
            [], [], [remote_entry("fixture.pcapng")]]
        def pull(_entry, _directory):
            state.cancelled.set(True)
            return capture
        self.board.pull_capture.side_effect = pull
        with patch.object(controller.asyncio, "sleep", AsyncMock()), \
                patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        next_run.assert_not_called()
        self.assertEqual(state.result.peek().error, "Ожидание остановлено")
        self.release.assert_called_once_with(self.board)

    async def test_received_file_enters_existing_file_route_with_clean_context(self):
        capture = self.directory / "fixture.pcapng"
        capture.write_bytes(b"fixture")
        self.board.captures_present.side_effect = [
            [], [], [remote_entry("fixture.pcapng")]]
        self.board.pull_capture.return_value = capture
        with patch.object(controller.asyncio, "sleep", AsyncMock()), \
                patch.object(controller, "_spawn", side_effect=discard_task):
            await controller._board_capture_run()
        self.assertEqual(state.phase.peek(), "crack")
        self.assertEqual(state.run_source.peek(), "file")
        self.assertEqual(state.run_context.peek(), capture.name)
        self.assertIsNone(state.board_deadline.peek())
        self.assertIsNone(state.cracking_network.peek())
        self.release.assert_called_once_with(self.board)

    async def test_a_capture_already_on_the_board_is_not_taken_as_this_run(self):
        """A file left by an earlier run must not be mistaken for the new one."""
        self.board.captures_present.return_value = [remote_entry("old.pcapng")]
        with patch.object(controller, "BOARD_LISTEN_SECONDS", 0.03), \
                patch.object(controller.asyncio, "sleep", AsyncMock()), \
                patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        self.assertGreaterEqual(self.board.captures_present.call_count, 2)
        self.board.pull_capture.assert_not_called()
        next_run.assert_not_called()
        # The board was asked, repeatedly, and never had one for this network.
        self.assertIn("рукопожатия не поймано", state.result.peek().error)

    async def test_a_board_handshake_for_this_network_is_used_despite_being_older(self):
        """The firmware names captures after the access point they are for.

        So a file already on the board whose BSSID is the one being worked on is
        a handshake for it, caught minutes ago rather than seconds. Refusing
        every file that predates this run is what left the board holding a
        handshake and the program reporting that the network gave nothing up.
        """
        entry = remote_entry("HS_089AC7E75166_MTS_GPON_A3E2.pcap")
        entry.bssid = "089ac7e75166"
        capture = self.directory / entry.name
        capture.write_bytes(b"fixture")
        # The run is for that access point, spelled the way the scan spells it.
        state.cracking_network.set(
            Network("MTS_GPON_A3E2", "08:9A:C7:E7:51:66", 9, 80, "WPA2-Personal", "CCMP"))
        self.board.captures_present.return_value = [entry]
        self.board.pull_capture.return_value = capture
        with patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        self.board.pull_capture.assert_called_once_with(entry, self.directory)
        next_run.assert_called_once_with(capture, automatic=True)
        self.assertIn("уже есть хэндшейк", "\n".join(state.log.peek()))

    async def test_the_board_is_asked_between_capture_rounds_not_only_at_the_end(self):
        """The firmware writes the file on capture but keeps deauthing.

        Waiting for it to declare itself done means a handshake written in the
        first seconds is only looked for minutes later. The board has to be
        asked between rounds -- and a round that runs out of time has to be cut
        short with the token the firmware watches for, or the question is asked
        while the board is still shouting deauths and the answer comes back
        unreadable. A round the board ended on its own needs no token.
        """
        target = Network("MTS_GPON_A3E2", "08:9A:C7:E7:51:66", 9, 80, "WPA2-Personal", "CCMP")
        state.cracking_network.set(target)
        entry = remote_entry("HS_089AC7E75166_MTS_GPON_A3E2.pcap")
        entry.bssid = "089ac7e75166"
        capture = self.directory / entry.name
        capture.write_bytes(b"fixture")
        # Nothing there when the run starts; the capture appears on the first
        # check between rounds. The capture command runs out of time, which is
        # what leaves the firmware looping.
        self.board.captures_present.side_effect = [[], [], [entry]]
        self.board.start_capture.side_effect = bruce.BoardError("не закончила за отведённое время")
        self.board.pull_capture.return_value = capture
        with patch.object(controller, "BOARD_LISTEN_SECONDS", 5.0), \
                patch.object(controller, "BOARD_CAPTURE_ROUND", 0.05), \
                patch.object(controller.asyncio, "sleep", AsyncMock()), \
                patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        # Asked at least three times: before the run, the pre-flight, and after
        # the first round -- without the round check the last one never happens.
        self.assertGreaterEqual(self.board.captures_present.call_count, 3)
        self.board.stop_capture.assert_called()
        next_run.assert_called_once_with(capture, automatic=True)
        self.assertIn("получен", "\n".join(state.log.peek()))

    async def test_a_board_that_finishes_on_its_own_is_not_cut_off(self):
        """Ending the command cleanly means the board is idle; a token would be noise."""
        target = Network("MTS_GPON_A3E2", "08:9A:C7:E7:51:66", 9, 80, "WPA2-Personal", "CCMP")
        state.cracking_network.set(target)
        entry = remote_entry("HS_089AC7E75166_MTS_GPON_A3E2.pcap")
        entry.bssid = "089ac7e75166"
        capture = self.directory / entry.name
        capture.write_bytes(b"fixture")
        self.board.captures_present.side_effect = [[], [], [entry]]
        self.board.start_capture.return_value = "Done. Check /BrucePCAP/handshakes"
        self.board.pull_capture.return_value = capture
        with patch.object(controller, "BOARD_LISTEN_SECONDS", 5.0), \
                patch.object(controller, "BOARD_CAPTURE_ROUND", 0.05), \
                patch.object(controller.asyncio, "sleep", AsyncMock()), \
                patch.object(controller, "open_capture"):
            await controller._board_capture_run()
        self.board.stop_capture.assert_not_called()

    async def test_a_board_capture_for_another_network_is_left_alone(self):
        other = remote_entry("HS_001122334455_SomeOther.pcap")
        other.bssid = "001122334455"
        state.cracking_network.set(
            Network("MTS_GPON_A3E2", "08:9A:C7:E7:51:66", 9, 80, "WPA2-Personal", "CCMP"))
        self.board.captures_present.return_value = [other]
        with patch.object(controller, "BOARD_LISTEN_SECONDS", 0.05), \
                patch.object(controller, "BOARD_CAPTURE_ROUND", 0.05), \
                patch.object(controller, "open_capture") as next_run:
            await controller._board_capture_run()
        self.board.pull_capture.assert_not_called()
        next_run.assert_not_called()
        self.assertIn("ни одного для этой сети", "\n".join(state.log.peek()))

    async def test_device_error_returns_report_and_releases_device(self):
        self.board.captures_present.side_effect = bruce.BoardError("fixture unavailable")
        with patch.object(controller, "BOARD_LISTEN_SECONDS", 0.05), \
                patch.object(controller, "BOARD_CAPTURE_ROUND", 0.05):
            await controller._board_capture_run()
        self.assertEqual(state.phase.peek(), "result")
        self.assertIn("fixture unavailable", state.result.peek().error)
        self.assertEqual(state.result.peek().method, "захват")
        self.release.assert_called_once_with(self.board)


if __name__ == "__main__":
    unittest.main()
