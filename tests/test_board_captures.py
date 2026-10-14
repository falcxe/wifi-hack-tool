"""Stored capture browsing, exact binary transfers and serial lease cleanup."""
from __future__ import annotations

import asyncio
from collections import deque
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

os.environ["WIFI_TOOL_NO_BOARD"] = "1"

from opentui.testing import test_render
from .test_tui_setup import choose_command, native_input
from wifi_tool import bruce
from wifi_tool.ui import board_captures, commands, controller, dialogs, state
from wifi_tool.ui.app import App

FIXTURE = Path(__file__).parent / "fixtures" / "wpa2_psk_12345678.pcapng"


class SerialBytes:
    def __init__(self, chunks):
        self.chunks = deque(chunks)
        self.written = []

    def reset_input_buffer(self):
        pass

    def write(self, data):
        self.written.append(data)

    def flush(self):
        pass

    def read(self, size):
        return self.chunks.popleft() if self.chunks else b""


class BinaryTransferTests(unittest.TestCase):
    def test_saved_filename_is_detected_without_waiting_for_done(self):
        board = bruce.Board(bruce.BoardInfo("fixture"))
        board._serial = SerialBytes([b"handshake: HS_AABBCCDDEEFF_Fixture.pcap\r\n"])
        self.assertIn("HS_AABBCCDDEEFF", board._run_until_capture_ends("fixture", timeout=0.02))

    def test_command_rejection_and_stopped_prompt_end_wait_immediately(self):
        for reply in (b"Command not found\r\n# ", b"capture stopped by host\r\n# "):
            with self.subTest(reply=reply):
                board = bruce.Board(bruce.BoardInfo("fixture"))
                board._serial = SerialBytes([reply])
                with self.assertRaises(bruce.BoardCommandError) as error:
                    board._run_until_capture_ends("fixture", timeout=90)
                self.assertIn(reply.decode().splitlines()[0], str(error.exception))

    def test_wait_ready_consumes_fragmented_prompt_without_sending_or_discarding(self):
        board = bruce.Board(bruce.BoardInfo("fixture"))
        port = SerialBytes([b"capture finished\r\n", b"#", b" "])
        board._serial = port
        with patch.object(port, "reset_input_buffer") as discard:
            self.assertTrue(board.wait_ready(timeout=0.02))
        discard.assert_not_called()
        self.assertFalse(port.written)

    def test_existing_local_capture_is_refreshed_and_preserved_if_transfer_fails(self):
        data = FIXTURE.read_bytes()
        board = bruce.Board(bruce.BoardInfo("fixture"))
        entry = bruce.RemoteFile("fixture.pcapng", "/fixture.pcapng", len(data))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            path = destination / entry.name
            path.write_bytes(b"outdated local file")
            with patch.object(board, "read_file", return_value=data) as read:
                self.assertEqual(board.pull_capture(entry, destination), path)
            read.assert_called_once_with(entry.path, timeout=bruce.DEFAULT_TIMEOUT, size=len(data))
            self.assertEqual(path.read_bytes(), data)
            with patch.object(board, "read_file", side_effect=bruce.BoardError("fixture failure")):
                with self.assertRaises(bruce.BoardError):
                    board.pull_capture(entry, destination)
            self.assertEqual(path.read_bytes(), data)

    def test_binary_end_marker_and_trailing_newlines_are_preserved(self):
        payload = b"\xd4\xc3\xb2\xa1" + b"A" * 10 + b"\nEND 7\r\n# " + b"Z" * 20 + b"\r\n"
        header = f"COMMAND: storage stream /fixture.pcap\r\nSTREAM {len(payload)}\r\n".encode()
        serial = SerialBytes([header[:20], header[20:] + payload[:26], payload[26:] + b"\nEND 1\n# "])
        board = bruce.Board(bruce.BoardInfo("fixture"))
        board._serial = serial
        self.assertEqual(board.read_file("/fixture.pcap", size=len(payload)), payload)
        self.assertEqual(serial.written, [b"storage stream /fixture.pcap\r\n"])

    def test_truncated_transfer_is_reported_instead_of_saved(self):
        board = bruce.Board(bruce.BoardInfo("fixture"))
        board._serial = SerialBytes([b"STREAM 100\r\n\xd4\xc3\xb2\xa1"])
        with patch.object(bruce.time, "monotonic", side_effect=[0, 0, 100]):
            with self.assertRaisesRegex(bruce.BoardError, "4 из 100"):
                board.read_file("/fixture.pcap", size=100)

    def test_listing_failure_is_not_an_empty_capture_directory(self):
        board = bruce.Board(bruce.BoardInfo("fixture"))
        with patch.object(board, "send", side_effect=bruce.BoardError("fixture read error")):
            with self.assertRaisesRegex(bruce.BoardError, "fixture read error"):
                board.captures_present()


class StoredCaptureTests(unittest.TestCase):
    def test_existing_files_are_refreshed_and_all_networks_are_listed(self):
        data = FIXTURE.read_bytes()
        entries = [bruce.RemoteFile(f"HS_{mac}_{name}.pcapng", f"/captures/{name}.pcapng", len(data))
                   for mac, name in (("001122334455", "First_Network"), ("aabbccddeeff", "Second_Network"))]
        board = Mock()
        board.captures_present.return_value = entries
        board.read_file.return_value = data
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            (destination / entries[0].name).write_bytes(b"old local copy")
            records = board_captures.read_stored_captures(board, destination)
            self.assertEqual(len(records), 2)
            for record in records:
                self.assertFalse(record.error)
                self.assertGreater(record.report.eapol_frames, 0)
                self.assertGreater(len(record.report.eapol), 0)
                self.assertEqual(record.path.read_bytes(), data)
                self.assertIn("EAPOL", record.label)
            self.assertIn("Second_Network", records[1].label)
            self.assertEqual(board.read_file.call_count, 2)
            board.start_capture.assert_not_called()
            board.start_sniffer.assert_not_called()

    def test_failed_download_keeps_existing_file_and_does_not_hide_other_captures(self):
        data = FIXTURE.read_bytes()
        board = Mock()
        board.captures_present.return_value = [
            bruce.RemoteFile("first.pcapng", "/first.pcapng", len(data)),
            bruce.RemoteFile("second.pcapng", "/second.pcapng", len(data)),
        ]
        board.read_file.side_effect = [bruce.BoardError("fixture transfer failed"), data]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            existing = destination / "first.pcapng"
            existing.write_bytes(b"keep original")
            records = board_captures.read_stored_captures(board, destination)
            self.assertEqual(records[0].error, "fixture transfer failed")
            self.assertEqual(existing.read_bytes(), b"keep original")
            self.assertTrue(records[1].report.ok)


class BoardBrowserTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        state.reset()
        state.board.set("COM fixture")
        self.addCleanup(state.reset)
        self.addCleanup(dialogs.clear)
        self.addCleanup(controller.stop_ticking)
        self.previous_busy = controller._board_busy
        controller._board_busy = False
        self.addCleanup(setattr, controller, "_board_busy", self.previous_busy)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.board = Mock()
        data = FIXTURE.read_bytes()
        self.board.captures_present.return_value = [bruce.RemoteFile("HS_001122334455_Fixture.pcapng", "/fixture.pcapng", len(data))]
        self.board.read_file.return_value = data
        for context in (
            patch.object(controller, "_open_board_blocking", return_value=self.board),
            patch.object(board_captures, "ensure_captures_dir", return_value=Path(self.temp.name)),
        ):
            context.start()
            self.addCleanup(context.stop)
        self.release = patch.object(controller, "_release_board")
        self.released = self.release.start()
        self.addCleanup(self.release.stop)

    async def test_native_menu_lists_capture_counts_then_opens_chosen_file(self):
        view = await test_render(App, {"width": 80, "height": 24})
        native = native_input(view)
        self.addCleanup(view.destroy)
        self.addCleanup(native.stop)
        pending = []
        with patch.object(controller, "_spawn", side_effect=lambda coro: pending.append(asyncio.create_task(coro))):
            choose_command(view, "Захваты с платы", native=native)
            self.assertIn("Читаю сохранённые захваты", view.capture_char_frame())
            await pending[0]
            view.render_frame()
            self.assertIn("Захваты с платы (1)", view.capture_char_frame())
            self.assertIn("Fixture · EAPOL", view.capture_char_frame())
            native.feed("\r")
            view.render_frame()
            self.assertIn("Пар EAPOL", view.capture_char_frame())
            native.feed("\r")
            view.render_frame()
            self.assertEqual(state.phase.peek(), "crack_form")
            self.assertEqual(state.form_values.peek()["capture"], str(Path(self.temp.name) / "HS_001122334455_Fixture.pcapng"))
            self.board.start_capture.assert_not_called()
            self.board.start_sniffer.assert_not_called()
            self.released.assert_called_once_with(self.board)
            self.assertFalse(controller._board_busy)
            await asyncio.gather(*pending)

    async def test_dismissed_loading_dialog_does_not_reopen(self):
        pending = []
        with patch.object(controller, "_spawn", side_effect=lambda coro: pending.append(asyncio.create_task(coro))):
            board_captures.browse()
            dialogs.clear()
            await pending[0]
        self.assertFalse(dialogs.active())
        self.released.assert_called_once_with(self.board)

    async def test_cancellation_waits_for_reader_to_release_port(self):
        reading, finish = threading.Event(), threading.Event()
        def blocked_read(*args, **kwargs):
            reading.set()
            finish.wait(timeout=2)
            return FIXTURE.read_bytes()
        self.board.read_file.side_effect = blocked_read
        pending = []
        with patch.object(controller, "_spawn", side_effect=lambda coro: pending.append(asyncio.create_task(coro))):
            board_captures.browse()
            self.assertTrue(await asyncio.to_thread(reading.wait, 1))
            pending[0].cancel()
            await asyncio.sleep(.01)
            self.assertTrue(controller._board_busy)
            self.released.assert_not_called()
            finish.set()
            with self.assertRaises(asyncio.CancelledError):
                await pending[0]
        self.released.assert_called_once_with(self.board)
        self.assertFalse(controller._board_busy)

    def test_stored_capture_browser_is_not_offered_during_a_run(self):
        state.phase.set("crack")
        self.assertNotIn("Захваты с платы", [action.label for action in commands.available()])


class CaptureRequestTests(unittest.TestCase):
    """What the board is asked to do, and what it cannot do.

    The board is an ESP32, so it has no 5 GHz radio at all. Asked for channel 48
    it does not fail -- the firmware prints "Error changing channel" on every
    burst and deauths an empty band for the whole window, which from the host
    looks exactly like a network that will not hand over a client. Refusing
    here is what turns five wasted minutes into a sentence that names the
    reason.
    """

    def board(self):
        board = bruce.Board(bruce.BoardInfo(port="COM5", description="CH9102"))
        # A serial line that records what it was told to say and answers with a
        # capture the firmware would have written, so the test is about the
        # command that goes out and not about the read loop.
        board._serial = SerialBytes([b"capture file ready: returning to console\n"
                                     b"Done. Check /BrucePCAP/handshakes\n"])
        return board

    def test_a_5ghz_channel_is_refused_with_a_reason(self):
        board = self.board()
        with self.assertRaises(bruce.BoardError) as caught:
            board.start_capture("10:a3:b8:3a:c1:ba", 48, ssid="RT-5WiFi-317")
        message = str(caught.exception)
        self.assertIn("5 ГГц", message)
        self.assertIn("монитора", message)

    def test_a_24ghz_channel_is_accepted(self):
        board = self.board()
        board.start_capture("10:a3:b8:3a:c1:b9", 4, ssid="RT-WiFi-317", timeout=2.0)
        self.assertIn(b"-channel 4", b"".join(board._serial.written))
        self.assertIn(b"-mac 10:A3:B8:3A:C1:B9", b"".join(board._serial.written))

    def test_an_unknown_channel_is_still_refused(self):
        with self.assertRaises(bruce.BoardError):
            self.board().start_capture("10:a3:b8:3a:c1:b9", 0)

    def test_a_malformed_bssid_never_reaches_the_board(self):
        board = self.board()
        with self.assertRaises(bruce.BoardError):
            board.start_capture("10:a3:b8", 4)
        self.assertEqual(board._serial.written, [], "a bad address was sent anyway")


class DeviceTallyTests(unittest.TestCase):
    """How many devices the board has heard, and what that means for the wait.

    Both numbers answer one question from different sides: is anyone on this
    network to knock over? The board counts stations, the host counts EAPOL
    messages, and a capture with neither is waiting on nobody.
    """

    def parsed(self, chunks):
        seen = []
        board = bruce.Board(bruce.BoardInfo(port="COM5"))
        # The board's own "the file is written" line ends the capture; without it
        # the read waits out the timeout and fails, which is not what is under
        # test here.
        board._serial = SerialBytes(list(chunks) + [
            b"capture file ready: returning to console\n"
            b"Done. Check /BrucePCAP/handshakes\n"])
        board.start_capture("10:a3:b8:3a:c1:b9", 4, ssid="RT-WiFi-317", timeout=2.0,
                            on_clients=lambda devices, eapol: seen.append((devices, eapol)))
        return seen

    def test_the_status_line_is_read_into_numbers(self):
        seen = self.parsed([b"clients=4 eapol=12 msg1=1\n"])
        self.assertEqual(seen[-1], (4, 12))

    def test_a_quiet_capture_reports_zero_rather_than_nothing(self):
        self.assertEqual(self.parsed([b"clients=0 eapol=0 msg1=0\n"])[-1], (0, 0))

    def test_chatter_that_is_not_the_status_line_is_left_alone(self):
        seen = self.parsed([b"Preparing deauth frame to AP -> 10:A3:B8:3A:C1:B9\n"])
        self.assertEqual(seen, [])

    def test_the_latest_reading_wins(self):
        seen = self.parsed([b"clients=1 eapol=2 msg1=1\nclients=1 eapol=6 msg1=1\n"])
        self.assertEqual(seen[-1], (1, 6))


if __name__ == "__main__":
    unittest.main()
