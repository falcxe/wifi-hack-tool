"""Regression tests for review findings, using synthetic data and local processes."""
from __future__ import annotations

import asyncio
import ctypes
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from wifi_tool import assets, capturer, converter, hc22000, pipeline, profiles
from wifi_tool.models import CrackResult, Network
from wifi_tool.options import CrackOptions
from wifi_tool.ui import controller, state
from wifi_tool.ui.screens import result as result_screen
from . import test_hc22000 as frames
from opentui.testing import test_render
from wifi_tool.ui.app import App


@unittest.skipUnless(os.name == "nt", "Windows elevation")
class ElevationTests(unittest.TestCase):
    def test_terminal_launch_preserves_original_working_directory(self):
        with patch.dict(os.environ, {"WT_SESSION": "fixture"}), \
                patch.object(sys, "argv", ["main.py", "--runtime", "17"]), \
                patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=33) as launch:
            self.assertTrue(assets.relaunch_elevated())
        command = launch.call_args.args
        self.assertEqual(command[2], "wt.exe")
        self.assertIn(subprocess.list2cmdline(["-d", str(Path.cwd())]), command[3])
        self.assertTrue(command[3].endswith(subprocess.list2cmdline([
            sys.executable, str(Path("main.py").resolve()), "--runtime", "17"])))

    def test_missing_terminal_falls_back_to_interpreter(self):
        with patch.dict(os.environ, {"WT_SESSION": "fixture"}), \
                patch.object(sys, "argv", ["main.py"]), \
                patch.object(ctypes.windll.shell32, "ShellExecuteW", side_effect=[2, 33]) as launch:
            self.assertTrue(assets.relaunch_elevated())
        self.assertEqual(launch.call_count, 2)
        self.assertEqual(launch.call_args.args[2], sys.executable)
        self.assertEqual(launch.call_args.args[3], subprocess.list2cmdline([str(Path("main.py").resolve())]))

    def test_interpreter_receives_script_and_original_arguments(self):
        with tempfile.TemporaryDirectory(prefix="wifi test ") as tmp:
            script = Path(tmp) / "entry point.py"
            script.write_text("import sys; print(sys.argv[1:])", encoding="utf-8")
            arguments = ["--file", "capture with spaces.pcapng"]
            with patch.object(sys, "argv", [str(script), *arguments]), \
                    patch.object(assets, "_terminal_command", return_value=None), \
                    patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=33) as launch:
                self.assertTrue(assets.relaunch_elevated())
            call = launch.call_args.args
            self.assertEqual(call[2], sys.executable)
            # Exercise the exact command line handed to ShellExecute, without UAC.
            output = subprocess.run(subprocess.list2cmdline([call[2]]) + " " + call[3],
                                    capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual(output.stdout.strip(), repr(arguments))


class CleanupTests(unittest.IsolatedAsyncioTestCase):
    async def check_cleanup(self, operation, *, stop=False):
        launch_original = asyncio.create_subprocess_exec
        launched = asyncio.Event()
        children = []

        async def launch(*args, **kwargs):
            proc = await launch_original(sys.executable, "-c", "import time; time.sleep(30)",
                                         stdout=asyncio.subprocess.PIPE,
                                         stderr=asyncio.subprocess.STDOUT)
            children.append(proc)
            launched.set()
            return proc

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(asyncio, "create_subprocess_exec", side_effect=launch):
            target = Path(tmp) / "capture.pcapng"
            should_stop = launched.is_set if stop else None
            if operation == "capture":
                backend = capturer.Backend("test", "Local sleeper", Path(sys.executable))
                coro = capturer.capture(backend, capturer.Interface(1, "Fixture"), target,
                                         should_stop=should_stop)
            else:
                coro = converter._wpawolf(Path(sys.executable), target,
                                           target.with_suffix(".22000"), None, None,
                                           should_stop=should_stop)
            task = asyncio.create_task(coro)
            try:
                await asyncio.wait_for(launched.wait(), timeout=5)
                if stop:
                    error = capturer.CaptureError if operation == "capture" else converter.ConversionCancelled
                    with self.assertRaises(error):
                        await asyncio.wait_for(task, timeout=5)
                else:
                    await asyncio.sleep(0.02)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                self.assertIsNotNone(children[0].returncode, "child survived cancellation")
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                for proc in children:
                    if proc.returncode is None:
                        proc.kill()
                    await proc.wait()

    async def test_capture_task_cancellation_reaps_child(self):
        await self.check_cleanup("capture")

    async def test_converter_task_cancellation_reaps_child(self):
        await self.check_cleanup("converter")

    async def test_capture_stop_reaps_child(self):
        await self.check_cleanup("capture", stop=True)

    async def test_converter_stop_reaps_child(self):
        await self.check_cleanup("converter", stop=True)


class CaptureResultTests(unittest.IsolatedAsyncioTestCase):
    async def test_capture_outcomes_reach_result_screen(self):
        net = Network("Fixture", "aa:bb:cc:dd:ee:ff", auth="WPA2-Personal")
        for report in (hc22000.ConversionReport(pmkid=["fixture"]),
                       hc22000.ConversionReport(frames=3)):
            with self.subTest(found=report.ok):
                state.reset()
                state.phase.set("crack")
                with patch.object(controller, "_readiness", return_value=pipeline.Readiness()), \
                        patch.object(pipeline, "obtain_hashes", AsyncMock(return_value=(Path("fixture"), report))):
                    await controller.run_capture_only(net)
                result = state.result.peek()
                self.assertEqual(state.phase.peek(), "result")
                self.assertEqual(result.success, report.ok)
                self.assertEqual(result.summary, hc22000.summarise(report))
                self.assertEqual(result.password, "")
                self.assertEqual(bool(result.error), not report.ok)
                view = await test_render(App, {"width": 80, "height": 24})
                try:
                    view.render_frame()
                    screen = view.capture_char_frame()
                    self.assertIn("Захват готов" if report.ok else "Захват не получен", screen)
                    self.assertNotIn("Пароль найден", screen)
                    if report.ok:
                        self.assertIn(result.summary, screen)
                finally:
                    view.destroy()

    async def test_capture_readiness_failure_reaches_result_screen(self):
        state.reset()
        net = Network("Fixture", "aa:bb:cc:dd:ee:ff")
        # The probe itself failing, not one of the private wrappers around it:
        # this is the path a netsh/timedark error actually takes.
        with patch.object(pipeline, "check_readiness", side_effect=RuntimeError("probe failed")):
            await controller.run_capture_only(net)
        self.assertEqual(state.phase.peek(), "result")
        self.assertIn("probe failed", state.result.peek().error)


class RetryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(controller.configure_cracking, CrackOptions())
        self.path = Path(tmp.name) / "original.22000"
        self.path.write_text("fixture", encoding="utf-8")
        self.net = Network("Fixture", "aa:bb:cc:dd:ee:ff", auth="WPA2-Personal")
        self.options = CrackOptions(mask="1234567?d", runtime=17)
        state.reset()

    async def test_offline_retry_uses_historical_file_and_options(self):
        report = hc22000.ConversionReport(pmkid=[
            "WPA*01*" + "00" * 16 + "*aabbccddeeff*112233445566*46697874757265***"])
        outcome = CrackResult(network=self.net, error="Reached time limit")
        controller.configure_cracking(self.options)
        with patch.object(controller, "_readiness", return_value=pipeline.Readiness()), \
                patch.object(pipeline, "convert_capture", AsyncMock(return_value=(self.path, report))) as convert, \
                patch.object(pipeline, "attack", AsyncMock(return_value=outcome)) as attack:
            await controller._open_capture(self.path)
            original_result = state.result.peek()
            controller.configure_cracking(CrackOptions(mask="7654321?d", runtime=99))
            state.form_values.set({"source": "live", "capture": "some-other.pcapng"})
            state.last_result.set(CrackResult(network=Network("Another", "11:22:33:44:55:66")))
            state.result.set(original_result)
            queued = []
            with patch.object(controller, "_spawn", side_effect=queued.append):
                result_screen._retry()
            self.assertEqual(len(queued), 1)
            await queued[0]
            self.assertEqual(convert.call_args.args[0], self.path)
            self.assertEqual(convert.call_args.args[1], self.net.bssid)
            self.assertEqual(attack.call_args.kwargs["mask"], self.options.mask)
            self.assertEqual(attack.call_args.kwargs["timeout"], self.options.runtime)
            self.assertEqual(state.result.peek().request.capture_path, str(self.path.resolve()))

    async def test_manual_retry_preserves_original_options(self):
        controller.configure_cracking(self.options)
        with patch.object(controller, "_readiness", return_value=pipeline.Readiness()), \
                patch.object(pipeline, "attack", AsyncMock(return_value=CrackResult(network=self.net))) as attack:
            await controller.run_attack(self.net)
            controller.configure_cracking(CrackOptions(mask="7654321?d", runtime=99))
            queued = []
            with patch.object(controller, "_spawn", side_effect=queued.append):
                result_screen._retry()
            self.assertEqual(len(queued), 1)
            await queued[0]
            self.assertEqual(attack.call_args.kwargs["mask"], self.options.mask)
            self.assertEqual(attack.call_args.kwargs["timeout"], self.options.runtime)


class ProfileKeyTests(unittest.TestCase):
    def test_key_material_preserved_in_both_locales(self):
        for label in ("Содержимое ключа", "Key Content", "Contents of the key"):
            for password in ('abcdefgh"', '"abcdefgh', '"abcdefgh"', ' abcdefgh ', ' pass:word '):
                with self.subTest(label=label, password=password), \
                        patch.object(profiles, "_netsh", return_value=(
                            '    SSID name : "Fixture"\n'
                            '    Authentication : WPA2-Personal\n'
                            f'    {label} : {password}\n')):
                    self.assertEqual(profiles.read_profile("Fixture").key, password)


class ConverterRecordTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.capture = Path(tmp.name) / "synthetic.pcap"

    def write_session(self, extra=()):
        packets = [frames.beacon("Fixture"),
                   frames.data_frame(0x08, False, True, frames.STA, frames.AP, frames.AP, frames.M1),
                   frames.data_frame(0x08, True, False, frames.AP, frames.STA, frames.AP, frames.M2)]
        self.capture.write_bytes(frames.build_pcap(packets + list(extra)))

    def test_builtin_filter_compares_ap_field_not_client(self):
        self.write_session()
        hit = hc22000.convert(self.capture, bssid_filter=frames.AP.hex(":"))
        self.assertTrue(hit.ok)
        miss = hc22000.convert(self.capture, bssid_filter=frames.STA.hex(":"))
        self.assertEqual(miss.total, 0)

    def test_other_client_or_session_cannot_replace_anonce(self):
        for station, replay in ((bytes.fromhex("223344556677"), 1), (frames.STA, 100)):
            with self.subTest(station=station.hex(), replay=replay):
                other_nonce = bytes(range(96, 128))
                other_m1 = frames.eapol_key(0x008A, other_nonce, bytes(16), b"", replay=replay)
                self.write_session([frames.data_frame(0x08, False, True, station,
                                                       frames.AP, frames.AP, other_m1)])
                report = hc22000.convert(self.capture)
                records = [line.split("*") for line in report.eapol]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0][4], frames.STA.hex())
                self.assertEqual(records[0][6], frames.ANONCE.hex())

    def test_m3_pairs_with_its_own_client_and_replay_counter(self):
        other_station = bytes.fromhex("223344556677")
        other_nonce = bytes(range(96, 128))
        extra = [frames.data_frame(0x08, False, True, other_station, frames.AP, frames.AP,
                                   frames.eapol_key(0x018A, other_nonce, frames.M3_MIC, b"", replay=2)),
                 frames.data_frame(0x08, False, True, frames.STA, frames.AP, frames.AP, frames.M3)]
        self.write_session(extra)
        records = [line.split("*") for line in hc22000.convert(self.capture).eapol]
        m2 = next(record for record in records if record[2] == frames.M2_MIC.hex())
        own_m3 = next(record for record in records if record[4] == frames.STA.hex() and record[8] == "13")
        self.assertEqual(m2[6], frames.ANONCE.hex())
        self.assertEqual(own_m3[6], frames.SNONCE.hex())


if __name__ == "__main__":
    unittest.main(verbosity=2)
