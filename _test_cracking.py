"""Bounded offline-audit tests, without scanning or accessing saved keys."""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from main import _parse_args
from main import _run
from wifi_tool import converter, cracker, hc22000, pipeline
from wifi_tool.models import Network
from wifi_tool.options import CrackOptions, normalize_bssid, validate_mask
from wifi_tool.ui import controller, state


class OptionsTests(unittest.TestCase):
    def test_the_configured_limit_is_the_automatic_ladder_budget(self):
        """The «Лимит времени» field has to reach the automatic mode.

        It used to be read only by the manual run, while the ladder ran on a
        hardcoded half hour whatever the field said -- so the one setting a user
        reaches for when the ladder came up short was the one that did nothing.
        """
        self.assertEqual(controller._auto_budget(CrackOptions(runtime=7200)), 7200.0)
        self.assertEqual(controller._auto_budget(CrackOptions(runtime=300)), 300.0)
        # An empty field must not mean "no time at all" -- it falls back to the
        # default rather than skipping the run.
        self.assertEqual(
            controller._auto_budget(CrackOptions(runtime=0)), pipeline.AUTO_RUNTIME
        )

    def test_the_default_limit_covers_the_whole_ladder(self):
        """Half an hour covers everything except the nine-digit stage."""
        self.assertGreaterEqual(CrackOptions().runtime, pipeline.AUTO_RUNTIME)

    def test_dictionary_paths_and_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            words = Path(tmp) / "словарь с пробелами.txt"
            words.write_text("testpass\n", encoding="utf-8")
            opts = _parse_args(["--file", "own.pcapng", "--wordlist", str(words),
                                "--runtime", "30", "--no-rules"])
            self.assertEqual(opts["crack_options"].wordlist, words)
            self.assertEqual(opts["crack_options"].runtime, 30)
            self.assertFalse(opts["crack_options"].use_rules)

    def test_mask_validation(self):
        for mask in ("1234567?d", "MyHome?d?d", "?d?d?d?d?d?d?d?d", "abcde???d?d"):
            validate_mask(mask)
        for mask in ("?d", "1234567?", "1234567?1", "x" * 64, "--runtime=1"):
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                validate_mask(mask)

    def test_invalid_cli_does_not_start(self):
        for argv in (["--runtime", "0"], ["--mask", "?d"], ["--bssid", "not-a-mac"],
                     ["--mask", "1234567?d", "--wordlist", "missing"], ["--file"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    _parse_args(argv)
                self.assertEqual(caught.exception.code, 2)

    def test_status_json_progress_speed_and_terminal_state(self):
        status = cracker.HashStatus()
        data = {"status": 3, "progress": [25, 100], "devices": [{"speed": 1200}, {"speed": 800}],
                "rejected": 5, "estimated_stop": int(time.time()) + 30}
        self.assertTrue(cracker.parse_status(json.dumps(data), status))
        self.assertEqual(status.percent, 25)
        self.assertEqual(status.speed, "2.0 kH/s")
        self.assertEqual(status.depth, 25)
        self.assertEqual(status.rejected, 20)
        self.assertTrue(status.running)
        # hashcat's own device status codes: 5 is Exhausted, 6 is Cracked. They
        # are different outcomes, and mapping 6 to "exhausted" reported a
        # successful crack as an exhausted keyspace.
        data.update(status=5, progress=[100, 100])
        self.assertTrue(cracker.parse_status(json.dumps(data), status))
        self.assertTrue(status.exhausted)
        self.assertFalse(status.cracked)
        self.assertFalse(status.running)

        cracked = cracker.HashStatus()
        self.assertTrue(cracker.parse_status(json.dumps(data | {"status": 6}), cracked))
        self.assertTrue(cracked.cracked)
        self.assertFalse(cracked.exhausted)
        # A trailing Exhausted line after a crack must not undo it.
        self.assertTrue(cracker.parse_status(json.dumps(data | {"status": 5}), cracked))
        self.assertTrue(cracked.cracked)
        self.assertFalse(cracked.exhausted)

        self.assertFalse(cracker.parse_status("{broken", status))
        self.assertFalse(cracker.parse_status('{"status":3,"progress":[1,2],"devices":null}', status))

    def test_show_preserves_colons_spaces_and_unicode(self):
        password = " пароль:с пробелом "
        output = "digest:ap:client:ssid:" + password.encode().hex() + "\n"
        with patch.object(cracker.subprocess, "run", return_value=SimpleNamespace(stdout=output)) as run:
            found = cracker.show_cracked(Path("hashcat.exe"), Path("capture.22000"))
        self.assertEqual(list(found.values()), [password])
        self.assertIn("--outfile-format=1,3", run.call_args.args[0])


class FakeProcess:
    def __init__(self, code=None, output=b""):
        self.returncode = code
        self.stdout = asyncio.StreamReader()
        self.terminated = False
        self.reaped = False
        if output:
            self.stdout.feed_data(output)
        if code is not None:
            self.stdout.feed_eof()

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.stdout.feed_eof()

    def kill(self):
        self.returncode = -9

    async def wait(self):
        self.reaped = True
        return self.returncode


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.exe = self.root / "hashcat.exe"
        self.hashes = self.root / "own.22000"
        self.words = self.root / "words.txt"
        for path in (self.exe, self.hashes, self.words):
            path.write_text("fixture\n", encoding="utf-8")

    async def test_mask_needs_no_dictionary_and_reports_progress(self):
        line = json.dumps({"status": 3, "progress": [5, 10], "devices": [{"speed": 500}]})
        proc = FakeProcess(0, (line + "\n").encode())
        snapshots = []
        with patch.object(cracker.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)) as launch, \
                patch.object(cracker, "show_cracked", return_value={"fixture": "12345678"}):
            out = await cracker.crack(self.hashes, hashcat=self.exe, mask="1234567?d", timeout=20,
                                      on_status=lambda st: snapshots.append(st.percent))
        command = launch.call_args.args
        self.assertEqual(command[command.index("-a") + 1], "3")
        self.assertEqual(command[-1], "1234567?d")
        self.assertIn("--runtime=20", command)
        self.assertIn("--status-json", command)
        self.assertNotIn("--force", command)
        self.assertEqual(launch.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL)
        self.assertEqual(launch.call_args.kwargs["creationflags"],
                         subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.assertTrue(out.cracked)
        self.assertEqual(out.password, "12345678")
        self.assertIn(50.0, snapshots)
        # Finding the password early does not mean all candidates were tested.
        self.assertEqual(snapshots[-1], 50.0)
        self.assertFalse(out.status.running)
        self.assertTrue(proc.reaped)

    async def test_dictionary_exhaustion_is_not_success(self):
        proc = FakeProcess(1, b"Exhausted\n")
        with patch.object(cracker.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)), \
                patch.object(cracker, "show_cracked", return_value={}):
            out = await cracker.crack(self.hashes, self.words, hashcat=self.exe)
        self.assertFalse(out.cracked)
        self.assertTrue(out.exhausted)
        self.assertFalse(out.status.running)

    async def test_carriage_return_status_is_parsed_without_flooding_the_journal(self):
        line = json.dumps({"status": 3, "progress": [5, 10], "devices": [{"speed": 650000}]})
        prompt = "[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => "
        proc = FakeProcess(1, (prompt + "\r" + " " * len(prompt) + "\r" + line +
                               "\nfixture device warning\n").encode())
        snapshots, journal = [], []
        with patch.object(cracker.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)), \
                patch.object(cracker, "show_cracked", return_value={}):
            out = await cracker.crack(
                self.hashes, self.words, hashcat=self.exe,
                on_status=lambda st: snapshots.append((st.percent, st.speed)), on_log=journal.append,
            )
        self.assertIn((50.0, "650.0 kH/s"), snapshots)
        self.assertIn("fixture device warning", journal)
        self.assertFalse(any("[s]tatus" in message or message.lstrip().startswith("{") for message in journal))
        self.assertTrue(out.exhausted)
        self.assertTrue(proc.reaped)

    async def test_cancel_and_timeout_reap_process(self):
        for kwargs, flag in (({"should_stop": lambda: True}, "cancelled"),
                              ({"timeout": 0.01}, "timed_out")):
            with self.subTest(flag=flag):
                proc = FakeProcess()
                with patch.object(cracker.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)), \
                        patch.object(cracker, "show_cracked", return_value={}):
                    out = await cracker.crack(self.hashes, self.words, hashcat=self.exe, **kwargs)
                self.assertTrue(getattr(out, flag))
                self.assertTrue(proc.terminated)
                self.assertTrue(proc.reaped)

    async def test_task_cancellation_reaps_process(self):
        proc = FakeProcess()
        with patch.object(cracker.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)):
            task = asyncio.create_task(cracker.crack(self.hashes, self.words, hashcat=self.exe))
            await asyncio.sleep(0.02)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(proc.terminated)
        self.assertTrue(proc.reaped)

    async def test_backend_errors_are_surfaced(self):
        proc = FakeProcess(255, b"No hashes loaded.\n")
        with patch.object(cracker.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)):
            with self.assertRaisesRegex(cracker.HashcatError, "No hashes loaded"):
                await cracker.crack(self.hashes, self.words, hashcat=self.exe)

    async def test_missing_rules_fail_before_spawn(self):
        with patch.object(cracker.asyncio, "create_subprocess_exec", AsyncMock()) as launch:
            with self.assertRaisesRegex(cracker.HashcatError, "правил"):
                await cracker.crack(self.hashes, self.words, self.root / "missing.rule", hashcat=self.exe)
        launch.assert_not_called()

    async def test_pipeline_mask_has_no_wordlist_requirement(self):
        report = hc22000.ConversionReport(pmkid=["fixture"])
        ready = pipeline.Readiness(hashcat=self.exe)
        outcome = cracker.CrackOutcome(exhausted=True)
        with patch.object(cracker, "crack", AsyncMock(return_value=outcome)) as call:
            result = await pipeline.attack(Network("Own", "aa:bb:cc:dd:ee:ff"), readiness=ready,
                                            hash_path=self.hashes, report=report,
                                            mask="1234567?d", timeout=30)
        self.assertIsNone(call.call_args.args[1])
        self.assertIsNone(call.call_args.args[2])
        self.assertEqual(call.call_args.kwargs["mask"], "1234567?d")
        self.assertFalse(result.success)

    async def test_hashfile_scope_filters_ap_not_client(self):
        own = "WPA*01*" + "00" * 16 + "*aabbccddeeff*112233445566*4f776e***"
        other = "WPA*01*" + "11" * 16 + "*112233445566*aabbccddeeff*4f74686572***"
        self.hashes.write_text(own + "\n" + other + "\n", encoding="utf-8")
        result = await converter.convert(self.hashes, self.root / "filtered.22000", "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result.backend, "hashfile")
        self.assertEqual(result.report.pmkid, [own])
        self.assertEqual(result.path.read_text().splitlines(), [own])
        self.assertEqual(self.hashes.read_text().splitlines(), [own, other])

    async def test_external_converter_writes_only_selected_ap(self):
        own = "WPA*01*" + "00" * 16 + "*aabbccddeeff*112233445566*4f776e***"
        other = "WPA*01*" + "11" * 16 + "*112233445566*aabbccddeeff*4f74686572***"
        output = self.root / "converted.22000"
        async def run(*args, **kwargs):
            output.write_text(own + "\n" + other + "\n", encoding="utf-8")
            return FakeProcess(0)
        with patch.object(converter.asyncio, "create_subprocess_exec", side_effect=run):
            result = await converter._wpawolf(self.exe, self.hashes, output, "aa:bb:cc:dd:ee:ff", None)
        self.assertEqual(result.path.read_text().splitlines(), [own])

    async def test_controller_rejects_ambiguous_capture(self):
        records = ["WPA*01*" + "00" * 16 + f"*{ap}*000000000000*4f776e***"
                   for ap in ("aabbccddeeff", "112233445566")]
        report = hc22000.ConversionReport(pmkid=records)
        controller.configure_cracking(CrackOptions())
        self.addCleanup(controller.configure_cracking, CrackOptions())
        with patch.object(pipeline, "convert_capture", AsyncMock(return_value=(self.hashes, report))), \
                patch.object(pipeline, "attack", AsyncMock()) as attack:
            await controller._open_capture(self.hashes)
        attack.assert_not_called()
        self.assertIn("--bssid", state.result.peek().error)

    async def test_ui_exit_always_cleans_background_tasks(self):
        with patch("main.render", AsyncMock(side_effect=KeyboardInterrupt)), \
                patch.object(controller, "boot"), patch.object(controller, "bind"), \
                patch.object(controller, "stop_pending") as cleanup:
            with self.assertRaises(KeyboardInterrupt):
                await _run(None)
        cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
