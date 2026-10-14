"""Idle input, raw parsing and animation lifecycle regressions.

The optional --windows-probe runs the real renderer in a console, injects a
key-release event and checks that frames keep arriving without another key.
"""
from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import queue
import sys
import threading
import time
import unittest
from unittest.mock import patch

from opentui.input.handler import InputHandler
from wifi_tool.ui import controller, state
from wifi_tool.ui.terminal_input import (BufferedInputBackend,
                                        ResponsiveInputHandler,
                                        nonblocking_terminal_input)


class BlockingBackend:
    def __init__(self):
        self.input = queue.Queue()

    def start(self):
        pass

    def stop(self):
        self.input.put(-1)

    def read_byte(self):
        return self.input.get()

    def feed(self, text):
        for byte in text.encode("utf-8"):
            self.input.put(byte)


class InputTests(unittest.TestCase):
    def setUp(self):
        self.source = BlockingBackend()
        self.backend = BufferedInputBackend(self.source)
        self.backend.start()
        self.addCleanup(self.backend.stop)

    def test_idle_poll_does_not_wait_for_a_character(self):
        reader = self.backend._thread
        start = time.monotonic()
        for _ in range(100):
            self.assertFalse(self.backend.has_data())
            self.assertEqual(self.backend.read_byte(), -1)
        self.assertLess(time.monotonic() - start, 0.1)
        self.assertTrue(reader.is_alive())
        self.backend.stop()
        self.assertFalse(reader.is_alive())

    def test_raw_arrow_unicode_and_bracketed_paste_are_preserved(self):
        handler = InputHandler(backend=self.backend)
        handler.start()
        self.addCleanup(handler.stop)
        keys, pastes = [], []
        handler.on_key(lambda event: keys.append(event.key))
        handler.on_paste(lambda event: pastes.append(event.text))
        self.source.feed("\x1b[AЖ\x1b[200~C:\\Тест\\capture.pcapng\x1b[201~")
        deadline = time.monotonic() + 2
        while not pastes and time.monotonic() < deadline:
            if self.backend.has_data(.05):
                handler.poll()
        self.assertEqual(keys, ["up", "Ж"])
        self.assertEqual(pastes, ["C:\\Тест\\capture.pcapng"])
        self.assertFalse(self.backend.has_data())

    def test_pushback_preserves_byte_order(self):
        self.source.feed("ab")
        deadline = time.monotonic() + 1
        while len(self.backend._bytes) < 2 and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertEqual(self.backend.read_byte(), ord("a"))
        self.backend.unread(ord("a"))
        self.assertEqual(self.backend.read_byte(), ord("a"))
        self.assertEqual(self.backend.read_byte(), ord("b"))

    def test_fragmented_arrow_is_never_escape_and_poll_never_waits(self):
        handler = InputHandler(backend=self.backend)
        handler.start()
        self.addCleanup(handler.stop)
        keys = []
        handler.on_key(lambda event: keys.append(event.key))
        for part in ("\x1b", "[", "1;", "2"):
            self.source.feed(part)
            time.sleep(.005)
            started = time.monotonic()
            self.assertFalse(handler.poll())
            self.assertLess(time.monotonic() - started, .02)
            self.assertEqual(keys, [])
        self.source.feed("B")
        self.assertTrue(self.backend.has_data(.1))
        self.assertTrue(handler.poll())
        self.assertEqual(keys, ["down"])

    def test_lone_escape_still_arrives_and_utf8_is_atomic(self):
        self.source.feed("\x1b")
        self.assertTrue(self.backend.has_data(.15))
        self.assertEqual(self.backend.read_byte(), 27)
        self.source.input.put(0xd0)
        time.sleep(.005)
        self.assertFalse(self.backend.has_data())
        self.source.input.put(0x96)
        self.assertTrue(self.backend.has_data(.1))
        self.assertEqual(bytes([self.backend.read_byte(), self.backend.read_byte()]).decode(), "Ж")


class RepeatTests(unittest.TestCase):
    def test_repeat_paste_and_mouse_order_and_bulk_paste_speed(self):
        from opentui.input._backend_buffer import BufferBackend
        backend = BufferBackend()
        handler = ResponsiveInputHandler(backend=backend)
        handler.start()
        self.addCleanup(handler.stop)
        events = []
        handler.on_key(lambda event: events.append((event.key, event.repeat_count)))
        handler.on_paste(lambda event: events.append(("paste", event.text)))
        handler.on_mouse(lambda event: events.append(("mouse", event.x)))
        payload = "Тест" * 500
        backend.feed("\x1b[B" * 3 + "\x1b[200~" + payload + "\x1b[201~" + "\x1b[A" * 2 + "\x1b[<0;5;7M")
        frames = 0
        while backend.has_data():
            while handler.poll():
                pass
            frames += 1
        self.assertEqual(events, [("down", 3), ("paste", payload), ("up", 2), ("mouse", 4)])
        self.assertLess(frames, 10)

    def test_continuous_navigation_yields_to_rendering_and_preserves_enter(self):
        from opentui.input._backend_buffer import BufferBackend
        backend = BufferBackend()
        handler = ResponsiveInputHandler(backend=backend)
        handler.start()
        self.addCleanup(handler.stop)
        keys = []
        handler.on_key(lambda event: keys.extend([event.key] * getattr(event, "repeat_count", 1)))
        backend.feed("\x1b[B" * 300 + "\r")
        frames = 0
        while backend.has_data():
            before = len(keys)
            while handler.poll():
                pass
            self.assertLessEqual(len(keys) - before, 32)
            frames += 1
        self.assertGreater(frames, 9)
        self.assertEqual(keys, ["down"] * 300 + ["return"])


class ConsoleModeTests(unittest.TestCase):
    def test_mouse_selection_is_disabled_and_original_modes_are_restored(self):
        from opentui.input._backend_windows import WindowsBackend

        class Kernel:
            def __init__(self):
                self.modes = {10: 0x00f7, 11: 3}

            def GetStdHandle(self, number):
                return 10 if number == -10 else 11

            def GetConsoleMode(self, handle, pointer):
                pointer._obj.value = self.modes[handle]
                return 1

            def SetConsoleMode(self, handle, mode):
                self.modes[handle] = mode
                return 1

            def ReadFile(self, handle, buffer, size, count, overlapped):
                count._obj.value = 0
                return 0

        kernel = Kernel()
        with patch("opentui.input._backend_windows._get_kernel32", return_value=kernel), \
                patch("opentui.input._backend_windows.atexit.register"):
            backend = BufferedInputBackend(WindowsBackend())
            backend.start()
            try:
                self.assertFalse(kernel.modes[10] & 0x0040, "QuickEdit can pause the console")
                self.assertTrue(kernel.modes[10] & 0x0080)
                self.assertTrue(kernel.modes[10] & 0x0200)
                self.assertTrue(kernel.modes[10] & 0x0010)
            finally:
                backend.stop()
            self.assertEqual(kernel.modes, {10: 0x00f7, 11: 3})


class AnimationTests(unittest.TestCase):
    def setUp(self):
        controller.stop_ticking()
        state.reset()
        self.previous = controller._renderer
        self.addCleanup(self.restore)

    def restore(self):
        controller.stop_ticking()
        controller._renderer = self.previous

    def test_repeated_runs_detach_old_callbacks(self):
        class Renderer:
            def __init__(self):
                self.callbacks = []

            def set_frame_callback(self, callback):
                self.callbacks.append(callback)

            def remove_frame_callback(self, callback):
                self.callbacks.remove(callback)

        renderer = Renderer()
        controller.bind(renderer)
        state.phase.set("crack")
        for index in range(5):
            clock = [float(index * 10)]
            with patch.object(controller.time, "monotonic", side_effect=lambda: clock[0]):
                controller.start_ticking()
                controller.start_ticking()
                self.assertEqual(len(renderer.callbacks), 1)
                old = renderer.callbacks[0]
                clock[0] += .25
                old(.016)
                self.assertEqual(state.elapsed.peek(), .25)
                controller.stop_ticking()
                self.assertEqual(renderer.callbacks, [])
                old(10)
                self.assertEqual(state.elapsed.peek(), 0)

    def test_switching_renderers_rebinds_active_animation(self):
        class Renderer:
            def __init__(self):
                self.callbacks = []

            def set_frame_callback(self, callback):
                self.callbacks.append(callback)

            def remove_frame_callback(self, callback):
                self.callbacks.remove(callback)

        first, second = Renderer(), Renderer()
        state.phase.set("crack")
        state.begin_run_stages(["crack"])
        with patch.object(controller.time, "monotonic", side_effect=[0, 0, .5]):
            controller.bind(first)
            controller.bind(second)
            self.assertEqual(first.callbacks, [])
            self.assertEqual(len(second.callbacks), 1)
            second.callbacks[0](.016)
            self.assertGreater(state.tick.peek(), 0)


class OverlayMouseTests(unittest.IsolatedAsyncioTestCase):
    async def test_keyboard_menu_and_modal_mouse_actions_run_once(self):
        from opentui.testing import test_render
        from .test_tui_setup import native_input
        from wifi_tool.ui import dialogs, forms
        from wifi_tool.ui.actions import Action
        from wifi_tool.ui.app import App

        self.addCleanup(dialogs.clear)
        for phase in ("scan", "crack_form"):
            with self.subTest(phase=phase):
                state.reset()
                state.networks.set([])
                if phase == "crack_form":
                    forms.open_form()
                view = await test_render(App, {"width": 80, "height": 24})
                native = native_input(view)
                try:
                    view.render_frame()
                    self.assertNotIn("F1 меню", view.capture_char_frame())
                    native.feed("\x1bOP")
                    view.render_frame()
                    self.assertTrue(dialogs.active())
                    self.assertIn("Команды", view.capture_char_frame())
                    view.mock_mouse.click(1, 23)
                    view.render_frame()
                    self.assertFalse(dialogs.active())
                    calls = []
                    dialogs.open_select("Mouse fixture", [Action("Fixture action", lambda: calls.append(1))],
                                        searchable=False)
                    view.render_frame()
                    lines = view.capture_char_frame().splitlines()
                    row = next(index for index, line in enumerate(lines) if "Fixture action" in line)
                    column = lines[row].index("Fixture action")
                    view.mock_mouse.click(column + 1, row)
                    view.render_frame()
                    self.assertEqual(calls, [1])
                    self.assertFalse(dialogs.active())
                    self.assertEqual(state.phase.peek(), phase)
                finally:
                    native.stop()
                    view.destroy()


def windows_probe(report_path: Path, *, application=False) -> None:
    """Exercise actual console input and CliRenderer.run with no mocked loop."""
    from opentui import Text, component, render
    from opentui.hooks import use_keyboard, use_paste, use_renderer
    from opentui.signals import Signal
    from wifi_tool.console import enable_utf8_console
    from wifi_tool.ui.motion import Motion
    from wifi_tool.ui import dialogs
    from wifi_tool.ui.app import App
    from .test_ui_redesign import NETS
    from dataclasses import replace

    enable_utf8_console()
    frames = Signal(0)
    cursor = Signal(0)
    clock = Motion()
    scroll_frames = []
    holder = {}
    keys, pastes = [], []
    evidence = {}
    done = threading.Event()
    frame_times = []
    if application:
        state.reset()
        state.networks.set([replace(NETS[0], ssid=f"Fixture {i:03}",
                                   bssid=f"00:00:00:00:{i // 256:02x}:{i % 256:02x}") for i in range(400)])

    @component
    def Probe():
        def key(event):
            keys.append(event.key)
            if event.key == "up":
                cursor.set(15)
        use_keyboard(key)
        use_paste(lambda event: pastes.append(event.text))
        renderer = use_renderer()
        if not holder:
            holder["renderer"] = renderer
            clock.bind(renderer, enabled=True)
            def count(delta):
                frames.set(frames.peek() + 1)
                frame_times.append(time.monotonic())
                if "console_mode_running" not in evidence:
                    mode = wintypes.DWORD()
                    kernel.GetConsoleMode(handle, ctypes.byref(mode))
                    evidence["console_mode_running"] = mode.value
                if application and dialogs.active():
                    evidence["unexpected_dialog"] = True
                if "probe" in clock.scrolls:
                    scroll_frames.append(clock.scrolls["probe"].value(clock.now))
            renderer.set_frame_callback(count)
        if application:
            return App()
        start, _ = clock.window("probe", 40, 8, cursor())
        return Text(lambda: f"Idle frames: {frames()} · scroll: {start}")

    class Key(ctypes.Structure):
        _fields_ = [("down", wintypes.BOOL), ("repeat", wintypes.WORD),
                    ("vk", wintypes.WORD), ("scan", wintypes.WORD),
                    ("char", wintypes.WCHAR), ("control", wintypes.DWORD)]

    class Payload(ctypes.Union):
        _fields_ = [("key", Key), ("padding", ctypes.c_byte * 16)]

    class Record(ctypes.Structure):
        _fields_ = [("kind", wintypes.WORD), ("data", Payload)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetStdHandle.restype = wintypes.HANDLE
    kernel.WriteConsoleInputW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Record),
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    handle = kernel.GetStdHandle(-10)
    kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetConsoleMode.restype = wintypes.BOOL
    kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.SetConsoleMode.restype = wintypes.BOOL
    original_mode = wintypes.DWORD()
    if not kernel.GetConsoleMode(handle, ctypes.byref(original_mode)):
        raise ctypes.WinError(ctypes.get_last_error())
    # Reproduce the usual conhost setting in this probe's own hidden console.
    evidence["console_mode_before"] = original_mode.value | 0x00c0
    if not kernel.SetConsoleMode(handle, evidence["console_mode_before"]):
        raise ctypes.WinError(ctypes.get_last_error())

    def inject(chars="", *, release=False):
        events = (Record * (len(chars) if chars else 1))()
        for index, char in enumerate(chars or "\0"):
            events[index].kind = 1
            events[index].data.key.down = not release
            events[index].data.key.repeat = 1
            events[index].data.key.vk = 0x10 if release else 0
            events[index].data.key.char = char
        written = wintypes.DWORD()
        if not kernel.WriteConsoleInputW(handle, events, len(events), ctypes.byref(written)):
            raise ctypes.WinError(ctypes.get_last_error())

    def writer():
        try:
            time.sleep(.5)
            evidence["before_release"] = frames.peek()
            inject(release=True)
            if application:
                time.sleep(.3)
                evidence["before_burst"] = frames.peek()
                # Fragment a real console arrow, then simulate a large repeat backlog.
                inject("\x1b")
                time.sleep(.006)
                inject("[")
                time.sleep(.006)
                inject("B")
                inject("\x1b[B" * 300)
                deadline = time.monotonic() + 3
                while state.selected.peek() < 301 and time.monotonic() < deadline:
                    time.sleep(.01)
                evidence["selected"] = state.selected.peek()
                evidence["after_burst"] = frames.peek()
                time.sleep(.25)
                evidence.update(frames=frames.peek(), phase=state.phase.peek(), dialog=dialogs.active())
                return
            time.sleep(1.2)
            evidence["after_idle"] = frames.peek()
            inject("\x1b[AЖ\x1b[200~capture.pcapng\x1b[201~")
            time.sleep(.4)
            evidence.update(frames=frames.peek(), keys=keys, pastes=pastes)
        finally:
            if holder:
                holder["renderer"].stop()

    def watchdog():
        if not done.wait(6):
            import os
            report_path.write_text(json.dumps({"timeout": True, "frames": frames.peek()}))
            os._exit(2)

    threading.Thread(target=writer, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    with nonblocking_terminal_input():
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
            asyncio.run(render(Probe))
    restored_mode = wintypes.DWORD()
    kernel.GetConsoleMode(handle, ctypes.byref(restored_mode))
    evidence["console_mode_after"] = restored_mode.value
    kernel.SetConsoleMode(handle, original_mode.value)
    evidence["scroll_frames"] = scroll_frames
    clock.unbind()
    evidence["reader_stopped"] = not any(
        thread.name == "wifi-tool-console-input" for thread in threading.enumerate()
    )
    report_path.write_text(json.dumps(evidence, ensure_ascii=False), encoding="utf-8")
    done.set()
    assert not evidence["console_mode_running"] & 0x0040, evidence
    assert evidence["console_mode_running"] & 0x0200, evidence
    assert evidence["console_mode_after"] == evidence["console_mode_before"], evidence
    if application:
        assert evidence["selected"] == 301, evidence
        assert evidence["after_burst"] - evidence["before_burst"] >= 10, evidence
        assert evidence["phase"] == "scan" and not evidence["dialog"], evidence
        assert not evidence.get("unexpected_dialog"), evidence
        assert evidence["reader_stopped"], evidence
        return
    assert evidence["after_idle"] - evidence["before_release"] > 30, evidence
    assert keys == ["up", "Ж"], evidence
    assert pastes == ["capture.pcapng"], evidence
    assert evidence["reader_stopped"], evidence
    assert len({round(value, 3) for value in scroll_frames if 0 < value < 8}) >= 3, evidence
    assert scroll_frames[-1] == 8, evidence


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] in ("--windows-probe", "--windows-hold-probe"):
        windows_probe(Path(sys.argv[2]), application=sys.argv[1] == "--windows-hold-probe")
    else:
        unittest.main()
