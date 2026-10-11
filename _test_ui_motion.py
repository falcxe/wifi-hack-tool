"""Motion timing and actual OpenTUI input/frame regressions."""
from __future__ import annotations

import unittest
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from opentui.testing import test_render

from _test_tui_setup import native_input
from _test_ui_redesign import NETS
from wifi_tool.ui import controller, dialogs, motion, state
from wifi_tool.ui.actions import Action
from wifi_tool.ui.app import App
from wifi_tool.ui.motion import Motion
from wifi_tool.ui.screens import scan


class Renderer:
    _config = SimpleNamespace(testing=False)

    def __init__(self):
        self.callbacks = []

    def set_frame_callback(self, callback):
        self.callbacks.append(callback)

    def remove_frame_callback(self, callback):
        self.callbacks.remove(callback)


class MotionClockTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.renderer = Motion(), Renderer()
        self.clock.bind(self.renderer, enabled=True)
        self.addCleanup(self.clock.unbind)

    def test_short_scroll_has_intermediate_frames_and_keeps_selection_visible(self):
        self.clock.window("list", 60, 8, 0, token="data")
        start, indices = self.clock.window("list", 60, 8, 15, token="data")
        self.assertEqual(start, 0)
        self.assertIn(15, indices)
        positions = []
        for _ in range(12):
            self.clock.advance(1 / 60)
            start, indices = self.clock.window("list", 60, 8, 15, token="data")
            positions.append(start)
            self.assertIn(15, indices)
        self.assertGreater(len(set(positions)), 3)
        self.assertEqual(positions[-1], 8)
        self.assertFalse(self.clock.active())

    def test_retargeting_never_queues_old_destinations(self):
        self.clock.window("list", 60, 8, 0)
        self.clock.window("list", 60, 8, 15)
        self.clock.advance(.04)
        current = self.clock.scrolls["list"].value(self.clock.now)
        self.clock.window("list", 60, 8, 19)
        self.assertAlmostEqual(self.clock.scrolls["list"].origin, current)
        self.clock.advance(.18)
        start, indices = self.clock.window("list", 60, 8, 19)
        self.assertEqual(start, 12)
        self.assertIn(19, indices)

    def test_highlight_changes_color_then_stops_without_idle_repaints(self):
        self.clock.row("list", 0, 0)
        self.clock.row("list", 1, 1)
        before = self.clock.row("list", 1, 0)
        self.clock.advance(.04)
        middle = self.clock.row("list", 1, 0)
        self.assertNotEqual(before, middle)
        self.clock.advance(.2)
        self.assertIsNone(self.clock.row("list", 1, 0))
        revision = self.clock.revision.peek()
        for _ in range(100):
            self.clock.advance(.016)
        self.assertEqual(self.clock.revision.peek(), revision)

    def test_data_change_large_jump_and_reduced_motion_snap(self):
        self.clock.window("list", 100, 8, 0, token="old")
        self.clock.window("list", 100, 8, 15, token="old")
        start, _ = self.clock.window("list", 100, 8, 15, token="new")
        self.assertEqual(start, 8)
        start, _ = self.clock.window("list", 100, 8, 99, token="new")
        self.assertEqual(start, 92)
        self.clock.enabled = False
        start, _ = self.clock.window("list", 100, 8, 98, token="new", target=91)
        self.assertEqual(start, 91)

    def test_renderer_rebind_detaches_old_clock_and_stale_callback_is_inert(self):
        old = self.renderer.callbacks[0]
        self.clock.bind(self.renderer)
        self.assertEqual(len(self.renderer.callbacks), 1)
        second = Renderer()
        self.clock.bind(second, enabled=True)
        self.assertEqual(self.renderer.callbacks, [])
        self.clock.window("list", 60, 8, 0)
        self.clock.window("list", 60, 8, 15)
        old(1)
        self.assertEqual(self.clock.now, 0)
        second.callbacks[0](.04)
        self.assertGreater(self.clock.now, 0)

    def test_color_animation_updates_existing_boxes_without_screen_notifications(self):
        from opentui import Box
        previous = self.clock.paint(Box(), "list", 0, 0)
        selected = self.clock.paint(Box(), "list", 1, 1)
        before = selected.background_color
        revision = self.clock.revision.peek()
        for _ in range(12):
            self.clock.advance(1 / 60)
        self.assertNotEqual(selected.background_color, before)
        self.assertIsNone(previous.background_color)
        self.assertEqual(self.clock.revision.peek(), revision)


class AnimatedInputTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        controller.stop_ticking()
        state.reset()
        state.readiness.set(None)
        state.adapter.set(None)
        state.networks.set(NETS)
        spawn = patch.object(controller, "_spawn", side_effect=lambda coro: coro.close())
        spawn.start()
        self.addCleanup(spawn.stop)
        self.addCleanup(motion.engine.unbind)
        self.addCleanup(dialogs.clear)
        self.addCleanup(controller.stop_ticking)

    async def render(self):
        view = await test_render(App, {"width": 80, "height": 24})
        view.render_frame()
        motion.bind(view.renderer, enabled=True)
        native = native_input(view)
        self.addCleanup(view.destroy)
        self.addCleanup(native.stop)
        return view, native

    def frames(self, view, count=12):
        for _ in range(count):
            view.render_frame()

    async def test_page_scroll_animates_but_enter_uses_current_network_immediately(self):
        view, native = await self.render()
        page = state.list_pages.peek()["scan"]
        native.feed("\x1b[B" * (page - 1))
        self.frames(view)
        native.feed("\x1b[6~")
        view.render_frame()
        target = state.selected.peek()
        self.assertTrue(motion.engine.active())
        self.assertIn(NETS[target].ssid, view.capture_char_frame())
        self.assertNotIn("Действия", view.capture_char_frame())
        native.feed("\r")
        view.render_frame()
        self.assertEqual(state.phase.peek(), "audit")
        self.assertIs(state.audit_network.peek(), NETS[target])
        self.assertFalse(motion.engine.active())

    async def test_menu_enter_during_motion_activates_exactly_one_command(self):
        view, native = await self.render()
        calls = []
        dialogs.open_select("Motion fixture", [Action(f"Fixture {i:02}", lambda i=i: calls.append(i))
                                               for i in range(40)], palette=True)
        view.render_frame()
        native.feed("\x1b[6~")
        view.render_frame()
        target = dialogs.stack.peek()[-1].selected
        self.assertIn(f"Fixture {target:02}", view.capture_char_frame())
        native.feed("\r")
        view.render_frame()
        self.assertEqual(calls, [target])
        self.assertFalse(dialogs.active())
        self.assertEqual(state.phase.peek(), "scan")

    async def test_wheel_scroll_during_motion_keeps_enter_on_visible_network(self):
        view, native = await self.render()
        native.feed("\x1b[<65;5;7M" * 4)
        view.render_frame()
        selected = state.selected.peek()
        self.assertGreater(state.network_scroll_offset.peek(), 0)
        self.assertTrue(motion.engine.active())
        self.assertIn(f"› {NETS[selected].ssid}", view.capture_char_frame())
        native.feed("\r")
        view.render_frame()
        self.assertEqual(state.phase.peek(), "audit")
        self.assertIs(state.audit_network.peek(), NETS[selected])
        self.assertFalse(motion.engine.active())

    async def test_resize_and_filter_reset_motion_and_keep_selected_row_visible(self):
        view, native = await self.render()
        native.feed("\x1b[B" * 8 + "\x1b[6~")
        view.render_frame()
        selected = state.selected.peek()
        view.resize(44, 16)
        view.render_frame()
        self.assertIn(NETS[selected].ssid, view.capture_char_frame())
        scan.set_query(NETS[selected].ssid)
        view.render_frame()
        self.assertFalse(motion.engine.active())
        self.assertIn(NETS[selected].ssid, view.capture_char_frame())
        state.replace_networks([replace(NETS[selected], signal=95)])
        view.render_frame()
        self.assertIn("95%", view.capture_char_frame())

    async def test_held_arrow_burst_keeps_rendering_and_never_opens_a_dialog(self):
        from opentui.input._backend_buffer import BufferBackend
        from opentui.renderer._session import bind_event_loop
        from wifi_tool.ui.terminal_input import ResponsiveInputHandler

        nets = [replace(NETS[0], ssid=f"Fixture {i:03}", bssid=f"00:00:00:00:{i // 256:02x}:{i % 256:02x}")
                for i in range(400)]
        state.networks.set(nets)
        view, native = await self.render()
        native.stop()
        backend = BufferBackend()
        handler = ResponsiveInputHandler(backend=backend)
        handler.start()
        self.addCleanup(handler.stop)
        bind_event_loop(view.renderer, SimpleNamespace(input_handler=handler, on_frame=lambda cb: None))
        backend.feed("\x1b[B" * 300)
        frames = 0
        started = time.monotonic()
        while backend.has_data():
            before = state.selected.peek()
            while handler.poll():
                pass
            self.assertLessEqual(state.selected.peek() - before, 32)
            view.render_frame()
            self.assertFalse(dialogs.active())
            self.assertIn(nets[state.selected.peek()].ssid, view.capture_char_frame())
            frames += 1
        self.assertGreater(frames, 9)
        self.assertEqual(state.selected.peek(), 300)
        self.assertLess(time.monotonic() - started, 3)
        backend.feed("\x1b[C\x1b[D")
        for _ in range(2):
            while handler.poll():
                pass
            view.render_frame()
            self.assertFalse(dialogs.active())
        backend.feed("\r")
        while handler.poll():
            pass
        view.render_frame()
        self.assertEqual(state.phase.peek(), "audit")
        self.assertIs(state.audit_network.peek(), nets[300])


if __name__ == "__main__":
    unittest.main()
