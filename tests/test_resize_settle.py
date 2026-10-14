"""Resize settling: a dragged window must cost one repaint, not dozens.

OpenTUI applies every polled size immediately on Windows and waits for the
window to stop moving only on Unix. Each applied size forces a full repaint,
so the difference between the two is the difference between a window that
follows the cursor and one that comes apart while it is being dragged.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool.ui import terminal_input  # noqa: E402

SKIP = unittest.skipUnless(os.name == "nt", "the settled path is Windows-only")


class FakeLoop:
    """The parts of ``EventLoop`` the resize handling actually touches."""

    def __init__(self):
        self._resize_pending = False
        self._last_resize_time = 0.0
        self._settle_installed = False
        self._resize_handlers = []

    def on_frame(self, callback):
        self._resize_handlers.append(callback)

    def frame(self):
        for callback in list(self._resize_handlers):
            callback(1 / 60)


class Clock:
    """A hand-cranked clock, so settling is tested without waiting for it."""

    def __init__(self):
        self.now = 100.0

    def perf_counter(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@SKIP
class SettledResizeTests(unittest.TestCase):
    def setUp(self):
        from opentui.input import event_loop

        self.event_loop = event_loop
        self.original = event_loop.EventLoop._handle_resize
        self.addCleanup(setattr, event_loop.EventLoop, "_handle_resize", self.original)
        self.applied = []
        self.size = (100, 40)
        self.clock = Clock()

    def _install(self):
        """Install the wrapper over a stand-in that records what it applied."""
        loop = self.event_loop
        applied = self.applied

        def record(self):
            # The real handler re-reads the size when it finally runs; so does
            # this one, which is what makes a drag that ends somewhere new
            # measurable correctly.
            applied.append(self.current)

        loop.EventLoop._handle_resize = record
        terminal_input._settled_resize()

        handler = loop.EventLoop._handle_resize
        fake = FakeLoop()
        fake.current = self.size
        fake._handle_resize = handler.__get__(fake, FakeLoop)
        return fake

    def _run(self, loop, sizes, settle_between=False):
        """Feed sizes through the polling branch the way the frame loop does."""
        for size in sizes:
            self.size = size
            loop.current = size
            with patch.object(terminal_input.time, "perf_counter",
                              self.clock.perf_counter), \
                    patch("shutil.get_terminal_size", lambda fallback=None: loop.current):
                if loop.current != self._previous(loop):
                    loop._last_term_size = loop.current
                    loop._handle_resize()
                self.clock.advance(0.016)
                loop.frame()
                if settle_between:
                    # The window holds still: give the loop the frames it needs
                    # to notice that the size has settled.
                    self.clock.advance(terminal_input.RESIZE_SETTLE_SECONDS)
                    loop.frame()

    def _previous(self, loop):
        return getattr(loop, "_last_term_size", None)

    def test_a_drag_applies_nothing_until_it_stops(self):
        loop = self._install()
        drag = [(99, 40), (98, 40), (95, 38), (90, 34), (80, 30)]
        self._run(loop, drag)

        self.assertEqual(self.applied, [],
                         "every intermediate size reached the renderer, which is "
                         "the tearing: each one forces a full repaint")
        self.assertTrue(loop._resize_pending,
                        "the last size must still be waiting to be applied")
        self.assertTrue(loop._settle_installed)

    def test_each_settled_change_is_applied(self):
        """Settling must not swallow resizes -- only postpone them.

        Three separate resizes, each given its quiet period, are three resizes.
        If this ever comes out empty the fix has quietly turned into "ignore the
        terminal size", which is worse than the tearing.
        """
        loop = self._install()
        self._run(loop, [(99, 40), (98, 40), (80, 30)], settle_between=True)
        self.assertEqual(self.applied, [(99, 40), (98, 40), (80, 30)])
        self.assertFalse(loop._resize_pending,
                         "a settled resize left the loop waiting forever")

    def test_a_lone_resize_still_lands(self):
        loop = self._install()
        self._run(loop, [(80, 30)], settle_between=True)
        self.assertEqual(self.applied, [(80, 30)])

    def test_the_wrapper_is_removed_when_the_session_ends(self):
        before = self.event_loop.EventLoop._handle_resize
        with terminal_input.terminal_session():
            self.assertIsNot(self.event_loop.EventLoop._handle_resize, before)
        self.assertIs(self.event_loop.EventLoop._handle_resize, before)


class RendererConfigTests(unittest.TestCase):
    def test_the_renderer_is_told_instead_of_guessed(self):
        config = terminal_input.renderer_config()
        self.assertTrue(config["use_alternate_screen"],
                        "nothing the app draws should reach the terminal's scrollback")
        self.assertIs(config["use_mouse"], True,
                      "left to a guess, an unhandled wheel scrolls the terminal")


if __name__ == "__main__":
    unittest.main()