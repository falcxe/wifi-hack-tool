"""Export a moving preview from actual OpenTUI frames and native key parsing."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from PIL import Image, ImageDraw, ImageFont
from opentui.structs import display_width
from opentui.testing import test_render

from tests.test_tui_setup import native_input
from wifi_tool.models import Network
from wifi_tool.ui import controller, dialogs, motion, state
from wifi_tool.ui.app import App
from wifi_tool.ui.theme import CANVAS


def rasterize(view):
    font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 18)
    bold = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 18)
    frame = view.capture_spans()
    canvas = Image.new("RGB", (view.renderer.width * 10 + 32, view.renderer.height * 24 + 32), CANVAS)
    draw = ImageDraw.Draw(canvas)

    def color(value):
        return tuple(round(getattr(value, name) * 255) for name in ("r", "g", "b"))

    for y, line in enumerate(frame.lines):
        x = 16
        top = 16 + y * 24
        for span in line.spans:
            if span.bg.a:
                draw.rectangle((x, top, x + span.width * 10 - 1, top + 23), fill=color(span.bg))
            for char in span.text:
                draw.text((x, top + 2), char, font=bold if span.attributes & 1 else font, fill=color(span.fg))
                x += display_width(char) * 10
    return canvas


async def export(output: Path):
    state.reset()
    state.readiness.set(None)
    state.adapter.set(None)
    state.networks.set([Network(f"Домашняя_{i:02}", f"02:00:00:00:00:{i:02x}",
                                (i % 11) + 1, 92 - i, "WPA2-Personal", "CCMP") for i in range(40)])
    frames, evidence = [], []
    with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()):
        view = await test_render(App, {"width": 80, "height": 24})
        view.render_frame()
        motion.bind(view.renderer, enabled=True)
        native = native_input(view)
        try:
            def take(count):
                for _ in range(count):
                    view.render_frame()
                    frames.append(rasterize(view))
                    evidence.append({"phase": state.phase.peek(), "selected": state.selected.peek(),
                                     "file_selected": state.file_selected.peek(),
                                     "active": motion.engine.active(),
                                     "offsets": {name: lane.value(motion.engine.now)
                                                 for name, lane in motion.engine.scrolls.items()}})

            take(24)
            for _ in range(8):
                native.feed("\x1b[B")
                take(6)
            native.feed("\x1b[6~")
            take(24)
            native.feed("\x1b[5~")
            take(24)
            native.feed("\x1bOP")
            take(12)
            for _ in range(4):
                native.feed("\x1b[B")
                take(6)
            take(12)
            native.feed("\x1b")
            state.file_entries.set([Path(f"C:/Captures/session_{i:02}.pcapng") for i in range(50)])
            state.file_directory.set("C:/Captures")
            state.file_selected.set(0)
            state.file_error.set("")
            state.phase.set("file_picker")
            take(18)
            for _ in range(6):
                native.feed("\x1b[B")
                take(6)
            native.feed("\x1b[6~")
            take(30)
        finally:
            native.stop()
            view.destroy()
            motion.engine.unbind()
            controller.stop_ticking()
            dialogs.clear()
    output.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(output, save_all=True, append_images=frames[1:], duration=20,
                   loop=0, disposal=2, optimize=False)
    output.with_suffix(".json").write_text(json.dumps(evidence, ensure_ascii=False), encoding="utf-8")
    frames[54].save(output.with_suffix(".png"))
    print(f"Exported {len(frames)} actual animated frames: {output.resolve()}")


if __name__ == "__main__":
    os.environ["WIFI_TOOL_NO_BOARD"] = "1"
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path, default=Path("ui_artifacts/motion-preview.gif"))
    asyncio.run(export(parser.parse_args().output))
