"""Render every screen at 80x24 and print the full frame."""
import asyncio
import argparse
from dataclasses import asdict
import html
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from opentui.testing import test_render

from wifi_tool import profiles
from wifi_tool.models import CrackResult, Network
from wifi_tool.ui import forms, state
from wifi_tool.ui.app import App
from wifi_tool.ui import controller, dialogs
from wifi_tool.ui.theme import CANVAS

NETS = [
    Network("MyHomeWiFi", "aa:bb:cc:dd:ee:ff", 6, 92, "WPA2-Personal", "CCMP"),
    Network("neighbor_5G", "11:22:33:44:55:66", 36, 76, "WPA2-Personal", "CCMP"),
    Network("CafeFree", "77:88:99:aa:bb:cc", 11, 55, "Open", ""),
]


def frame(setup, width=80, height=24):
    async def go():
        state.reset()
        setup()
        obj = await test_render(App, {"width": width, "height": height})
        obj.render_frame()
        return obj

    obj = asyncio.run(go())
    text = obj.capture_char_frame()
    obj.destroy()
    return text


def scan():
    state.phase.set("scan")
    state.networks.set(NETS)
    state.selected.set(0)


def audit():
    state.phase.set("audit")
    state.audit_network.set(NETS[0])


def form():
    forms.open_form(NETS[0])


def crack():
    state.phase.set("crack")
    state.cracking_network.set(NETS[0])
    state.log.set(["$ hashcat -m 22000 --status", "Статус: работаю",
                   "hashcat (v7.1.2) : 14235.6 kH/s"])
    state.progress.set(0.42)
    state.status.set("Этап 3/6: RockYou WPA")


def capturing():
    state.phase.set("crack")
    state.cracking_network.set(NETS[0])
    state.log.set(["$ tshark -i 12 -I 6 -a duration:300 -w own.pcapng",
                   "Захват рукопожатия/PMKID, до 5м 00с (остановлюсь, как только поймаю)..."])
    state.status.set("Захват PMKID / рукопожатия")
    state.capture_left.set(37)
    state.capture_bytes.set(184_320)


def result():
    state.phase.set("result")
    state.result.set(CrackResult(
        network=NETS[0], success=False, method="—", elapsed=93,
        error="Хэш не получен.\nВозможные причины:\n  • клиент не переподключался",
        remedy="Попробуй другой словарь."))


def export_frames(output: Path) -> None:
    """Rasterize the actual OpenTUI cell buffer, with its captured colors.

    This is a headless terminal capture, not a design mockup. Plain frames and
    styled cell spans are kept beside the PNGs so every image is reproducible.
    """
    from PIL import Image, ImageDraw, ImageFont
    from tests.test_secondary_ui import setup_case
    from tests.test_tui_setup import FIXTURE
    from tests.test_ui_redesign import SIZES

    output.mkdir(parents=True, exist_ok=True)
    font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 18)
    bold = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 18)
    cell_width, cell_height, padding = round(font.getlength("M")), 24, 16
    names = ("scan", "audit", "form", "running", "running-capture", "result-success",
             "result-failure", "saved", "saved-empty", "saved-loading", "file-picker", "targets",
             "help", "commands", "stop", "form-install", "board-wait", "board-audit")
    manifest = []

    def color(rgba):
        return tuple(round(max(0.0, min(1.0, getattr(rgba, channel))) * 255) for channel in ("r", "g", "b"))

    async def capture(name, width, height, directory):
        with patch.object(controller, "_spawn", side_effect=lambda coro: coro.close()), patch.object(controller, "start_ticking"):
            if name == "scan":
                state.reset()
                state.adapter.set(None)
                state.networks.set([Network("Домашняя_24", "aa:bb:cc:dd:ee:01", 6, 92, "WPA2-Personal", "CCMP"),
                                    Network("Студия_5G", "aa:bb:cc:dd:ee:02", 36, 76, "WPA3-Personal", "CCMP"),
                                    Network("Гостевая", "aa:bb:cc:dd:ee:03", 11, 55, "Open", ""),
                                    Network("Очень_длинное_имя_домашней_сети", "aa:bb:cc:dd:ee:04", 1, 40, "WPA2-Personal", "TKIP")])
            else:
                setup_case("audit" if name == "commands" else "running" if name == "stop" else name, directory)
                if name == "form":
                    forms.open_form(capture=str(FIXTURE))
                    forms.set_value("mode", "mask")
                    forms.set_value("mask", "Course?d?d")
                    forms.focus(2)
                if name == "commands":
                    from wifi_tool.ui.commands import open_menu
                    open_menu()
                elif name == "stop":
                    from wifi_tool.ui.commands import confirm_stop
                    confirm_stop()
                elif name == "running":
                    state.run_stages.set([("saved", "done"), ("capture", "done"), ("convert", "done"), ("crack", "current")])
                    state.stage.set("Этап 3/6: RockYou WPA")
                    state.progress_known.set(True)
                    state.run_speed.set("684.5 kH/s")
                    state.run_eta.set("1м 20с")
                elif name == "result-failure":
                    state.result.peek().remedy = "Откройте параметры и выберите другой файл захвата."
            view = await test_render(App, {"width": width, "height": height})
            try:
                view.render_frame()
                if state.phase.peek() == "crack":
                    state.elapsed.set(17)
                    state.tick.set(1)
                    view.render_frame()
                plain = view.capture_char_frame()
                styled = view.capture_spans()
                stem = f"{name}-{width}x{height}"
                (output / (stem + ".txt")).write_text(plain, encoding="utf-8")
                (output / (stem + ".json")).write_text(json.dumps(asdict(styled), ensure_ascii=False), encoding="utf-8")
                canvas = Image.new("RGB", (width * cell_width + 2 * padding, height * cell_height + 2 * padding), CANVAS)
                draw = ImageDraw.Draw(canvas)
                for row_index, line in enumerate(styled.lines):
                    column = 0
                    for span in line.spans:
                        left, top = padding + column * cell_width, padding + row_index * cell_height
                        if span.bg.a:
                            draw.rectangle((left, top, left + span.width * cell_width - 1, top + cell_height - 1), fill=color(span.bg))
                        # Draw each glyph at its captured cell coordinate.
                        for character in span.text:
                            from opentui.structs import display_width
                            draw.text((left, top + 2), character, font=bold if span.attributes & 1 else font,
                                      fill=color(span.fg))
                            left += display_width(character) * cell_width
                        column += span.width
                canvas.save(output / (stem + ".png"))
                manifest.append({"screen": name, "width": width, "height": height, "image": stem + ".png", "text": stem + ".txt"})
            finally:
                view.destroy()
                controller.stop_ticking()

    async def run(directory):
        for name in names:
            for width, height in SIZES:
                await capture(name, width, height, directory)

    with tempfile.TemporaryDirectory() as directory:
        asyncio.run(run(Path(directory)))
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    entries = "\n".join(f'<figure><figcaption>{html.escape(item["screen"])} · {item["width"]}×{item["height"]}</figcaption>'
                        f'<a href="{item["text"]}">Текст кадра</a><img src="{item["image"]}" loading="lazy"></figure>'
                        for item in manifest if item["width"] in (44, 80, 120))
    (output / "index.html").write_text('<!doctype html><meta charset="utf-8"><title>WiFi Tool — кадры OpenTUI</title>'
        '<style>body{background:#111619;color:#e1e7e9;font:16px monospace;margin:24px}figure{margin:32px 0}img{display:block;max-width:100%;margin-top:10px}a{color:#8dc9c1}</style>'
        '<h1>Кадры OpenTUI</h1><p>Реальный headless-буфер на фикстурах. Все шесть размеров доступны в manifest.json.</p>' + entries, encoding="utf-8")
    print(f"Exported {len(manifest)} OpenTUI frames: {output.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--export", type=Path)
    args = parser.parse_args()
    if args.export:
        os.environ["WIFI_TOOL_NO_BOARD"] = "1"
        export_frames(args.export)
        raise SystemExit(0)
    for name, fn in (("scan", scan), ("audit", audit), ("form", form),
                     ("capture", capturing), ("crack", crack), ("result", result)):
        print(f"\n{'=' * 78}\n### {name}\n{'=' * 78}")
        print(frame(fn))
    sys.stdout.flush()
