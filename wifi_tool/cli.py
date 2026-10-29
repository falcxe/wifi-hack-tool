"""The WiFi crack TUI: argument parsing, UAC elevation, and the render loop.
Reached two ways, and both must keep working: 'wifi-tool' (or 'python -m
wifi_tool') from an installed package, and 'python main.py' from a clone, which
is a two-line wrapper around here. The UAC re-launch restarts sys.argv[0], so
under the first it re-runs the console script and under the second the file --
both land back in main() below.

Options:
  --file PATH   Crack an existing capture (.pcap/.pcapng/.22000) instead of
                scanning. Useful without admin rights or capture hardware.
  --auto        Start in the one-key automatic mode. In the TUI this is what
                Enter does on a selected network.
  --no-elevate  Do not ask for administrator rights.
"""
from __future__ import annotations

import asyncio
import argparse
import os
import sys
from pathlib import Path

from opentui import render

from . import __version__
from .assets import is_admin, relaunch_elevated
from .console import enable_utf8_console
from .options import CrackOptions
from .ui import controller
from .ui.app import App
from .ui.terminal_input import renderer_config, terminal_session


def _parse_args(argv: list[str]) -> dict:
    parser = argparse.ArgumentParser(description="Аудит пароля собственной Wi-Fi сети")
    parser.add_argument("--file", help="готовый захват .pcap/.pcapng или файл .22000")
    candidates = parser.add_mutually_exclusive_group()
    candidates.add_argument("--wordlist", type=Path, help="свой словарь кандидатов")
    candidates.add_argument("--mask", help="маска hashcat, например 'MyHome?d?d'")
    parser.add_argument("--rules", type=Path, help="файл правил для словаря")
    parser.add_argument("--no-rules", action="store_true", help="проверять словарь без мутаций")
    parser.add_argument("--runtime", type=int, default=600, help="лимит подбора в секундах (600)")
    parser.add_argument(
        "--auto",
        action="store_true",
        help="автоматический режим: без вопросов, Enter в TUI делает то же",
    )
    parser.add_argument("--bssid", help="целевая точка доступа в файле захвата")
    parser.add_argument("--no-elevate", action="store_true")
    opts = vars(parser.parse_args(argv))
    # --auto and --wordlist/--mask describe the same run in two ways; say so
    # instead of silently letting one of them win.
    if opts["auto"] and (opts["wordlist"] or opts["mask"] or opts["no_rules"]):
        parser.error("--auto нельзя сочетать с --wordlist, --mask или --no-rules")
    audit = CrackOptions(
        wordlist=opts["wordlist"], rules=opts["rules"], mask=opts["mask"],
        runtime=opts["runtime"], bssid=opts["bssid"], use_rules=not opts["no_rules"],
    )
    try:
        audit.validate()
    except ValueError as exc:
        parser.error(str(exc))
    opts["crack_options"] = audit
    return opts


def _elevate() -> bool:
    """Re-launch elevated; returns True if the new process owns the session."""
    print("Нужны права администратора: перезапускаю с повышением привилегий...")
    ok = relaunch_elevated()
    if not ok:
        print(
            "Не удалось получить права администратора.\n"
            "Запусти вручную: правый клик по терминалу -> \"Запуск от имени администратора\"."
        )
    return ok


async def _run(pending_path: str | None, automatic: bool = False) -> None:
    """Start the UI and schedule bootstrap on the controller's background loop.

    The boot task is created here rather than in a mount callback so it does not
    depend on when (or whether) the renderer flushes mount callbacks. OpenTUI's
    renderer blocks while running its frame loop, so the controller owns a
    separate event loop for the asynchronous pipeline.

    ``automatic`` is what ``--auto`` asks for: run the one-key path with no
    questions asked. With a capture file there is nothing to choose, so it starts
    immediately; otherwise the scan has to finish first to know the target.
    """
    controller.bind(None)
    if pending_path and automatic:
        controller.start_capture_run(pending_path)
    elif pending_path:
        controller.open_crack_form(capture=pending_path, from_cli=True)
    elif automatic:
        controller.boot_auto()
    else:
        controller.boot()
    try:
        with terminal_session():
            await render(App, renderer_config())
    finally:
        controller.stop_pending()


def _strip_self_path(argv: list[str]) -> list[str]:
    """Drop any argument that is just the running executable's own path.

    Observed on Windows 11 with Windows Terminal set as the default console
    host: double-clicking the exe in Explorer launches it with its own path
    repeated as an argument, on top of the one already in ``sys.argv[0]``.
    This parser has no positional argument at all -- every option is a flag --
    so a bare token identical to the executable's path can never be real
    input; left in, it is the whole difference between a double-click that
    opens the TUI and one that prints "unrecognized arguments: <that same
    path>" and exits.
    """
    self_path = os.path.normcase(os.path.abspath(sys.argv[0]))
    return [a for a in argv if os.path.normcase(os.path.abspath(a)) != self_path]


def main() -> int:
    opts = _parse_args(_strip_self_path(sys.argv[1:]))
    controller.configure_cracking(opts["crack_options"])

    # Before anything is drawn: a Windows console left on code page 866 turns
    # every box-drawing character and Cyrillic letter into mojibake, because
    # Python writes UTF-8 and the console decodes it as CP866.
    for note in enable_utf8_console():
        print(f"[консоль] {note}")

    # enable_utf8_console exports PYTHONIOENCODING for child processes, but this
    # process's own streams were already bound to the locale at startup. Left
    # alone they keep encoding as CP1251/CP866 and every label comes out as
    # mojibake, which is what the board output used to trigger.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover - exotic hosts
            pass

    # An existing capture needs neither scanning nor live capture, so it works
    # fine without administrator rights.
    if not opts["no_elevate"] and not opts["file"] and not is_admin():
        if _elevate():
            return 0

    asyncio.run(_run(opts["file"], opts["auto"]))
    return 0


