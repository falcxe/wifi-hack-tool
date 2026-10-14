"""Set the machine up: Python packages, then the external tools.

    uv run python tools/setup.py

Both halves in one place on purpose. ``uv sync`` covers what pip can install;
this covers what it cannot -- hashcat and wpawolf are Windows binaries with no
Python package, so they are downloaded here with a pinned SHA-256 and unpacked
into ``assets/``.

Run it on a fresh clone and the result is a machine ready to pick a password:
every dependency present, hashcat unpacked and findable, wordlists in place.
Re-running is safe and cheap -- what is already installed is reported and
skipped, and ``--force`` reinstalls one tool by key.
"""
from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool import installer  # noqa: E402
from wifi_tool.console import enable_utf8_console  # noqa: E402
from wifi_tool.cracker import find_hashcat  # noqa: E402
from wifi_tool.options import ensure_captures_dir, find_quick_wordlist  # noqa: E402


def _utf8() -> None:
    """Print Cyrillic as text, not as mojibake.

    A Windows console on code page 866 decodes this script's UTF-8 output as
    CP866, and every Russian word below turns into ``�``. The app solves this
    for itself at startup; setup runs before it, so it has to solve it here.
    """
    for note in enable_utf8_console():
        print(f"[консоль] {note}")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover - exotic hosts
            pass


def _rule(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def _check_deps() -> bool:
    """Report the Python packages, which uv owns rather than this script."""
    try:
        import opentui  # noqa: F401
        import serial  # noqa: F401
    except ImportError as exc:
        print(f"  [!] не хватает Python-пакета: {exc.name}")
        print("      поставь их одной командой:")
        print("        uv sync")
        return False

    import opentui
    import serial
    print(f"  opentui {getattr(opentui, '__version__', '?')}  "
          f"pyserial {serial.__version__}")
    return True


def _check_words() -> None:
    quick = find_quick_wordlist()
    if quick:
        print(f"  быстрый словарь: {quick.name}")
    else:
        print("  [!] быстрого словаря нет -- положи probable-wpa.txt в assets/")


def _check_captures() -> None:
    try:
        path = ensure_captures_dir()
        print(f"  папка захватов: {path}")
    except Exception as exc:  # noqa: BLE001 - not worth failing setup over
        print(f"  (!) папка captures/ недоступна: {exc}")


def _install_words(only_check: bool) -> int:
    """Fetch the dictionaries. Returns the number that failed."""
    if only_check:
        found = installer.installed_wordlists()
        for name, path in found.items():
            print(f"  [OK] {name:<18} {path.name}")
        if not found:
            print("  [--] словарей нет")
        return 0

    results = installer.install_wordlists(on_log=lambda line: print(f"  {line}"))
    failed = 0
    for key, outcome in results.items():
        title = "RockYou WPA" if key == "rockyou" else "частые пароли"
        if outcome == "ok":
            print(f"  [OK] {title}")
        else:
            failed += 1
            print(f"  [!!] {title}: {outcome}")
    return failed


async def _install_tools(only: list[str] | None) -> int:
    """Download and unpack the binaries; return a process exit code."""
    wanted = only or [t.key for t in installer.TOOLS.values()]
    results = await installer.install_all(
        wanted, on_log=lambda line: print(f"  {line}")
    )
    failed = 0
    for key, outcome in results.items():
        tool = installer.TOOLS.get(key)
        title = tool.title.split(" (")[0] if tool else key
        if outcome == "ok":
            print(f"  [OK] {title}")
        else:
            failed += 1
            print(f"  [!!] {title}: {outcome}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Полная установка wifi_tool: зависимости и внешние программы")
    parser.add_argument("--only", nargs="+", metavar="KEY",
                        help="поставить только эти инструменты: "
                             + ", ".join(installer.TOOLS))
    parser.add_argument("--check", action="store_true",
                        help="только показать состояние, ничего не качать")
    parser.add_argument("--force", action="store_true",
                        help="переустановить выбранное, даже если оно уже есть")
    args = parser.parse_args()

    _utf8()
    print("wifi_tool — установка")
    print("=" * 40)

    _rule("1. Python-пакеты")
    deps_ok = _check_deps()

    _rule("2. Внешние программы")
    if args.check:
        for tool in installer.TOOLS.values():
            mark = "[OK]" if installer.is_installed(tool) else "[--]"
            print(f"  {mark} {tool.title}")
        print(f"\n  hashcat: {find_hashcat() or 'не найден'}")
    else:
        keys = args.only
        if args.force and keys:
            for key in keys:
                tool = installer.TOOLS.get(key)
                if tool is None:
                    continue
                target = tool.target
                import shutil
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target, ignore_errors=True)
                    else:
                        target.unlink(missing_ok=True)
        code = asyncio.run(_install_tools(keys))
        if code and not keys:
            print("\n  Продолжаю: подбор заработает для готовых файлов захвата,")
            print("  а для живой атаки нужен hashcat — см. F1 → Установить компоненты.")

    _rule("3. Словари")
    if args.only:
        # A targeted reinstall should not start pulling a 53 MB archive.
        _check_words()
    else:
        words_failed = _install_words(args.check)
        if words_failed and not args.check:
            print("\n  Без RockYou лестница остаётся на кандидатах по имени сети")
            print("  и масках. Скачать позже: uv run python tools/setup.py")

    _rule("4. Рабочие папки")
    _check_captures()

    _rule("Готово")
    print("  Запуск: uv run wifi-tool")
    if not deps_ok:
        print("  Сначала: uv sync")
    return 0 if deps_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())