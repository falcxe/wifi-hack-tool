"""Catch a handshake on the connected board, then crack it. Run this and watch.

    python catch.py            # listen on the board for a handshake
    python catch.py --crack    # ...and crack whatever is pulled

Why a separate script and not just the TUI: the one step nobody can automate is
a client reconnecting, because that is what a handshake *is*. So this prints a
visible countdown and says what to do with the phone while it waits, instead of
that message arriving in a terminal after the wait has already timed out.

The board does the listening (its radio can do monitor mode, this PC's cannot)
and this program does the guessing, the same split the TUI uses.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wifi_tool import bruce, pipeline  # noqa: E402
from wifi_tool.assets import load_assets  # noqa: E402
from wifi_tool.models import Network  # noqa: E402
from wifi_tool.options import ensure_captures_dir  # noqa: E402


def listen(seconds: int) -> Path | None:
    dest = ensure_captures_dir()
    board = bruce.first_board()
    if board is None:
        found = bruce.find_boards()
        if not found:
            print("Плата не найдена. Подключи M5StickC по USB и проверь, что он в паре с Bruce.")
        else:
            print(f"Плата есть ({found[0]}), но не отвечает как Bruce: {found[0]}")
        return None
    try:
        print(f"Плата: {board.info}")
        if board.firmware:
            print(f"Прошивка: {board.firmware}")

        ready = board.captures_present()
        if ready:
            print(f"На плате уже есть: {', '.join(e.name for e in ready)}")
        else:
            board.start_sniffer()
            print("\n" + "=" * 64)
            print("  СНИФФЕР ИДЁТ.  Выключи и включи Wi-Fi на телефоне.")
            print("  Рукопожатие появится в момент переподключения.")
            print("=" * 64 + "\n")

        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(4)
            pulled = board.pull_captures(dest)
            if pulled:
                found = pulled[-1]
                print(f"\nПоймали: {found.name}  ({found.stat().st_size} байт)")
                return found
            left = max(0, int(deadline - time.monotonic()))
            print(f"  жду...  осталось {left // 60}:{left % 60:02d}", end="\r", flush=True)
        print("\nРукопожатие не поймано. Возможно, телефон не переподключался.")
        return None
    finally:
        board.close()


def crack(path: Path) -> None:
    """Convert and guess, without asking anything."""
    assets = load_assets()
    net = Network(ssid=path.stem.split("-")[0] or "сеть", bssid="",
                  auth="WPA2-Personal", channel=0, signal=0)
    print(f"\nРазбираю {path.name} и подбираю...")
    result = asyncio.run(pipeline.auto_attack(
        net, capture_path=path,
        hashcat_path=assets.hashcat,
        wordlist=assets.wordlist,
    ))
    if result.success:
        print(f"\n  ПАРОЛЬ НАЙДЕН: {result.password}   ({result.method})")
    else:
        print(f"\n  Не нашлось. {result.error}")
        print(f"  Файл остался: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Рукопожатие с платы и подбор")
    parser.add_argument("--seconds", type=int, default=180,
                        help="сколько слушать (по умолчанию 180)")
    parser.add_argument("--crack", action="store_true",
                        help="сразу подобрать пароль после поимки")
    args = parser.parse_args()

    found = listen(args.seconds)
    if found is None:
        return 1
    if args.crack:
        crack(found)
    else:
        print(f"  Файл: {found}")
        print("  Подобрать пароль: python catch.py --crack")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
