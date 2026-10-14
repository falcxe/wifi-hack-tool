"""Build assets/wpa-extra.txt from borrowed wordlists.

    uv run python tools/build_extra_wordlist.py --out assets/wpa-extra.txt

Why this is a script and not a committed blob
---------------------------------------------
The four source lists (AuthMe, PSQ, notpull, dict) are other people's
downloads. Committing them would put ~15 MB of somebody's collection into this
repository for no benefit -- the script is the artifact, and running it on a
machine that already has the files is one command.

What comes out
--------------
Only what RockYou does not already have, and only what could be a WPA key at
all. Measured on the 14 October 2026 sources:

* 2.2M source lines -> 768k pass the WPA length filter (8..63 bytes);
* minus RockYou -> **682k candidates rockyou-wpa.txt does not contain**.

The shape of those 682k is what makes it worth a rung of the ladder: it is
overwhelmingly ``имя+год`` / ``имя+цифры`` / gaming handles, and among them
14,391 nine-digit numbers and 52,125 eight-digit ones. Those are exactly the two
passwords the digit masks brute-force blind -- a nine-digit mask is a *billion*
candidates and about 24 minutes of a 4060 Ti, where this list checks the same
ground in well under a second.

Ordering
--------
Sorted by descending likelihood, so that if a stage is ever truncated it is the
tail that gets cut. Pure digits sort last within the file for the same reason:
they are the shape the masks already cover exhaustively, so a known list of them
is mostly redundant, but a *known* one costs nothing and the unknown ones are
worth the whole file.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool.cracker import find_hashcat  # noqa: E402
from wifi_tool.options import ASSETS_DIR, find_wordlist  # noqa: E402

MIN_PSK_BYTES = 8
MAX_PSK_BYTES = 63


def _usable(line: str) -> bool:
    """A WPA key is 8..63 bytes; hashcat's own padding and this agree.

    Counting bytes rather than characters is the whole point: ``пароль`` is 12
    characters but 16 bytes in UTF-8, and a dictionary filtered by character
    count either throws real eight-byte keys away or lets in six-byte ones.
    """
    return MIN_PSK_BYTES <= len(line.encode("utf-8", "ignore")) <= MAX_PSK_BYTES


def _read(paths: list[Path]) -> set[str]:
    seen: set[str] = set()
    for path in paths:
        if not path.is_file():
            print(f"  пропущено, нет файла: {path}")
            continue
        added = 0
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line in seen:
                    continue
                # A candidate that is only whitespace would be read back from
                # the file as an empty line, which hashcat counts as one.
                if not line.strip() or not _usable(line):
                    continue
                seen.add(line)
                added += 1
        print(f"  {path.name}: +{added}")
    return seen


def build(sources: list[Path], baseline: Path, out: Path) -> dict[str, int]:
    print("Читаю исходники:")
    pool = _read(sources)
    print(f"  уникальных кандидатов WPA: {len(pool)}")

    print(f"Вычитаю {baseline.name}:")
    seen_here = 0
    with baseline.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if line and line in pool:
                pool.discard(line)
                seen_here += 1
    print(f"  уже было в rockyou: {seen_here}")
    print(f"  осталось новых: {len(pool)}")

    digits = sorted((s for s in pool if s.isdigit()), key=lambda s: (len(s), s))
    words = sorted((s for s in pool if not s.isdigit()), key=lambda s: (len(s), s))
    # A mask covers all-digit passwords exhaustively, so a known digit is a
    # bonus rather than the point; everything else is the point. Both sorts run
    # shortest-first inside their group: a truncated list should keep the keys
    # that fit in a phone's memory and the ones people actually type, and both
    # are overwhelmingly short.
    ordered = words + digits

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for line in ordered:
            fh.write(line + "\n")

    stats = {
        "всего": len(ordered),
        "с буквами": len(words),
        "только цифры": len(digits),
        "цифр на 8": sum(1 for s in digits if len(s) == 8),
        "цифр на 9": sum(1 for s in digits if len(s) == 9),
    }
    print(f"\nЗаписано в {out}:")
    for key, value in stats.items():
        print(f"  {key:<14} {value:>9,}".replace(",", " "))
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sources", nargs="*", type=Path,
                        help="исходные словари (по умолчанию -- из --source-dir)")
    parser.add_argument("--source-dir", type=Path,
                        help="папка с исходниками; берёт AuthMe_top.txt, psq.txt, "
                             "notpull.txt, dict.txt, если они там есть")
    parser.add_argument("--baseline", type=Path,
                        help="словарь-эталон для вычитания "
                             "(по умолчанию rockyou-wpa из assets/)")
    parser.add_argument("--out", type=Path, default=ASSETS_DIR / "wpa-extra.txt")
    args = parser.parse_args()

    sources = list(args.sources)
    if not sources and args.source_dir:
        sources = [args.source_dir / name for name in
                   ("AuthMe_top.txt", "psq.txt", "notpull.txt", "dict.txt")]
    if not sources:
        parser.error("передай исходники путями или через --source-dir")

    baseline = args.baseline or find_wordlist()
    if baseline is None or not baseline.is_file():
        parser.error("не найден эталон rockyou-wpa.txt -- положи его в assets/ "
                     "или укажи --baseline")

    hashcat = find_hashcat()
    print(f"hashcat: {hashcat or 'не найден — проверь tools/setup.py'}\n")

    build(sources, baseline, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())