"""What the ``extra`` stage is worth, measured against real hashcat.

Two claims need checking, and only one of them can be checked by cracking:

*Cost.* The stage costs what it claims -- run it against a real handshake and
time it. The ladder prints ~1 s from a size estimate; this is the wall clock.

*Correctness.* A password that IS in wpa-extra.txt must be found when hashcat
reads that one-line list. The fixture's own password cannot be used for this:
it is ``12345678``, which rockyou already has, and the whole point of the file
is entries rockyou does not have. So this half checks the mechanics on a known
password and the coverage separately, by counting.

What this cannot do is crack an arbitrary password from a real handshake -- the
password of a given handshake is fixed by the exchange, so there is nothing to
choose. Anything claiming otherwise would be measuring a fixture it made up.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool import auto, hc22000  # noqa: E402
from wifi_tool.options import ASSETS_DIR, find_extra_wordlist  # noqa: E402

FIXTURE = (Path(__file__).resolve().parent.parent / "tests" / "fixtures"
           / "wpa2_psk_12345678.pcapng")
FIXTURE_PASSWORD = "12345678"


def hashcat_dir() -> Path | None:
    from wifi_tool.cracker import find_hashcat

    exe = find_hashcat()
    return Path(exe).parent if exe else None


def count_digits(extra: Path, length: int) -> int:
    """How many all-digit entries of exactly this length the file holds."""
    seen = set()
    with extra.open(encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if len(s) == length and s.isdigit():
                seen.add(s)
    return len(seen)


def run(hash_dir: Path, hashes: Path, args: list[str], limit: float) -> tuple[str, float]:
    """Run hashcat; return (verdict, wall-clock seconds).

    Two things this deliberately does NOT do by hand, because both are traps:

    * ``-p`` is ``--separator`` in hashcat 7.x, not ``--potfile``. The potfile
      path is ``--potfile-path=`` and only long-form. ``-p <file>`` fails with
      "Separator length has to be exactly 1 byte" and, worse, silently keeps
      reading the default potfile -- which already holds the answer and turns a
      real run into "All hashes found as potfile entries" before any candidate
      is tried.
    * The hash file must come before the wordlist. With the wordlist last and
      unlabelled, hashcat tries to parse the *wordlist* as hashes and reports
      "No hashes loaded".

    The project's own ``_build_command`` already encodes both rules, so it is
    used here rather than a hand-rolled command that would drift from it.
    """
    from wifi_tool.cracker import _build_command

    pot = Path(tempfile.gettempdir()) / f"verify_extra_{uuid4().hex}.potfile"
    target = args[0]
    is_mask = target.startswith("?d")
    # wordlist must be a real path even for a mask run: _build_command appends it
    # unconditionally when mask is None, and a literal "None" on the command
    # line is a filename hashcat will not find.
    cmd = _build_command(
        (hash_dir / "hashcat.exe").resolve(), hashes.resolve(),
        Path(target).resolve(), None, pot,
        mask=target if is_mask else None,
        timeout=limit,
    )
    started = time.monotonic()
    proc = subprocess.run(cmd, cwd=hash_dir, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=limit + 30)
    elapsed = time.monotonic() - started
    out = ((proc.stdout or "") + (proc.stderr or ""))
    low = out.lower()

    # The potfile is the only dependable verdict here. hashcat 7.x stopped
    # printing "Cracked"/"Exhausted" for a dictionary run, and --status-json
    # does not help: on a run this short the timer never fires, so there is no
    # status line at all to read and every string match reports "unknown" on a
    # run that in fact succeeded. A crack always writes "<hash>:<password>" to
    # the potfile, so its content is the answer either way.
    cracked = False
    password = ""
    if pot.exists() and pot.stat().st_size:
        body = pot.read_text(encoding="utf-8", errors="replace")
        cracked = ":" in body
        if cracked:
            password = body.strip().rsplit(":", 1)[-1]
    pot.unlink(missing_ok=True)

    if cracked:
        return (f"Cracked ({password})" if password else "Cracked"), elapsed
    if "all hashes found as potfile" in low:
        return "SKIPPED(уже в potfile)", elapsed
    if "exhausted" in low:
        return "Exhausted", elapsed
    return f"не найдено (код {proc.returncode})", elapsed


def main() -> int:
    extra = find_extra_wordlist(ASSETS_DIR)
    hash_dir = hashcat_dir()
    if extra is None:
        raise SystemExit("нет assets/wpa-extra.txt -- построй его "
                         "tools/build_extra_wordlist.py")
    if hash_dir is None:
        raise SystemExit("нет hashcat -- поставь tools/setup.py")
    if not FIXTURE.is_file():
        raise SystemExit(f"нет фикстуры {FIXTURE}")

    print("=" * 64)
    print("Проверка этапа 'extra' настоящим hashcat")
    print("=" * 64)

    rate = auto.Rate()
    stage = auto.Stage("extra", "", extra)
    mask8 = auto.Stage("digits", "", mask="?d?d?d?d?d?d?d?d")
    mask9 = auto.Stage("digits", "", mask="?d?d?d?d?d?d?d?d?d")

    print("\n1. Сколько кандидатов в файле")
    print(f"   всего в wpa-extra.txt      : {int(stage.candidates()):>12,}")
    n8, n9 = count_digits(extra, 8), count_digits(extra, 9)
    print(f"   из них только цифр, 8 шт.   : {n8:>12,}")
    print(f"   из них только цифр, 9 шт.   : {n9:>12,}")

    print("\n2. Сколько это стоит по сравнению с масками")
    print(f"   этап extra                 : {stage.seconds(rate):>9.1f} с")
    print(f"   маска 8 цифр               : {mask8.seconds(rate):>9.1f} с"
          f"  ({int(mask8.candidates()):,} кандидатов)")
    print(f"   маска 9 цифр               : {mask9.seconds(rate):>9.1f} с"
          f"  ({int(mask9.candidates()):,} кандидатов)")

    with tempfile.TemporaryDirectory(prefix="wifi_extra_") as tmp:
        tmp_path = Path(tmp)
        hashes = tmp_path / "cap.hc22000"
        hc22000.convert(FIXTURE, out_path=hashes)

        print("\n3. Механика: hashcat читает список и находит пароль")
        one = tmp_path / "one.txt"
        one.write_text(FIXTURE_PASSWORD + "\n", encoding="ascii")
        verdict, secs = run(hash_dir, hashes, [str(one)], 120)
        print(f"   список из одной строки -> {verdict} за {secs:.1f} с")
        ok_mechanics = verdict.startswith("Cracked")

        print("\n4. Реальный прогон всего файла против настоящего хэша")
        verdict2, secs2 = run(hash_dir, hashes, [str(extra)], 600)
        print(f"   весь wpa-extra.txt -> {verdict2} за {secs2:.1f} с "
              f"(оценка была {stage.seconds(rate):.1f} с)")
        print(f"   это в {mask9.seconds(rate) / max(secs2, 0.01):.0f} раз быстрее "
              f"маски на 9 цифр")
        print("   (пароль фикстуры в этом файле отсутствует по построению: "
              "файл содержит\n    только то, чего нет в rockyou, а 12345678 "
              "в rockyou есть)")

    print()
    print("Итог")
    if ok_mechanics:
        print("   Список читается hashcat и пароль в нём находится: да")
    else:
        print("   Механика НЕ проверена -- список не сработал")
    print(f"   Известных паролей, которые маски ищут вслепую: {n8 + n9:,}")
    return 0 if ok_mechanics else 1


if __name__ == "__main__":
    raise SystemExit(main())