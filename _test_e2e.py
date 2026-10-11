"""End-to-end test: capture file -> converter -> hashcat -> plaintext password.

This is the definitive test. It runs the real hashcat binary against a hash
file produced by this project's converter and requires the documented password
to come out. Nothing is mocked: if the hc22000 layout, the field encoding, the
nonce choice or the message-pair code were wrong, hashcat would fail to parse
the file or would never recover the password.

Requires hashcat (see README). Skips with a clear message when it is absent.
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wifi_tool import converter, cracker  # noqa: E402
from wifi_tool.installer import find_7z  # noqa: E402

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "tests" / "fixtures" / "wpa2_psk_12345678.pcapng"
EXPECTED_PSK = "12345678"  # documented in the fixture's upstream file name


async def _convert(out: Path) -> int:
    result = await converter.convert(FIXTURE, out, None, prefer="builtin")
    return len(result.report.eapol)


async def main() -> int:
    hashcat = cracker.find_hashcat()
    if hashcat is None or not hashcat.exists():
        print("SKIP: hashcat не найден — положи hashcat.exe в assets/")
        print("      (или распакуй официальный архив в assets/hashcat-<версия>/)")
        return 0
    if not FIXTURE.exists():
        print(f"SKIP: нет фикстуры {FIXTURE}")
        return 0

    print(f"hashcat: {hashcat}")

    tmp = Path(tempfile.mkdtemp(prefix="wifi_tool_e2e_"))
    hash_file = tmp / "handshake.22000"
    try:
        count = await _convert(hash_file)
        assert count, "converter produced no hashes from the fixture"
        print(f"converted: {count} EAPOL record(s) -> {hash_file.name}")
        print(f"  first line: {hash_file.read_text(encoding='utf-8').splitlines()[0][:76]}...")

        wordlist = ROOT / "assets" / "wordlist.txt"
        assert wordlist.exists(), "starter wordlist is missing"

        rules = None
        for candidate in ("best66.rule", "best64.rule"):
            probe = hashcat.parent / "rules" / candidate
            if probe.exists():
                rules = probe
                break

        cmd = [str(hashcat), "-m", "22000", str(hash_file), str(wordlist)]
        if rules:
            cmd += ["-r", str(rules)]
        print(f"running : {' '.join(cmd[-4:])}")

        outcome = await cracker.crack(
            hash_file, wordlist, rules, hashcat=hashcat, timeout=120,
            potfile=tmp / "dictionary.potfile",
        )
        print(f"cracked : {outcome.cracked} password={outcome.password!r} "
              f"in {outcome.elapsed:.1f}s")

        assert outcome.cracked, "hashcat did not recover the password"
        assert outcome.password == EXPECTED_PSK, (
            f"recovered {outcome.password!r}, expected {EXPECTED_PSK!r}"
        )
        # Ten candidates, with a separate empty potfile: a cached dictionary
        # result must not turn a broken mask command into a false pass.
        masked = await cracker.crack(
            hash_file, hashcat=hashcat, mask="1234567?d", timeout=120,
            potfile=tmp / "mask.potfile",
        )
        assert masked.cracked and masked.password == EXPECTED_PSK, (
            f"mask mode failed: {masked.log[-10:]}"
        )
        print(f"mask    : recovered fixture password in {masked.elapsed:.1f}s")
        print(f"\nPASSWORD RECOVERED: {outcome.password}")
        print("ALL OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
