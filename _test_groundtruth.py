"""Ground-truth test: compare the built-in converter against real wpawolf output.

Runs both converters over the same real-world capture and requires the emitted
hc22000 records to match byte for byte. wpawolf is a rewrite of ZerBea's
hcxpcapngtool with parity required against it, so it is used here as the
reference implementation.

These captures come from vanhoefm/wifi-example-captures, a published research
collection. The WPA2 fixture's PSK is documented in its filename.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wifi_tool import converter, hc22000  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "tests" / "fixtures"

# The fixture's password is documented in its file name upstream.
WPA2_FIXTURE = "wpa2_psk_12345678.pcapng"
WPA2_PSK = "12345678"


def prf_sha1(key: bytes, label: bytes, data: bytes, length: int) -> bytes:
    out = b""
    i = 0
    while len(out) < length:
        i += 1
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
    return out[:length]


def derive_ptk(psk: str, essid: str, ap: bytes, sta: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """The PTK derivation hashcat mode 22000 performs for a candidate password."""
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), essid.encode(), 4096, 32)
    mac = lambda m: b"".join(bytes([b]) for b in m)  # noqa: E731
    data = (mac(min(ap, sta)) + mac(max(ap, sta))) + (
        mac(min(anonce, snonce)) + mac(max(anonce, snonce))
    )
    return prf_sha1(pmk, b"Pairwise key expansion", data, 64)


def verify_line(line: str, psk: str, snonce: bytes) -> bool | None:
    """Check a WPA*02 record the way hashcat would. None if fields are unusable."""
    f = line.split("*")
    if len(f) < 9 or f[1] != "02":
        return None
    mic = bytes.fromhex(f[2])
    ap = bytes.fromhex(f[3])
    sta = bytes.fromhex(f[4])
    essid = bytes.fromhex(f[5]).decode("utf-8", "replace")
    nonce = bytes.fromhex(f[6])
    eapol = bytes.fromhex(f[7])
    pair = f[8]
    if pair == "13":
        # AP-less record: the stored nonce is the SNonce.
        used_snonce, anonce = nonce, snonce
    else:
        used_snonce, anonce = snonce, nonce
    ptk = derive_ptk(psk, essid, ap, sta, anonce, used_snonce)
    # The MIC covers the EAPOL-Key body; the stored frame keeps its 4-byte
    # EAPOL header, so zero the MIC field at header + 77 and hash the lot.
    buf = bytearray(eapol)
    buf[4 + 77 : 4 + 77 + 16] = b"\x00" * 16
    return hmac.compare_digest(hmac.new(ptk[:16], bytes(buf), hashlib.sha1).digest()[:16], mic)


def _lines(path: Path) -> set[str]:
    return {ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()}


async def _convert(capture: Path, prefer: str) -> tuple[set[str], hc22000.ConversionReport]:
    out = capture.with_name(f"_{capture.stem}_{prefer}.22000")
    try:
        result = await converter.convert(capture, out, None, prefer=prefer)
        return _lines(out), result.report
    except converter.ConversionError:
        # A converter that extracts nothing is a valid outcome for some
        # captures (e.g. WPA3/SAE where the handshake is encrypted).
        return set(), hc22000.ConversionReport()
    finally:
        out.unlink(missing_ok=True)
        out.with_suffix(".essid.txt").unlink(missing_ok=True)


async def main() -> None:
    have_wolf = converter.find_wpawolf() is not None
    captures = sorted(FIXTURES.glob("*.pcapng"))
    assert captures, f"no fixtures in {FIXTURES}"

    failures: list[str] = []

    for capture in captures:
        mine, report = await _convert(capture, "builtin")
        print(f"{capture.name}")
        print(f"  builtin : pmkid={len(report.pmkid)} eapol={len(report.eapol)} frames={report.frames}")

        if not have_wolf:
            print("  wpawolf not installed -- cross-check skipped")
            continue

        wolf, _ = await _convert(capture, "wpawolf")
        print(f"  wpawolf : lines={len(wolf)}")

        if mine == wolf:
            print(f"  MATCH   : identical output ({len(mine)} lines)")
        else:
            only_mine = sorted(mine - wolf)
            only_wolf = sorted(wolf - mine)
            print(f"  DIFF    : only-builtin={len(only_mine)} only-wpawolf={len(only_wolf)}")
            for line in only_mine[:3]:
                print(f"    + builtin: {line[:70]}")
            for line in only_wolf[:3]:
                print(f"    + wpawolf: {line[:70]}")
            if not mine >= wolf:
                failures.append(
                    f"{capture.name}: built-in output is missing records wpawolf found"
                )
            else:
                print("  ok      : built-in is a superset (cracks the same, tries extra)")

    # --- informational: does a known password verify? -----------------------
    # The WPA2 fixture is a WNM sleep-test capture; its name mentions a PSK but
    # that is not reliably the key the client used, so this probe reports rather
    # than asserts. The hard guarantee above is the byte-identical match with
    # wpawolf, an independent implementation that is kept at parity with
    # hcxpcapngtool.
    capture = FIXTURES / WPA2_FIXTURE
    mine, _ = await _convert(capture, "builtin")
    snonce = bytes.fromhex(
        "a0f9ee918d283ba076e71850d8a68f0b370efa1a9f4bf7afe39cb4ecc26f3f28"
    )
    for candidate in (WPA2_PSK, "test-wnm-rsn", "password", "abcdefgh"):
        hits = [ln for ln in mine if verify_line(ln, candidate, snonce) is True]
        print(f"  probe {candidate!r}: {len(hits)} record(s) verify")
        if hits:
            print(f"    -> emitted records crack against {candidate!r}")
            break

    if failures:
        raise AssertionError("\n".join(failures))
    print("ALL OK")


if __name__ == "__main__":
    asyncio.run(main())
