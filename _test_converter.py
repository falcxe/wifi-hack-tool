"""Tests the conversion backend chain (built-in Python, plus wpawolf if present)."""
from __future__ import annotations

import asyncio
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wifi_tool import converter  # noqa: E402

AP = bytes.fromhex("aabbccddeeff")
STA = bytes.fromhex("112233445566")
PMKID = bytes(range(16))
ANONCE = bytes(range(32, 64))
SNONCE = bytes(range(64, 96))
M2_MIC = bytes(range(96, 112))
M3_MIC = bytes(range(112, 128))
_B = b"\xff" * 6


def rsn_ie_with_pmkid(pmkids: list[bytes]) -> bytes:
    body = b"\x00\x01" + b"\x00\x0f\xac\x08"
    body += struct.pack("<H", 1) + b"\x00\x0f\xac\x08"
    body += struct.pack("<H", 1) + b"\x00\x0f\xac\x08"
    body += b"\x8c\x00" + struct.pack("<H", len(pmkids))
    return bytes([48, len(body)]) + body + b"".join(pmkids)


def eapol_key(key_info: int, nonce: bytes, mic: bytes, key_data: bytes, replay: int = 1) -> bytes:
    """Build an EAPOL-Key message with the corrected wire layout.

    Fixed part is 95 bytes: desc(1) key_info(2) key_len(2) replay(8) nonce(32)
    IV(16) reserved(16) MIC(16) key_data_len(2), then the key data.
    """
    body = bytearray()
    body += b"\x02" + struct.pack(">H", key_info) + struct.pack(">H", 16)
    body += replay.to_bytes(8, "big")  # replay counter, big endian
    body += nonce.ljust(32, b"\x00")[:32]
    body += bytes(16)  # IV
    body += bytes(16)  # reserved
    body += mic.ljust(16, b"\x00")[:16]
    body += struct.pack(">H", len(key_data))
    body += key_data
    return bytes([1, 3]) + struct.pack(">H", len(body)) + bytes(body)

def data_frame(subtype, to_ds, from_ds, a1, a2, a3, payload) -> bytes:
    """802.11 data frame.

    Frame Control byte 0 carries bits 0-1 protocol version, 2-3 type and
    4-7 subtype (transmitted LSB-first), so QoS Data is 0x88, not 0x22.
    """
    fc0 = (2 << 2) | (subtype << 4)
    fc1 = (1 if to_ds else 0) | (2 if from_ds else 0)
    frame = bytes([fc0, fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x00\x00"
    if subtype & 0x08:
        frame += b"\x00\x00"  # QoS control
    return frame + b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + payload


def mgmt_frame(subtype, bssid, ssid: str) -> bytes:
    """802.11 management frame (type 0) carrying an SSID information element."""
    frame = bytes([subtype << 4, 0x00]) + b"\x00\x00" + bssid + bssid + _B + b"\x00\x00"
    frame += b"\x00" * 8 + b"\x64\x00" + b"\x04\x11"  # timestamp, interval, capability
    return frame + bytes([0, len(ssid)]) + ssid.encode()


def beacon(ssid: str) -> bytes:
    """Management subtype 8 = beacon; addr1 is the BSSID."""
    return mgmt_frame(0x08, AP, ssid)


def build_pcap(frames: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(f), len(f)) + f
    return out


def make_capture(path: Path) -> Path:
    m1 = eapol_key(0x008A, ANONCE, b"\x00" * 16, rsn_ie_with_pmkid([PMKID]), replay=1)
    m2 = eapol_key(0x010A, SNONCE, M2_MIC, rsn_ie_with_pmkid([]), replay=1)
    m3 = eapol_key(0x018A, ANONCE, M3_MIC, b"", replay=2)
    frames = [
        beacon("MyHomeWiFi"),
        data_frame(0x08, True, False, _B, AP, AP, m1),
        data_frame(0x08, False, True, AP, STA, AP, m2),
        data_frame(0x08, True, False, _B, STA, AP, m3),
    ]
    path.write_bytes(build_pcap(frames))
    return path


async def main() -> None:
    pcap = make_capture(Path("_tmp_conv.pcap"))
    out = Path("_tmp_conv.22000")

    # --- built-in backend ---------------------------------------------------
    result = await converter.convert(pcap, out, None, prefer="builtin")
    assert result.backend == "builtin", result.backend
    assert result.report.ok, result.report
    assert len(result.report.pmkid) == 1, result.report.pmkid
    assert PMKID.hex() in result.report.pmkid[0]
    assert b"MyHomeWiFi".hex() in result.report.pmkid[0]
    assert len(result.report.eapol) >= 1, result.report.eapol
    assert M2_MIC.hex() in result.report.eapol[0]
    print(f"builtin: pmkid={len(result.report.pmkid)} eapol={len(result.report.eapol)} essids={result.report.essids}")

    # --- bssid filter -------------------------------------------------------
    hit = await converter.convert(pcap, out, AP.hex(":"), prefer="builtin")
    assert hit.report.ok, hit.report
    miss = await converter.convert(pcap, out, "00:11:22:33:44:99", prefer="builtin")
    assert miss.report.total == 0, miss.report
    print("bssid filter: ok")

    # --- a file that is not a capture --------------------------------------
    # A capture backend that gives up mid-run writes its error message into the
    # output file. Read as an empty capture this became "nobody reconnected",
    # which is advice for a network that was never the problem.
    broken = Path("_tmp_broken.pcap")
    broken.write_bytes(b"ERR: File is too big")
    for backend in ("builtin", "wpawolf"):
        try:
            await converter.convert(broken, out, None, prefer=backend)
        except converter.ConversionError as exc:
            assert "ERR: File is too big" in str(exc), str(exc)
            assert "не читается как захват" in str(exc), str(exc)
        else:
            raise AssertionError(f"{backend}: a text file was accepted as a capture")
    print("unreadable capture file: reported, not treated as an empty one")

    # Same verdict from the parser itself, whichever way the file is reached.
    from wifi_tool import hc22000

    try:
        hc22000.convert(broken)
    except hc22000.CaptureFormatError as exc:
        assert "ERR: File is too big" in str(exc), str(exc)
    else:
        raise AssertionError("a 20-byte text file parsed as an empty capture")

    # --- a truncated capture keeps the frames it did have --------------------
    # A file cut mid-block is the normal shape of a hard-killed capture: what
    # was read is real, and saying so beats discarding it.
    truncated = Path("_tmp_truncated.pcap")
    full = pcap.read_bytes()
    truncated.write_bytes(full[: len(full) - 40])
    report = hc22000.convert(truncated)
    assert report.truncated, report
    assert report.ok, report
    assert "оборван" in hc22000.summarise(report), hc22000.summarise(report)
    print(f"truncated capture: {report.frames} frames kept, {len(report.eapol)} eapol")

    # --- a handshake with no beacon still gets its ESSID --------------------
    # The ESSID comes from the beacons in the capture. A short capture can hold
    # the handshake and none, and a record with a blank ESSID cannot be checked
    # against any candidate by hashcat however long the run.
    no_beacon = Path("_tmp_nobeacon.pcap")
    m1 = eapol_key(0x008A, ANONCE, b"\x00" * 16, rsn_ie_with_pmkid([PMKID]), replay=1)
    m2 = eapol_key(0x010A, SNONCE, M2_MIC, rsn_ie_with_pmkid([]), replay=1)
    m3 = eapol_key(0x018A, ANONCE, M3_MIC, b"", replay=2)
    no_beacon.write_bytes(build_pcap([
        data_frame(0x08, True, False, _B, AP, AP, m1),
        data_frame(0x08, False, True, AP, STA, AP, m2),
        data_frame(0x08, True, False, _B, STA, AP, m3),
    ]))
    bare = await converter.convert(no_beacon, out, None, prefer="builtin")
    assert bare.report.essids == 0, bare.report
    assert all(b"MyHomeWiFi".hex() not in line for line in bare.report.eapol)
    hinted = await converter.convert(no_beacon, out, None, prefer="builtin",
                                     essid_hint="MyHomeWiFi")
    assert b"MyHomeWiFi".hex() in hinted.report.eapol[0], hinted.report.eapol
    print("essid hint: filled in where the capture had no beacon")

    # --- wpawolf backend, if installed ------------------------------------
    exe = converter.find_wpawolf()
    if exe is None:
        assert converter.preferred_backend() == "builtin"
        print("wpawolf: not installed, builtin fallback confirmed")
    else:
        wolf = await converter.convert(pcap, out, None, prefer="wpawolf")
        assert wolf.backend == "wpawolf", wolf.backend
        assert wolf.report.ok, wolf.report
        print(
            f"wpawolf: pmkid={len(wolf.report.pmkid)} eapol={len(wolf.report.eapol)} "
            f"essids={wolf.report.essids}"
        )

    for leftover in ("_tmp_conv.pcap", "_tmp_conv.22000", "_tmp_conv.essid.txt",
                     "_tmp_broken.pcap", "_tmp_truncated.pcap", "_tmp_nobeacon.pcap"):
        Path(leftover).unlink(missing_ok=True)
    print("ALL OK")


if __name__ == "__main__":
    asyncio.run(main())
