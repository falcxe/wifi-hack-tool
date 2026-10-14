"""Self-test for hc22000.convert using synthetic 802.11 frames."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool.hc22000 import convert  # noqa: E402

AP = bytes.fromhex("aabbccddeeff")
STA = bytes.fromhex("112233445566")
PMKID = bytes(range(16))
ANONCE = bytes(range(32, 64))
SNONCE = bytes(range(64, 96))
M2_MIC = bytes(range(96, 112))
M3_MIC = bytes(range(112, 128))
_B = b"\xff\xff\xff\xff\xff\xff"
SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


def rsn_ie_with_pmkid(pmkids: list[bytes]) -> bytes:
    body = b"\x00\x01"                      # version 1
    body += b"\x00\x0f\xac\x08"              # group cipher CCMP
    body += struct.pack("<H", 1) + b"\x00\x0f\xac\x08"   # pairwise
    body += struct.pack("<H", 1) + b"\x00\x0f\xac\x08"   # akm PSK
    body += b"\x8c\x00"                      # RSN capabilities
    body += struct.pack("<H", len(pmkids))
    for p in pmkids:
        body += p
    return bytes([48, len(body)]) + body


def eapol_key(
    key_info: int, nonce: bytes, mic: bytes, key_data: bytes, replay: int = 1
) -> bytes:
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

def data_frame(subtype: int, to_ds: bool, from_ds: bool, addr1, addr2, addr3, payload) -> bytes:
    """802.11 data frame.

    Frame Control byte 0 is bits 0-1 protocol version, 2-3 type, 4-7 subtype
    (transmitted LSB-first), so type=2/subtype=8 (QoS Data) is 0x88.
    """
    fc0 = (2 << 2) | (subtype << 4)
    fc1 = (1 if to_ds else 0) | (2 if from_ds else 0)
    frame = bytes([fc0, fc1]) + b"\x00\x00" + addr1 + addr2 + addr3 + b"\x00\x00"
    if subtype & 0x08:
        frame += b"\x00\x00"  # QoS control
    return frame + SNAP_EAPOL + payload


def mgmt_frame(subtype: int, bssid: bytes, ssid: str, extra: bytes = b"") -> bytes:
    """802.11 management frame (type 0) carrying an SSID information element."""
    frame = bytes([subtype << 4, 0x00]) + b"\x00\x00" + bssid + bssid + _B + b"\x00\x00"
    frame += b"\x00" * 8 + b"\x64\x00" + b"\x04\x11"  # timestamp, interval, capability
    frame += bytes([0, len(ssid)]) + ssid.encode()
    return frame + extra


def beacon(ssid: str) -> bytes:
    """Management subtype 8 = beacon; addr1 is the BSSID."""
    return mgmt_frame(0x08, AP, ssid)


M1 = eapol_key(0x008A, ANONCE, b"\x00" * 16, rsn_ie_with_pmkid([PMKID]), replay=1)
M2 = eapol_key(0x010A, SNONCE, M2_MIC, rsn_ie_with_pmkid([]), replay=1)
M3 = eapol_key(0x018A, ANONCE, M3_MIC, b"", replay=2)


def build_pcap(frames: list[bytes], linktype: int = 105) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(f), len(f)) + f
    return out


def main() -> None:
    frames = [
        beacon("MyHomeWiFi"),
        data_frame(0x08, True, False, _B, AP, AP, M1),
        data_frame(0x08, False, True, AP, STA, AP, M2),
        data_frame(0x08, True, False, _B, STA, AP, M3),
    ]

    # --- classic pcap, bare 802.11 -----------------------------------------
    pcap = Path("_tmp_test.pcap")
    pcap.write_bytes(build_pcap(frames))
    rep = convert(pcap, out_path="_tmp_test.22000")
    print("frames:", rep.frames, "essids:", rep.essids)
    print("pmkid:", rep.pmkid)
    print("eapol pairs:", len(rep.eapol))
    for ln in rep.eapol:
        print("  ", ln[:70], "...")
    text = Path("_tmp_test.22000").read_text()
    # hc22000 encodes the MACs and the ESSID as hex without separators.
    ssid_hex = b"MyHomeWiFi".hex()
    assert len(rep.pmkid) == 1, rep.pmkid
    assert ssid_hex in rep.pmkid[0], rep.pmkid[0]
    assert PMKID.hex() in rep.pmkid[0]
    assert f"*{AP.hex()}*" in rep.pmkid[0], rep.pmkid[0]
    assert len(rep.eapol) >= 1, rep.eapol
    # message-pair codes are hex: 82 = M2+M3 (body from M2), 13 = body from M3
    assert any(ln.endswith("*82") or ln.endswith("*13") for ln in rep.eapol), rep.eapol
    # the 82 record exports M2's body, the 13 record exports M3's
    assert M2_MIC.hex() in rep.eapol[0], rep.eapol[0]
    assert any(M3_MIC.hex() in ln for ln in rep.eapol), rep.eapol
    assert ssid_hex in rep.eapol[0], rep.eapol[0]
    assert STA.hex() in rep.eapol[0], rep.eapol[0]

    # --- radiotap-wrapped ----------------------------------------------------
    present = 1 << 5  # dBm antenna signal
    rt_len = 8 + 1
    rt = struct.pack("<BBHI", 0, 0, rt_len, present) + struct.pack("<b", -45)
    assert len(rt) == rt_len
    pcap2 = Path("_tmp_test_rt.pcap")
    pcap2.write_bytes(build_pcap([rt + f for f in frames], linktype=127))
    rep2 = convert(pcap2, out_path="_tmp_test_rt.22000")
    assert rep2.pmkid == rep.pmkid, (rep2.pmkid, rep.pmkid)
    assert len(rep2.eapol) == len(rep.eapol), (rep2.eapol, rep.eapol)
    print("radiotap: ok")

    # --- bssid filter --------------------------------------------------------
    rep3 = convert(pcap, bssid_filter=AP.hex(":"))
    assert rep3.pmkid and rep3.eapol
    rep4 = convert(pcap, bssid_filter="00:11:22:33:44:99")
    assert rep4.total == 0, rep4
    print("filter: ok")

    # --- ethernet encapsulation ---------------------------------------------
    pcap3 = Path("_tmp_test_eth.pcap")
    pcap3.write_bytes(build_pcap([b"\x00" * 12 + b"\x08\x00" + f for f in frames], linktype=1))
    rep5 = convert(pcap3)
    assert rep5.pmkid == rep.pmkid, (rep5.pmkid, rep.pmkid)
    print("ethernet: ok")

    for f in ("_tmp_test.pcap", "_tmp_test.22000", "_tmp_test_rt.pcap",
              "_tmp_test_rt.22000", "_tmp_test_eth.pcap"):
        Path(f).unlink(missing_ok=True)

    print("ALL OK")
    print("--- sample line ---")
    print(text.splitlines()[0])


if __name__ == "__main__":
    main()