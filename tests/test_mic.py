"""Structural checks for the EAPOL-Key parser against the real wire layout.

The layout was corrected against a real capture cross-checked with wpawolf:
the fixed part is 95 bytes and the MIC sits at offset 77 of the descriptor
body (i.e. 81 in the stored frame, which keeps its 4-byte EAPOL header).

This file verifies the parser against that layout -- field positions, the
exported frame, and message classification. It does not assert a particular
MIC *formula*, which is hashcat's job, so it cannot prove a password;
`tests/test_groundtruth.py` covers correctness by requiring byte-identical output
with an independent implementation.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool.hc22000 import _parse_eapol_key  # noqa: E402

NONCE = bytes(range(32, 64))
KEY_DATA = b"\x30\x10\x01\x00\x00\x0f\xac\x08"


def build_eapol(
    key_info: int, nonce: bytes, mic: bytes, key_data: bytes, replay: int = 1
) -> bytes:
    """Build an EAPOL-Key message with the corrected 95-byte fixed part."""
    body = bytearray()
    body += b"\x02"                            # descriptor type
    body += struct.pack(">H", key_info)        # key info
    body += struct.pack(">H", 16)              # key length
    body += replay.to_bytes(8, "big")          # replay counter, big endian
    body += nonce.ljust(32, b"\x00")[:32]      # nonce
    body += bytes(16)                          # IV
    body += bytes(16)                          # reserved
    body += mic.ljust(16, b"\x00")[:16]        # MIC
    body += struct.pack(">H", len(key_data))   # key data length
    body += key_data
    return bytes([1, 3]) + struct.pack(">H", len(body)) + bytes(body)


def classify(key_info: int) -> tuple[bool, bool, bool, bool]:
    """(is M1, is M2, is M3, is M4) from the key-info bits."""
    has_mic = bool(key_info & 0x0100)
    enc_key_data = bool(key_info & 0x0080)
    return (
        enc_key_data and not has_mic,
        has_mic and not enc_key_data,
        has_mic and enc_key_data,
        not has_mic and not enc_key_data,
    )


def main() -> None:
    ref = hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", 4096, 32)
    assert ref.hex() == (
        "f42c6fc52df0ebef9ebb4b90b38a5f90"
        "2e83fe1b135a70e23aed762e9710a12e"
    ), ref.hex()
    print("PBKDF2 test vector: ok")

    mic = bytes(range(96, 112))
    frame = build_eapol(0x010A, NONCE, mic, KEY_DATA)

    desc, key_info, replay, nonce, got_mic, key_data, raw = _parse_eapol_key(frame)
    assert desc == 0x02, desc
    assert key_info == 0x010A, hex(key_info)
    assert int.from_bytes(replay, "big") == 1, replay
    assert nonce == NONCE, nonce.hex()
    assert got_mic == mic, (got_mic.hex(), mic.hex())
    assert key_data == KEY_DATA, key_data.hex()
    print("EAPOL-Key parse round-trip: ok")

    # The export keeps the EAPOL header and zeroes the MIC at header + 77 --
    # exactly where the parser reports finding the MIC.
    assert len(raw) == len(frame), (len(raw), len(frame))
    assert raw[:4] == frame[:4], "EAPOL header must be preserved"
    assert raw[81:97] == bytes(16), "MIC field must be zeroed in the export"
    assert raw[:81] == frame[:81], "fields before the MIC must be untouched"
    assert raw[97:] == frame[97:], "fields after the MIC must be untouched"
    assert raw[:81] + mic + raw[97:] == frame, "export is not a faithful MIC-zeroed copy"
    print("exported frame layout: ok")

    assert classify(0x008A) == (True, False, False, False)   # M1
    assert classify(0x010A) == (False, True, False, False)   # M2
    assert classify(0x018A) == (False, False, True, False)   # M3
    assert classify(0x000A) == (False, False, False, True)   # M4
    print("message classification: ok")

    print("ALL OK")


if __name__ == "__main__":
    main()
