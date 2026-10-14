"""The capture window: how long it listens, and when it decides to stop.

Two things are tested here, and they are the two halves of the same promise.
The window is long enough that a handshake has a real chance of happening in it,
and it ends on its own the moment the file holds something worth cracking --
otherwise "listen longer" would only ever mean "wait longer".
"""
from __future__ import annotations

import asyncio
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool import capturer, hc22000, pipeline  # noqa: E402
from wifi_tool.models import Network  # noqa: E402

AP = bytes.fromhex("aabbccddeeff")
STA = bytes.fromhex("112233445566")
OTHER_AP = bytes.fromhex("0a0b0c0d0e0f")
ANONCE = bytes(range(32, 64))
SNONCE = bytes(range(64, 96))
M2_MIC = bytes(range(96, 112))
M3_MIC = bytes(range(112, 128))
_B = b"\xff" * 6
SSID = "MyHomeWiFi"


def eapol_key(key_info: int, nonce: bytes, mic: bytes, key_data: bytes, replay: int = 1) -> bytes:
    body = bytearray()
    body += b"\x02" + struct.pack(">H", key_info) + struct.pack(">H", 16)
    body += replay.to_bytes(8, "big")
    body += nonce.ljust(32, b"\x00")[:32]
    body += bytes(16) + bytes(16)
    body += mic.ljust(16, b"\x00")[:16]
    body += struct.pack(">H", len(key_data)) + key_data
    return bytes([1, 3]) + struct.pack(">H", len(body)) + bytes(body)


def data_frame(to_ds: bool, from_ds: bool, a1: bytes, a2: bytes, a3: bytes, payload: bytes) -> bytes:
    fc0 = (2 << 2) | (0x08 << 4)
    fc1 = (1 if to_ds else 0) | (2 if from_ds else 0)
    frame = bytes([fc0, fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x00\x00"
    frame += b"\x00\x00"  # QoS control
    return frame + hc22000._SNAP_EAPOL + payload


def beacon(ssid: str) -> bytes:
    return beacon_for(ssid)


def beacon_for(ssid: str, bssid: bytes = AP) -> bytes:
    """A beacon announcing ``ssid`` from ``bssid``."""
    frame = bytes([0x08 << 4, 0x00]) + b"\x00\x00" + bssid + bssid + _B + b"\x00\x00"
    frame += b"\x00" * 8 + b"\x64\x00\x04\x11"
    return frame + bytes([0, len(ssid)]) + ssid.encode()


def build_pcap(frames: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(f), len(f)) + f
    return out


def handshake_frames(bssid: bytes = AP, sta: bytes = STA) -> list[bytes]:
    """A beacon plus a complete M2/M3 pair, which is what converts to a record."""
    m2 = eapol_key(0x010A, SNONCE, M2_MIC, b"\x30\x04\x00\x00", replay=1)
    m3 = eapol_key(0x018A, ANONCE, M3_MIC, b"", replay=2)
    return [
        beacon(SSID),
        data_frame(False, True, bssid, bssid, sta, m2),
        data_frame(True, False, _B, sta, bssid, m3),
    ]


def network(bssid: str = "aa:bb:cc:dd:ee:ff") -> Network:
    return Network(ssid=SSID, bssid=bssid, channel=6, signal=50,
                   auth="WPA2-Personal", protection="AES")


class SignatureScanTests(unittest.TestCase):
    """``first_key_frame`` -- the cheap "did something just happen" detector."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "capture.pcap"

    def write(self, frames: list[bytes]) -> None:
        self.path.write_bytes(build_pcap(frames))

    def test_locates_the_first_handshake_frame(self):
        self.write(handshake_frames())
        offset = hc22000.first_key_frame(self.path)
        self.assertIsNotNone(offset)
        blob = self.path.read_bytes()
        self.assertEqual(
            blob[offset : offset + len(hc22000.EAPOL_KEY_SIGNATURE)],
            hc22000.EAPOL_KEY_SIGNATURE,
        )

    def test_silent_capture_reports_nothing(self):
        self.write([beacon(SSID)])
        self.assertIsNone(hc22000.first_key_frame(self.path))

    def test_resumes_past_what_it_already_judged(self):
        m2 = eapol_key(0x010A, SNONCE, M2_MIC, b"\x30\x04\x00\x00", replay=1)
        self.write([beacon(SSID), data_frame(False, True, AP, AP, STA, m2)])
        first = hc22000.first_key_frame(self.path)
        self.assertIsNotNone(first)
        # The caller asks again from just after that frame and must not be told
        # about it again, or every tick would re-verify the same handshake.
        after = first + len(hc22000.EAPOL_KEY_SIGNATURE)
        self.assertIsNone(hc22000.first_key_frame(self.path, after))

    def test_signature_spanning_two_chunks_is_still_found(self):
        pad = bytes(range(256)) * 4096  # straddles the 1 MB read boundary
        frames = [data_frame(False, True, AP, AP, STA,
                             eapol_key(0x010A, SNONCE, M2_MIC, b"", 1)), pad]
        self.path.write_bytes(build_pcap(frames))
        self.assertIsNotNone(hc22000.first_key_frame(self.path))

    def test_missing_or_unreadable_file_is_quiet(self):
        self.assertIsNone(hc22000.first_key_frame(self.path))


class VerifierTests(unittest.TestCase):
    """``verify(path)`` -- the thing the capture actually waits for."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "capture.pcap"
        self.verify = pipeline._handshake_verifier(network())

    def write(self, frames: list[bytes]) -> None:
        self.path.write_bytes(build_pcap(frames))

    def test_accepts_a_capture_holding_this_networks_handshake(self):
        self.write(handshake_frames())
        self.assertTrue(self.verify(self.path))

    def test_rejects_a_capture_with_no_handshake(self):
        self.write([beacon(SSID)])
        self.assertFalse(self.verify(self.path))

    def test_rejects_another_networks_handshake(self):
        # The air is full of other people's handshakes. Ending a capture on one
        # of those produces a file hashcat cannot check this network against.
        self.write(handshake_frames(bssid=OTHER_AP))
        self.assertFalse(self.verify(self.path))

    def test_rejects_a_lone_message_with_nothing_to_pair_with(self):
        m1 = eapol_key(0x008A, ANONCE, b"\x00" * 16, b"", replay=1)
        self.write([beacon(SSID), data_frame(True, False, _B, AP, AP, m1)])
        self.assertFalse(self.verify(self.path))

    def test_a_handshake_from_another_access_point_of_the_same_network_counts(self):
        """The WPA key comes from the network's name, not from its radio.

        The other band of the same router, or a second AP of a mesh, speaks the
        same SSID and therefore the same key. Filtering strictly to the selected
        BSSID threw away captures that did hold a handshake.
        """
        self.write([beacon_for(SSID), beacon_for(SSID, OTHER_AP),
                    *handshake_frames(bssid=OTHER_AP)])
        self.assertTrue(self.verify(self.path))

    def test_a_handshake_from_a_different_network_does_not(self):
        self.write([beacon_for(SSID), beacon_for("Neighbour", OTHER_AP),
                    *handshake_frames(bssid=OTHER_AP)])
        self.assertFalse(self.verify(self.path))

    def test_rejects_a_file_the_backend_is_still_writing(self):
        blob = build_pcap(handshake_frames())
        self.path.write_bytes(blob[:-40])  # cut mid-frame, as a kill would
        self.assertFalse(self.verify(self.path))


class CaptureWindowTests(unittest.IsolatedAsyncioTestCase):
    """``capturer.capture`` with a real backend process behind it."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.target = self.root / "capture.pcap"

    def backend(self, script: str) -> capturer.Backend:
        path = self.root / "writer.py"
        path.write_text(script, encoding="utf-8")
        return capturer.Backend("test", "Writer", Path(sys.executable),
                                args=[str(path), "{out}"], needs_channel=False)

    async def test_stops_as_soon_as_the_verifier_is_satisfied(self):
        script = (
            "import sys, time\n"
            f"open(sys.argv[1], 'wb').write({build_pcap(handshake_frames())!r})\n"
            "time.sleep(60)\n"
        )
        backend = self.backend(script)
        started = time.monotonic()
        result = await capturer.capture(
            backend, capturer.Interface(1, "Fixture"), self.target,
            duration=300, scan_interval=0.2, verify=lambda p: p.exists(),
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result, self.target)
        self.assertLess(elapsed, 20, "capture kept listening after it had a handshake")

    async def test_keeps_listening_while_the_verifier_says_no(self):
        # Noise on the air that does not add up to a record: the point of the
        # verifier is that "EAPOL appeared" alone must not end the capture.
        script = (
            "import sys, time\n"
            f"open(sys.argv[1], 'wb').write({build_pcap([beacon(SSID)])!r})\n"
            "time.sleep(60)\n"
        )
        backend = self.backend(script)
        verify = pipeline._handshake_verifier(network())
        started = time.monotonic()
        await capturer.capture(
            backend, capturer.Interface(1, "Fixture"), self.target,
            duration=4, scan_interval=0.2, verify=verify,
        )
        self.assertGreaterEqual(time.monotonic() - started, 4)

    async def test_a_channel_the_backend_cannot_use_is_said_out_loud(self):
        """The channel is the one thing that must never be dropped silently.

        ``build_command`` substitutes ``{channel}`` into whatever the backend's
        template asks for, and neither default template does -- so without a word
        in the log, a capture aimed at channel 6 records channel 1 and finds
        nothing for five minutes.
        """
        script = (
            "import sys, time\n"
            f"open(sys.argv[1], 'wb').write({build_pcap(handshake_frames())!r})\n"
            "time.sleep(60)\n"
        )
        backend = self.backend(script)
        lines: list[str] = []
        await capturer.capture(
            backend, capturer.Interface(1, "Fixture"), self.target,
            duration=2, channel=6, on_log=lines.append,
            verify=lambda p: True,
        )
        self.assertTrue(any("канал" in line for line in lines), lines)

    async def test_default_ceiling_is_a_five_minute_window(self):
        self.assertGreaterEqual(pipeline.CAPTURE_SECONDS, 300)


if __name__ == "__main__":
    unittest.main()
