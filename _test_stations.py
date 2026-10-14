"""Who was on the network, according to the captures already on disk.

The count is what tells one network apart from another before choosing which to
attack, so it is worth being careful about what it does and does not say: it
counts addresses seen in one capture, it is a lower bound at that moment, and it
never claims more than the file showed.
"""
from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wifi_tool import stations  # noqa: E402

AP = bytes.fromhex("aabbccddeeff")
OTHER_AP = bytes.fromhex("0a0b0c0d0e0f")
_B = b"\xff" * 6
SSID = "TestNet"
#: Locally administered -- bit 1 of the first octet, what a phone's private
#: per-network address looks like.
RANDOMISED = bytes.fromhex("c2e34d027c82")
PLAIN = bytes.fromhex("1008c13ba48c")
OTHER = bytes.fromhex("d8d668664347")


def beacon(ssid: str = SSID) -> bytes:
    frame = bytes([0x08 << 4, 0x00]) + b"\x00\x00" + AP + AP + _B + b"\x00\x00"
    frame += b"\x00" * 8 + b"\x64\x00\x04\x11"
    return frame + bytes([0, len(ssid)]) + ssid.encode()


def data(ap: bytes, station: bytes) -> bytes:
    """A data frame from the station to the access point."""
    fc0 = (2 << 2) | (0x08 << 4)
    fc1 = 0x01  # To DS
    frame = bytes([fc0, fc1]) + b"\x00\x00" + ap + station + ap + b"\x00\x00"
    return frame + b"\x00\x00" + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + b"\x08\x00"


def pcap(frames: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(f), len(f)) + f
    return out


class StationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        stations.forget()

    def write(self, name: str, frames: list[bytes]) -> Path:
        path = self.root / name
        path.write_bytes(pcap(frames))
        return path

    def test_devices_on_both_directions_are_counted_once(self):
        self.write("a.pcap", [beacon(),
                               data(AP, PLAIN),          # station -> AP
                               data(AP, PLAIN),          # the same one again
                               bytes([0x08, 0x02]) + b"\x00\x00" + AP + PLAIN + AP + b"\x00\x00"
                               + b"\x00\x00" + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + b"\x08\x00"])
        info = stations.survey(self.root)["aabbccddeeff"]
        self.assertEqual(info.devices, 1)

    def test_a_private_address_is_counted_and_marked(self):
        self.write("a.pcap", [beacon(), data(AP, RANDOMISED)])
        info = stations.survey(self.root)["aabbccddeeff"]
        self.assertEqual(info.devices, 1)
        self.assertEqual(info.randomised, 1)
        self.assertEqual(info.real, 0)

    def test_two_networks_are_counted_apart(self):
        self.write("a.pcap", [beacon(), data(AP, PLAIN)])
        self.write("b.pcap", [beacon("Other"), data(OTHER_AP, OTHER)])
        found = stations.survey(self.root)
        self.assertEqual(found["aabbccddeeff"].devices, 1)
        self.assertEqual(found["0a0b0c0d0e0f"].devices, 1)

    def test_the_newest_capture_of_a_network_wins(self):
        self.write("old.pcap", [beacon(), data(AP, PLAIN), data(AP, OTHER)])
        import os
        import time
        old = self.root / "old.pcap"
        time.sleep(0.01)
        self.write("new.pcap", [beacon(), data(AP, PLAIN)])
        os.utime(old, (1_600_000_000, 1_600_000_000))
        info = stations.survey(self.root)["aabbccddeeff"]
        self.assertEqual(info.devices, 1, "the older capture was not superseded")

    def test_a_capture_with_no_traffic_reports_nothing(self):
        self.write("a.pcap", [beacon()])
        self.assertEqual(stations.survey(self.root), {})

    def test_a_broken_file_is_skipped_not_fatal(self):
        (self.root / "junk.pcap").write_bytes(b"ERR: File is too big")
        self.write("good.pcap", [beacon(), data(AP, PLAIN)])
        self.assertIn("aabbccddeeff", stations.survey(self.root))

    def test_the_answer_is_cached_until_the_folder_changes(self):
        self.write("a.pcap", [beacon(), data(AP, PLAIN)])
        first = stations.survey(self.root)
        self.assertEqual(stations.survey(self.root), first)
        # A new capture must be picked up without asking anything to forget.
        self.write("b.pcap", [beacon("New"), data(OTHER_AP, OTHER)])
        self.assertIn("0a0b0c0d0e0f", stations.survey(self.root))

    def test_devices_on_finds_the_network_by_its_bssid(self):
        self.write("a.pcap", [beacon(), data(AP, PLAIN), data(AP, OTHER)])

        class Net:
            bssid = "AA:BB:CC:DD:EE:FF"

        info = stations.devices_on(Net(), self.root)
        self.assertIsNotNone(info)
        self.assertEqual(info.devices, 2)

    def test_a_network_that_was_never_captured_has_no_answer(self):
        class Net:
            bssid = "99:99:99:99:99:99"

        self.assertIsNone(stations.devices_on(Net(), self.root))


if __name__ == "__main__":
    unittest.main()