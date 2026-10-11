"""Forced reauthentication: the frame, the kicker, and where it is wired.

The frames are the part worth pinning down byte for byte. A deauthentication
that is malformed is not a deauthentication: the client ignores it, the capture
waits, and the run looks exactly like a network that simply did not reconnect --
which is the outcome this module exists to make rarer. So the wire format is
asserted rather than assumed, and the lifecycle is tested separately, because a
kicker that outlives its capture is a network being knocked offline for nothing.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wifi_tool import deauth, pipeline  # noqa: E402
from wifi_tool.models import Network  # noqa: E402

BSSID = "aa:bb:cc:dd:ee:ff"
DEVICE = r"\Device\NPF_{7832E2B4-6CBA-48FF-9714-857EFFF85FC6}"
NET = Network("MyHomeWiFi", BSSID, 6, 70, "WPA2-Personal", "CCMP")


class FakeHandle:
    """A pcap handle that counts what it was handed."""

    def __init__(self, datalink: int = 105) -> None:
        self.frames: list[bytes] = []
        self.closed = False
        self._datalink = datalink

    def send(self, data: bytes) -> int:
        self.frames.append(data)
        return len(data)

    def datalink(self) -> int:
        return self._datalink

    def close(self) -> None:
        self.closed = True


class FakeIface:
    def __init__(self, monitor: bool = True) -> None:
        self._monitor = monitor

    def ismonitor(self) -> bool:
        return self._monitor


class FakeResolve:
    """Stands in for scapy's ``resolve_iface(device)``."""

    def __init__(self, monitor: bool = True) -> None:
        self.iface = FakeIface(monitor)

    def __call__(self, device):
        return self.iface


class FakeHandleModule:
    """Stands in for scapy's ``open_pcap(device, monitor=True)``."""

    def __init__(self, handle: FakeHandle) -> None:
        self.handle = handle

    def __call__(self, device, monitor: bool = False):
        return self.handle


def iface():
    from wifi_tool.capturer import Interface

    return Interface(12, "Wi-Fi", capture_id=DEVICE)


class FrameTests(unittest.TestCase):
    def test_the_frame_is_the_shape_a_client_believes(self):
        frame = deauth.build_frame(BSSID)
        # 2 control+duration, 3 addresses of 6, 2 sequence control, 1 reason.
        self.assertEqual(len(frame), 25)
        self.assertEqual(frame[0], 0xC0, "management frame, subtype deauthentication")
        self.assertEqual(frame[4:10], b"\xff" * 6, "must be broadcast to reach every client")
        self.assertEqual(frame[10:16], bytes.fromhex("aabbccddeeff"), "sent by the AP")
        self.assertEqual(frame[16:22], bytes.fromhex("aabbccddeeff"), "from the AP")
        self.assertEqual(frame[24], deauth.REASON_CODE)

    def test_bssids_are_accepted_in_either_notation(self):
        for value in (BSSID, BSSID.upper(), "AA-BB-CC-DD-EE-FF"):
            self.assertEqual(deauth.normalize_bssid(value), BSSID)
        for value in ("не MAC", "", "aa:bb:cc", "zz:bb:cc:dd:ee:ff"):
            self.assertIsNone(deauth.normalize_bssid(value), value)

    def test_sending_a_frame_nobody_can_receive_is_refused(self):
        kicker = deauth.Kicker(handle=FakeHandle())
        with self.assertRaises(ValueError):
            deauth.send(kicker, "не MAC")
        self.assertEqual(kicker.handle.frames, [])


class KickerTests(unittest.TestCase):
    def test_an_adapter_without_a_pcap_name_cannot_be_used(self):
        from wifi_tool.capturer import Interface

        with self.assertRaises(deauth.InjectionUnavailable):
            deauth.open_kicker(Interface(3, "Wi-Fi"))

    def test_a_handle_that_is_not_in_monitor_mode_is_refused(self):
        """The driver drops management frames in managed mode, silently.

        Opening a handle there succeeds, every send returns a plausible number,
        and nothing reaches the air -- so a kicker that cannot prove it is
        injecting must not exist at all.
        """
        handle = FakeHandle()
        with patch.object(deauth, "_scapy", return_value=(FakeHandleModule(handle),
                                                          FakeResolve(monitor=False))), \
                self.assertRaises(deauth.InjectionUnavailable) as caught:
            deauth.open_kicker(iface())
        self.assertIn("монитора", str(caught.exception))
        self.assertTrue(handle.closed)

    def test_a_handle_framed_as_ethernet_is_refused(self):
        """pcap_inject prepends an Ethernet header to a non-802.11 link type."""
        handle = FakeHandle(datalink=1)
        with patch.object(deauth, "_scapy", return_value=(FakeHandleModule(handle),
                                                          FakeResolve(monitor=True))), \
                self.assertRaises(deauth.InjectionUnavailable) as caught:
            deauth.open_kicker(iface())
        self.assertIn("Ethernet", str(caught.exception))
        self.assertTrue(handle.closed)

    def test_a_raw_80211_handle_is_accepted(self):
        handle = FakeHandle(datalink=105)
        with patch.object(deauth, "_scapy", return_value=(FakeHandleModule(handle),
                                                          FakeResolve(monitor=True))):
            kicker = deauth.open_kicker(iface())
        self.assertIs(kicker.handle, handle)
        self.assertEqual(kicker.datalink, 105)

    def test_a_send_that_the_driver_truncates_is_not_counted(self):
        class Truncating(FakeHandle):
            def send(self, data):
                return len(data) - 2

        kicker = deauth.Kicker(handle=Truncating())
        with self.assertRaises(OSError):
            deauth.send(kicker, BSSID)
        self.assertEqual(kicker.sent, 0)

    def test_bursts_go_out_repeatedly_until_the_deadline(self):
        handle = FakeHandle()
        with patch.object(deauth, "open_kicker",
                          return_value=deauth.Kicker(handle=handle)):
            frames, note = deauth.run(iface(), BSSID, seconds=0.05, interval=0.01)
        self.assertGreaterEqual(frames, deauth.BURST, "no burst left the adapter")
        self.assertEqual(len(handle.frames), frames)
        self.assertEqual(len(set(handle.frames)), 1, "the bursts differ between themselves")
        self.assertEqual(note, "")
        self.assertTrue(handle.closed, "the handle was left open")

    def test_a_stop_event_set_beforehand_sends_nothing(self):
        """Stop means stop: a kicker released after its capture is over must not
        knock a network offline for nobody."""
        handle = FakeHandle()
        stop = threading.Event()
        stop.set()
        with patch.object(deauth, "open_kicker",
                          return_value=deauth.Kicker(handle=handle)):
            frames, note = deauth.run(iface(), BSSID, seconds=30, stop=stop)
        self.assertEqual(frames, 0)
        self.assertEqual(handle.frames, [])
        self.assertEqual(note, "")

    def test_an_unavailable_injector_is_reported_not_raised(self):
        """A capture must not die because a network would not accept a kick."""
        with patch.object(deauth, "open_kicker",
                          side_effect=deauth.InjectionUnavailable("нет прав")):
            frames, note = deauth.run(iface(), BSSID, seconds=1)
        self.assertEqual(frames, 0)
        self.assertIn("нет прав", note)

    def test_a_burst_that_fails_midway_says_so(self):
        class Failing(FakeHandle):
            def send(self, data):
                raise OSError("adapter busy")

        handle = Failing()
        with patch.object(deauth, "open_kicker",
                          return_value=deauth.Kicker(handle=handle)):
            frames, note = deauth.run(iface(), BSSID, seconds=0.05, interval=0.01)
        self.assertEqual(frames, 0)
        self.assertIn("adapter busy", note)


class WiringTests(unittest.IsolatedAsyncioTestCase):
    """Where the kicker sits in a run, and when it is not started at all."""

    def test_nothing_is_sent_when_the_option_is_off(self):
        with patch.object(deauth, "run") as run:
            async def body():
                async with pipeline._kicking(iface(), NET, enabled=False, probe="",
                                             log=lambda line: None):
                    pass
            asyncio.run(body())
        run.assert_not_called()

    async def test_a_machine_that_cannot_inject_keeps_capturing_and_says_why(self):
        lines: list[str] = []
        with patch.object(deauth, "run") as run:
            async with pipeline._kicking(iface(), NET, enabled=True,
                                        probe="не установлен scapy",
                                        log=lines.append) as kicked:
                kicked.report()
        run.assert_not_called()
        self.assertTrue(any("scapy" in line for line in lines), lines)

    async def test_the_kicker_waits_for_the_channel_and_stops_with_the_capture(self):
        """Frames go out only once the radio is on the target's channel, and
        never after the capture that was listening for the reaction is over."""
        seen: list[object] = []
        stop_seen: list[threading.Event] = []

        def slow_run(_iface, _bssid, *, stop=None, **kw):
            seen.append("started")
            if stop is not None:
                stop_seen.append(stop)
                stop.wait(10)
            return 0, ""

        async def body():
            async with pipeline._kicking(iface(), NET, enabled=True, probe="",
                                         log=lambda line: None) as kicked:
                await asyncio.sleep(0.05)
                self.assertEqual(seen, [], "frames went out before the retune")
                kicked.start()
                await asyncio.sleep(0.05)
                self.assertEqual(seen, ["started"])

        with patch.object(deauth, "run", side_effect=slow_run):
            await asyncio.wait_for(body(), timeout=5)
        self.assertTrue(stop_seen and stop_seen[0].is_set())
        # A kicker still holding the radio would leave it in monitor mode for
        # the next run to trip over, so the adapter is handed back on the way out.
        restore = MagicMock(return_value="")
        with patch.object(pipeline.capturer, "restore_managed_mode", restore):
            async with pipeline._kicking(iface(), NET, enabled=True, probe="",
                                         log=lambda line: None) as kicked:
                kicked.start()
        restore.assert_called_once_with(iface())


if __name__ == "__main__":
    unittest.main()