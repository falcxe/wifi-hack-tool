"""Regression coverage for actual Windows netsh and tshark interface formats."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wifi_tool import capturer, pipeline, scanner


NETSH = """SSID 5 : TestNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 08:9A:C7:E7:51:68
         Signal             : 82%
         Radio type         : 802.11ac
         Channel            : 44
         Bss Load:
             Channel Utilization: 0 (0 %)
    BSSID 2                 : 08:9A:C7:E7:51:69
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 6
             Channel Utilization: 128 (50 %)
SSID 6 :
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : AA:BB:CC:DD:EE:01
         Signal             : 20%
         Channel            : 11
"""

DEVICE = r"\Device\NPF_{7832E2B4-6CBA-48FF-9714-857EFFF85FC6}"
TSHARK = f"8. {DEVICE} (Беспроводная сеть)\n12. etwdump (Event Tracing reader)\n"


class ScannerCaptureTests(unittest.TestCase):
    def test_indexed_bssids_and_independent_per_ap_fields(self):
        nets = scanner.parse_networks(NETSH)
        self.assertEqual(len(nets), 3)
        self.assertEqual([n.bssid for n in nets],
                         ["08:9a:c7:e7:51:68", "08:9a:c7:e7:51:69", "aa:bb:cc:dd:ee:01"])
        self.assertEqual([n.channel for n in nets], [44, 6, 11])
        self.assertEqual([n.signal for n in nets], [82, 40, 20])
        self.assertEqual([n.radio for n in nets], ["802.11ac", "802.11n", ""])
        self.assertEqual(nets[0].ssid, nets[1].ssid)
        self.assertEqual(nets[2].ssid, "")
        self.assertTrue(all(n.auth == "WPA2-Personal" and n.protection == "CCMP" for n in nets))

    def test_russian_exact_labels_ignore_utilization(self):
        text = NETSH.replace("Authentication", "Аутентификация").replace("Encryption", "Шифрование")
        text = text.replace("Channel Utilization", "Загрузка канала").replace("Channel", "Канал")
        text = text.replace("Signal", "Сигнал").replace("Radio type", "Радиотип")
        self.assertEqual([n.channel for n in scanner.parse_networks(text)], [44, 6, 11])

    def test_legacy_unindexed_format_and_colon_in_ssid(self):
        nets = scanner.parse_networks("SSID 1 : Lab: WiFi\nBSSID : AA:BB:CC:DD:EE:FF\nChannel : 36")
        self.assertEqual((nets[0].ssid, nets[0].bssid, nets[0].channel),
                         ("Lab: WiFi", "aa:bb:cc:dd:ee:ff", 36))

    def test_tshark_uses_device_id_instead_of_windows_index(self):
        backend = capturer.Backend("tshark", "tshark", Path("tshark.exe"), ["-i", "{iface}", "-w", "{out}"])
        iface = capturer.Interface(12, "Беспроводная сеть")
        proc = subprocess.CompletedProcess([], 0, TSHARK, "")
        with patch.object(capturer.subprocess, "run", return_value=proc):
            mapped = capturer.resolve_interface(backend, iface)
        self.assertEqual(mapped.capture_id, DEVICE)
        cmd = capturer.build_command(backend, mapped, Path("test.pcapng"), 60, None, None)
        self.assertEqual(cmd[2], DEVICE)
        self.assertNotIn("12", cmd)

    def test_tshark_missing_wifi_does_not_choose_extcap(self):
        backend = capturer.Backend("tshark", "tshark", Path("tshark.exe"))
        proc = subprocess.CompletedProcess([], 0, "12. etwdump (Event Tracing reader)", "")
        with patch.object(capturer.subprocess, "run", return_value=proc):
            with self.assertRaisesRegex(capturer.CaptureError, "не видит Wi-Fi"):
                capturer.resolve_interface(backend, capturer.Interface(12, "Wi-Fi"))

    def test_non_tshark_backend_keeps_its_interface_index(self):
        backend = capturer.Backend("cap80211", "cap80211", Path("netcap80211.exe"))
        iface = capturer.Interface(12, "Wi-Fi")
        with patch.object(capturer.subprocess, "run") as run:
            self.assertIs(capturer.resolve_interface(backend, iface), iface)
        run.assert_not_called()

    def test_detected_wireless_adapter_can_have_a_custom_name(self):
        adapter = scanner.AdapterInfo("My renamed adapter", "Wireless", "", "")
        ifaces = [capturer.Interface(3, "Ethernet"), capturer.Interface(12, adapter.name)]
        with patch.object(capturer, "list_interfaces", return_value=ifaces):
            self.assertEqual(pipeline._find_wireless_iface(adapter).index, 12)

    def test_no_arbitrary_wired_interface_fallback(self):
        with patch.object(capturer, "list_interfaces", return_value=[capturer.Interface(3, "Ethernet")]):
            self.assertIsNone(pipeline._find_wireless_iface())

    def test_missing_npcap_feature_is_reported_without_capture(self):
        backend = capturer.Backend("tshark", "tshark", Path("tshark.exe"))
        iface = capturer.Interface(12, "Wi-Fi", capture_id=DEVICE)
        with patch.object(capturer, "_npcap_dot11_enabled", return_value=False), \
                patch.object(capturer.subprocess, "run") as run:
            with self.assertRaisesRegex(capturer.CaptureError, "raw 802.11 выключена"):
                capturer.check_monitor_support(backend, iface)
        run.assert_not_called()

    def test_raw_link_types_confirm_monitor_support(self):
        backend = capturer.Backend("tshark", "tshark", Path("tshark.exe"))
        iface = capturer.Interface(12, "Wi-Fi", capture_id=DEVICE)
        proc = subprocess.CompletedProcess([], 0, "IEEE802_11_RADIO (802.11 plus radiotap)", "")
        with patch.object(capturer, "_npcap_dot11_enabled", return_value=True), \
                patch.object(capturer, "_wireless_modes", return_value=None), \
                patch.object(capturer.subprocess, "run", return_value=proc) as run:
            capturer.check_monitor_support(backend, iface)
        self.assertEqual(run.call_args.args[0], ["tshark.exe", "-i", DEVICE, "-I", "-L"])

    def test_ethernet_link_types_cannot_be_used_as_raw_wifi(self):
        backend = capturer.Backend("tshark", "tshark", Path("tshark.exe"))
        proc = subprocess.CompletedProcess([], 0, "EN10MB (Ethernet)", "")
        with patch.object(capturer, "_npcap_dot11_enabled", return_value=True), \
                patch.object(capturer, "_wireless_modes", return_value=None), \
                patch.object(capturer.subprocess, "run", return_value=proc):
            with self.assertRaisesRegex(capturer.CaptureError, "не предоставил raw"):
                capturer.check_monitor_support(backend, capturer.Interface(12, "Wi-Fi", capture_id=DEVICE))

    def test_driver_reporting_only_managed_has_a_clear_blocker(self):
        backend = capturer.Backend("tshark", "tshark", Path("tshark.exe"))
        iface = capturer.Interface(12, "Wi-Fi", capture_id=DEVICE)
        with patch.object(capturer, "_npcap_dot11_enabled", return_value=True), \
                patch.object(capturer, "_wireless_modes", return_value=("managed",)), \
                patch.object(capturer.subprocess, "run") as run:
            with self.assertRaisesRegex(capturer.CaptureError, "не поддерживает режим монитора"):
                capturer.check_monitor_support(backend, iface)
        run.assert_not_called()


class AdapterModeRestoreTests(unittest.TestCase):
    """A capture leaves the adapter in monitor mode, and somebody has to undo it.

    Only the capture tool's own exit path switches it back, so every capture that
    ends any other way -- cancelled, or stopped early because the handshake was
    already on disk -- leaves a stick that finds no networks at all and comes
    back only when it is unplugged. Both of those are ordinary outcomes here,
    not corner cases.
    """

    def done(self, code=0, out="", err=""):
        return subprocess.CompletedProcess([], code, out, err)

    def test_wlanhelper_is_preferred_for_the_interface_it_switched(self):
        iface = capturer.Interface(12, "Wi-Fi", capture_id=DEVICE)
        # Any file that exists stands in for Npcap's helper.
        helper = Path(__file__).resolve()
        with patch.object(capturer, "_wlan_helper", return_value=helper), \
                patch.object(capturer.subprocess, "run", return_value=self.done()) as run:
            self.assertEqual(capturer.restore_managed_mode(iface), "")
        self.assertEqual(run.call_args.args[0],
                         [str(helper), DEVICE.split("{")[1].split("}")[0], "mode", "managed"])
        self.assertEqual(run.call_count, 1, "netsh ran as well although Npcap did the job")

    def test_netsh_covers_a_backend_that_did_not_report_a_guid(self):
        iface = capturer.Interface(12, "Wi-Fi 2")
        with patch.object(capturer, "_wlan_helper", return_value=Path("missing.exe")), \
                patch.object(capturer.subprocess, "run", return_value=self.done()) as run:
            self.assertEqual(capturer.restore_managed_mode(iface), "")
        # The quotes belong to the argument: netsh splits its own command line,
        # so an adapter with a space in its name would arrive in two pieces.
        self.assertEqual(run.call_args.args[0],
                         ["netsh", "wlan", "set", "interface", 'name="Wi-Fi 2"',
                          "mode=managed"])

    def test_a_refusal_is_reported_not_raised(self):
        iface = capturer.Interface(12, "Wi-Fi")
        with patch.object(capturer, "_wlan_helper", return_value=Path("missing.exe")), \
                patch.object(capturer.subprocess, "run",
                             return_value=self.done(1, "", "The requested operation is not supported")):
            note = capturer.restore_managed_mode(iface)
        self.assertIn("not supported", note)
        self.assertIn("Wi-Fi", note)

    def test_the_wireless_adapter_is_found_when_none_is_named(self):
        ifaces = [capturer.Interface(3, "Ethernet"),
                  capturer.Interface(12, "Беспроводная сеть 2")]
        with patch.object(capturer, "list_interfaces", return_value=ifaces):
            self.assertEqual(capturer.wireless_interface().index, 12)

    def test_no_wireless_adapter_means_nothing_to_do(self):
        with patch.object(capturer, "list_interfaces",
                          return_value=[capturer.Interface(3, "Ethernet")]):
            self.assertEqual(capturer.restore_managed_mode(), "")


class CaptureFileTests(unittest.IsolatedAsyncioTestCase):
    """The file a capture tool leaves behind is what the rest of the tool believes.

    A killed capture tool cannot flush, so the packets it had not written yet
    are gone -- and a handshake is a few kilobytes, small enough that the whole
    of it can be "not written yet". Two rules follow, and both are here because
    getting either wrong makes a recorded handshake look like an absent one.
    """

    def test_tshark_is_told_when_to_stop_on_its_own(self):
        backend = capturer.Backend("tshark", "tshark", Path("tshark.exe"),
                                   capturer.DEFAULT_BACKENDS["tshark"]["args"])
        cmd = capturer.build_command(
            backend, capturer.Interface(12, "Wi-Fi", capture_id=DEVICE),
            Path("out.pcapng"), 45, None, None,
        )
        self.assertIn("duration:45", cmd)
        # Without it the only way out is a hard kill, and a hard kill does not
        # close the savefile.
        self.assertLess(cmd.index("duration:45"), cmd.index("-w"))

    async def test_capture_error_file_is_reported_not_accepted(self):
        backend = capturer.Backend("test", "Fixture tool", Path(sys.executable))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "capture.pcap"
            target.write_bytes(b"ERR: File is too big")
            with self.assertRaises(capturer.CaptureError) as ctx:
                await capturer._verify_capture_file(target, backend)
            self.assertIn("ERR: File is too big", str(ctx.exception))

    async def test_missing_or_empty_output_is_an_error(self):
        backend = capturer.Backend("test", "Fixture tool", Path(sys.executable))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "capture.pcapng"
            with self.assertRaises(capturer.CaptureError):
                await capturer._verify_capture_file(target, backend)
            target.write_bytes(b"")
            with self.assertRaises(capturer.CaptureError):
                await capturer._verify_capture_file(target, backend)

    async def test_a_real_capture_file_passes(self):
        backend = capturer.Backend("test", "Fixture tool", Path(sys.executable))
        fixture = Path(__file__).resolve().parent / "fixtures" / "wpa2_psk_12345678.pcapng"
        await capturer._verify_capture_file(fixture, backend)

    async def test_a_finished_capture_hands_the_adapter_back(self):
        """Whatever ended the run, the adapter goes back to managed mode.

        The early stop is the dangerous one: it terminates the backend, and a
        terminated backend never runs the exit path that restores the mode.
        """
        backend = capturer.Backend("test", "Fixture tool", Path(sys.executable))
        iface = capturer.Interface(12, "Wi-Fi")
        fixture = Path(__file__).resolve().parent / "fixtures" / "wpa2_psk_12345678.pcapng"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "capture.pcapng"
            target.write_bytes(fixture.read_bytes())
            with patch.object(capturer, "restore_managed_mode", return_value="") as restore:
                await capturer.capture(backend, iface, target, duration=1)
        restore.assert_called_once_with(iface)

    async def test_an_empty_scan_looks_at_the_adapter_before_giving_up(self):
        """No networks at all is what a monitor-mode adapter reports.

        It is indistinguishable from an empty room from the outside, so the
        cheaper explanation is checked first: one command, instead of telling
        the user to unplug a stick that is working perfectly well.
        """
        calls: list[int] = []

        def fake_scan(timeout=15.0):
            calls.append(1)
            if len(calls) == 1:
                return []  # the adapter is still in monitor mode
            return [scanner.Network("Home", "aa:bb:cc:dd:ee:ff")]

        lines: list[str] = []
        with patch.object(pipeline, "scan", side_effect=fake_scan) as scan_call, \
                patch.object(pipeline.capturer, "restore_managed_mode",
                             return_value="") as restore:
            nets = await pipeline.scan_networks(on_log=lines.append)
        self.assertEqual([n.ssid for n in nets], ["Home"])
        self.assertEqual(scan_call.call_count, 2)
        restore.assert_called_once_with()
        self.assertTrue(any("повторяю скан" in line for line in lines), lines)

    async def test_a_scan_that_found_networks_is_left_alone(self):
        nets = [scanner.Network("Home", "aa:bb:cc:dd:ee:ff")]
        with patch.object(pipeline, "scan", return_value=nets) as scan_call, \
                patch.object(pipeline.capturer, "restore_managed_mode") as restore:
            found = await pipeline.scan_networks()
        self.assertEqual(found, nets)
        self.assertEqual(scan_call.call_count, 1)
        restore.assert_not_called()


class ReadinessRecoveryTests(unittest.TestCase):
    """Readiness must not tell the user to replug a stick that is merely stuck."""

    def test_an_invisible_adapter_is_returned_to_managed_mode_first(self):
        adapter = scanner.AdapterInfo("Wi-Fi", "Wireless", "aa:bb:cc:dd:ee:ff", "connected")
        seen: list[int] = []

        def detect():
            seen.append(1)
            return None if len(seen) == 1 else adapter

        with patch.object(pipeline, "detect_adapter", side_effect=detect), \
                patch.object(pipeline.capturer, "restore_managed_mode",
                             return_value="") as restore, \
                patch.object(pipeline.cracker, "find_hashcat", return_value=None), \
                patch.object(pipeline.capturer, "first_available_backend", return_value=None):
            readiness = pipeline.check_readiness()
        restore.assert_called_once_with()
        self.assertEqual(seen, [1, 1])
        self.assertIs(readiness.adapter, adapter)
        self.assertFalse([p for p in readiness.problems if "не найден" in p.lower()
                          and "адаптер" in p.lower()], readiness.problems)


class ChannelTuningTests(unittest.TestCase):
    """A capture aimed at the wrong channel is a capture of an empty band.

    ``build_command`` substitutes ``{channel}``, and no default backend's
    command line mentions it -- so the channel used to be dropped on the floor
    and the adapter recorded whatever channel it happened to be left on. Five
    minutes of silence from there is indistinguishable from a quiet network.
    """

    GUID = "7832E2B4-6CBA-48FF-9714-857EFFF85FC6"

    def iface(self):
        return capturer.Interface(12, "Wi-Fi", capture_id=DEVICE)

    def helper(self, replies):
        calls: list[tuple[str, ...]] = []

        def run(guid, *args):
            calls.append((guid, *args))
            return subprocess.CompletedProcess([], 0, replies.pop(0), "")

        return calls, run

    def test_the_2ghz_band_is_set_by_channel(self):
        calls, run = self.helper(["6", "6"])
        with patch.object(capturer, "_helper_run", side_effect=run), \
                patch.object(capturer, "_wlan_helper", return_value=Path(__file__)):
            self.assertEqual(capturer.set_monitor_channel(self.iface(), 6), "")
        self.assertEqual(calls[0], (self.GUID, "channel", "6"))

    def test_a_5ghz_channel_is_set_by_frequency(self):
        """WlanHelper's `channel` stops at 14; channel 36 is 5180 MHz."""
        calls, run = self.helper(["5180", "5180"])
        with patch.object(capturer, "_helper_run", side_effect=run), \
                patch.object(capturer, "_wlan_helper", return_value=Path(__file__)):
            self.assertEqual(capturer.set_monitor_channel(self.iface(), 36), "")
        self.assertEqual(calls[0], (self.GUID, "freq", "5180"))

    def test_an_adapter_that_stays_put_names_both_channels(self):
        # The driver refused (the command only works in monitor mode) and left
        # the card on channel 1. Saying so is the whole point.
        calls, run = self.helper(["0", "1"])
        with patch.object(capturer, "_helper_run", side_effect=run), \
                patch.object(capturer, "_wlan_helper", return_value=Path(__file__)):
            note = capturer.set_monitor_channel(self.iface(), 6)
        self.assertIn("channel=1", note)
        self.assertIn("6", note)

    def test_a_refusal_is_reported(self):
        with patch.object(capturer, "_helper_run",
                          return_value=subprocess.CompletedProcess([], 1, "", "invalid argument")), \
                patch.object(capturer, "_wlan_helper", return_value=Path(__file__)):
            note = capturer.set_monitor_channel(self.iface(), 6)
        self.assertIn("invalid argument", note)

    def test_no_helper_means_nothing_to_do(self):
        with patch.object(capturer, "_wlan_helper", return_value=Path("missing.exe")):
            self.assertEqual(capturer.set_monitor_channel(self.iface(), 6), "")
            # And an interface whose id carries no GUID at all.
            self.assertEqual(
                capturer.set_monitor_channel(capturer.Interface(3, "Wi-Fi"), 6), "")


class AdapterChoiceTests(unittest.TestCase):
    """Which adapter the capture runs on.

    A laptop with a USB stick has two wireless adapters and netsh lists the
    built-in one first. That one has no monitor mode, so picking the first
    candidate meant the program refused to capture on a machine that had a
    perfectly capable adapter plugged in beside it -- and the stick doing the
    capturing, doing it fine, was never opened.
    """

    BACKEND = capturer.Backend("tshark", "tshark", None)

    def machine(self, modes_for):
        internal = capturer.Interface(1, "Беспроводная сеть",
                                      capture_id=r"\Device\NPF_{AAAA}")
        stick = capturer.Interface(7, "Wi-Fi 2", capture_id=r"\Device\NPF_{BBBB}")
        return [internal, stick], lambda iface: modes_for(iface.capture_id)

    def test_the_adapter_that_can_be_captured_on_is_chosen(self):
        ifaces, modes = self.machine(
            lambda id: ("managed",) if "AAAA" in id else ("managed", "monitor"))
        detected = scanner.AdapterInfo("Беспроводная сеть", "Intel AX211", "", "off")
        with patch.object(capturer, "list_interfaces", return_value=ifaces), \
                patch.object(capturer, "_wireless_modes", side_effect=modes):
            chosen = pipeline._find_wireless_iface(detected, self.BACKEND)
        self.assertEqual(chosen.name, "Wi-Fi 2")

    def test_the_detected_adapter_still_wins_when_it_can_be_captured_on(self):
        ifaces, modes = self.machine(lambda id: ("managed", "monitor"))
        detected = scanner.AdapterInfo("Беспроводная сеть", "Wi-Fi 2", "", "off")
        with patch.object(capturer, "list_interfaces", return_value=ifaces), \
                patch.object(capturer, "_wireless_modes", side_effect=modes):
            chosen = pipeline._find_wireless_iface(detected, self.BACKEND)
        self.assertEqual(chosen.name, "Беспроводная сеть")

    def test_an_adapter_that_cannot_say_is_not_disqualified(self):
        """An unreadable modes query is not a verdict of "unsupported"."""
        ifaces, _ = self.machine(lambda id: ())
        with patch.object(capturer, "list_interfaces", return_value=ifaces), \
                patch.object(capturer, "_wireless_modes", return_value=None):
            chosen = pipeline._find_wireless_iface(None, self.BACKEND)
        self.assertEqual(chosen.name, "Беспроводная сеть")

    def test_nothing_capable_still_returns_an_adapter_to_explain(self):
        ifaces, modes = self.machine(lambda id: ("managed",))
        with patch.object(capturer, "list_interfaces", return_value=ifaces), \
                patch.object(capturer, "_wireless_modes", side_effect=modes):
            chosen = pipeline._find_wireless_iface(None, self.BACKEND)
        self.assertIsNotNone(chosen, "the screen needs something to name in its complaint")

    def test_an_adapter_npcap_cannot_see_is_skipped_not_fatal(self):
        stuck = capturer.Interface(1, "Беспроводная сеть")
        stick = capturer.Interface(7, "Wi-Fi 2", capture_id=r"\Device\NPF_{BBBB}")

        def resolve(backend, iface):
            if not iface.capture_id:
                raise capturer.CaptureError("tshark не видит Wi-Fi интерфейс")
            return iface

        with patch.object(capturer, "list_interfaces", return_value=[stuck, stick]), \
                patch.object(capturer, "resolve_interface", side_effect=resolve), \
                patch.object(capturer, "_wireless_modes",
                             return_value=("managed", "monitor")):
            chosen = pipeline._find_wireless_iface(None, self.BACKEND)
        self.assertEqual(chosen.name, "Wi-Fi 2")

    def test_wired_interfaces_are_never_candidates(self):
        ifaces = [capturer.Interface(3, "Ethernet"), capturer.Interface(7, "Wi-Fi 2")]
        with patch.object(capturer, "list_interfaces", return_value=ifaces):
            self.assertEqual(pipeline._find_wireless_iface().name, "Wi-Fi 2")
            # An adapter netsh itself reports as wireless stays a candidate even
            # when its name says nothing about Wi-Fi.
            with patch.object(capturer, "list_interfaces",
                              return_value=ifaces + [capturer.Interface(9, "Мой адаптер")]):
                renamed = scanner.AdapterInfo("Мой адаптер", "Realtek", "", "off")
                self.assertEqual(
                    pipeline._find_wireless_iface(renamed).name, "Мой адаптер")


if __name__ == "__main__":
    unittest.main(verbosity=2)
