"""What the installer reports about Npcap, and what it refuses to do.

The interesting cases are the ones that cannot be tested by installing
anything: this machine already has Npcap, and a second driver install would
be a system change nobody asked for. So the state machine is driven through
patched lookups instead, and the tests are about *deciding* correctly rather
than about touching the machine.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool import installer  # noqa: E402

ABSENT = {"installed": False, "dot11": None, "version": None,
          "wlan_helper": None, "path": None}
NO_DOT11 = {"installed": True, "dot11": False, "version": "0.9985",
            "wlan_helper": None, "path": None}
READY = {"installed": True, "dot11": True, "version": "1.83",
         "wlan_helper": Path(r"C:\Windows\System32\Npcap\WlanHelper.exe"),
         "path": Path(r"C:\Windows\System32\Npcap")}


class NpcapStateTests(unittest.TestCase):
    def test_absent_needs_the_installer(self):
        with patch.object(installer, "npcap_state", return_value=ABSENT):
            self.assertTrue(installer.npcap_needs_install())

    def test_installed_without_raw_80211_still_needs_work(self):
        """The most misleading state: Npcap is there, so everyone says it is fine.

        Capture needs the optional second filter driver. Without it the driver
        hands back Ethernet frames and no EAPOL ever appears, and the symptom
        is an empty capture rather than an error.
        """
        with patch.object(installer, "npcap_state", return_value=NO_DOT11):
            self.assertTrue(installer.npcap_needs_install())

    def test_ready_needs_nothing(self):
        with patch.object(installer, "npcap_state", return_value=READY):
            self.assertFalse(installer.npcap_needs_install())

    def test_a_missing_version_does_not_hide_an_installation(self):
        """Older builds write no DisplayVersion, and it is not a reason to
        report the driver as absent."""
        broken = dict(READY, version=None)
        with patch.object(installer, "npcap_state", return_value=broken):
            self.assertFalse(installer.npcap_needs_install())


class NpcapInstallTests(unittest.TestCase):
    def test_already_ready_installs_nothing(self):
        with patch.object(installer, "npcap_state", return_value=READY), \
                patch("wifi_tool.installer._download") as download:
            result = installer.install_npcap()
        self.assertEqual(result["status"], "already")
        download.assert_not_called()

    def test_without_admin_rights_nothing_is_downloaded(self):
        """Fetching a signed driver installer before discovering it cannot be
        run is pointless and looks like something is about to happen."""
        with patch.object(installer, "npcap_state", return_value=ABSENT), \
                patch("wifi_tool.installer._download") as download, \
                patch("wifi_tool.assets.is_admin", return_value=False):
            result = installer.install_npcap()
        self.assertEqual(result["status"], "denied")
        download.assert_not_called()
        self.assertIn("администратор", result["message"].lower())

    def test_every_documented_exit_code_is_understood(self):
        """Each code means a different next step, so none may fall through to
        a generic failure."""
        for code, text in installer.NPCAP_EXIT.items():
            self.assertTrue(text.strip(), code)

    def test_no_silent_flag_is_passed(self):
        """/S is OEM-only; the free installer ignores it and opens a window."""
        source = Path(installer.__file__).read_text(encoding="utf-8")
        body = source.split("def install_npcap(", 1)[1].split("\ndef ", 1)[0]
        self.assertNotIn('"/S"', body)
        self.assertNotIn("'/S'", body)

    def test_dot11_support_is_always_requested(self):
        source = Path(installer.__file__).read_text(encoding="utf-8")
        body = source.split("def install_npcap(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("/dot11_support=yes", body)

    def test_the_digest_is_pinned(self):
        self.assertEqual(len(installer.NPCAP_SHA256), 64)
        self.assertIn("{version}", installer.NPCAP_URL)


if __name__ == "__main__":
    unittest.main(verbosity=2)