"""Data models for the WiFi crack tool."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .options import CrackOptions


@dataclass
class Network:
    """A scanned WiFi network (one BSSID)."""

    ssid: str
    bssid: str
    channel: int = 0
    signal: int = 0
    auth: str = ""
    protection: str = ""
    radio: str = ""
    associated: bool = False

    @property
    def label(self) -> str:
        return self.ssid or "(hidden)"

    @property
    def haystack(self) -> str:
        """Lower-cased auth + protection text, for locale-tolerant checks."""
        return f"{self.auth} {self.protection}".lower()

    @property
    def is_open(self) -> bool:
        h = self.haystack
        return "open" in h or "нет" in h or "none" in h or not self.auth

    @property
    def is_wep(self) -> bool:
        return "wep" in self.haystack

    @property
    def is_psk(self) -> bool:
        """True for WPA/WPA2 personal networks -- the only ones we can attack."""
        h = self.haystack
        return "wpa" in h and ("personal" in h or "psk" in h or "общая" in h)

    @property
    def is_wpa3_only(self) -> bool:
        """SAE without a WPA2 leg -- there is no offline handshake to capture.

        A transition-mode AP advertises WPA3 *and* WPA2; the WPA2 leg is still
        offline-crackable, so this is deliberately false for those.
        """
        h = self.haystack
        if "wpa3" not in h and "sae" not in h:
            return False
        return "wpa2" not in h

    @property
    def crackable(self) -> bool:
        """Only pre-shared-key WPA/WPA2 networks can be cracked offline.

        WPA3-SAE is excluded on purpose: there is no EAPOL handshake in the clear
        to capture, so offering it as a target only burns the capture budget and
        then reports a failure that could never have succeeded.
        """
        return self.is_psk and not self.is_wep and not self.is_open and not self.is_wpa3_only


@dataclass(frozen=True)
class RunRequest:
    """The original inputs retained with a result for an exact retry."""

    mode: Literal["manual", "auto", "capture", "file", "board"]
    options: CrackOptions
    capture_path: str = ""
    capture_seconds: int = 60
    total_runtime: float = 1800


@dataclass
class CrackResult:
    """Outcome of a cracking attempt against one network."""

    network: Network
    password: str = ""
    success: bool = False
    method: str = ""
    elapsed: float = 0.0
    error: str = ""
    log: list = field(default_factory=list)
    #: What to do about it. A missing dictionary and a missing capture hardware
    #: need opposite advice, so the failure carries its own next step instead of
    #: the screen guessing one hint for every reason.
    remedy: str = ""
    summary: str = ""
    request: RunRequest | None = None
