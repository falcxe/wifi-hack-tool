"""Who was on the network, according to the captures already on disk.

WPA2 encrypts the payload and never the MAC header, so every data frame on the
channel names both the access point and the device at the other end:

    AP -> STA   addr1=client  addr2=BSSID  addr3=BSSID
    STA -> AP   addr1=BSSID   addr2=client addr3=BSSID
    STA -> STA  addr1=dst     addr2=src    addr3=BSSID   (forwarded by the AP)

Counting the distinct addresses on the other side answers the question that
decides which network is worth attacking: is there anything on it to knock
over? A capture with four devices behind it will give up a handshake when the
network is knocked; a capture from an empty one will sit through five minutes
and produce nothing, and the two are indistinguishable from silence.

The count is a **lower bound at the moment of that capture** -- a device in
power save that had not said anything is not in it -- and it is never updated
without a new capture. Shown as a hint, never as a census.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import hc22000
from .options import ensure_captures_dir

_BROADCAST = bytes.fromhex("ffffffffffff")


@dataclass(frozen=True)
class StationInfo:
    """What one capture said about the devices behind an access point."""

    devices: int
    randomised: int
    captured_at: datetime
    #: True when the file on disk converts into a crackable record. A network
    #: with this set needs no capture at all -- the hash is already in hand.
    has_hash: bool = False

    @property
    def real(self) -> int:
        return self.devices - self.randomised


def is_randomised(mac: bytes) -> bool:
    """True for a private address: bit 1 of the first octet.

    Modern phones put a per-network random address in the clear every time they
    join. It is still stable for a given network, so counting them separately
    says something a plain count cannot -- three devices may be one device that
    rotates, or three that do not.
    """
    return bool(mac[0] & 0x02)


def _station_for(path: Path) -> dict[str, tuple[int, int]]:
    """{bssid: (devices, randomised)} as seen in one capture."""
    out: dict[str, tuple[set[str], set[str]]] = {}
    try:
        frames = list(hc22000.iter_frames(path))
    except (hc22000.CaptureFormatError, OSError):
        return {}

    for _linktype, data in frames:
        frame = hc22000.strip_radiotap(data)
        if len(frame) < 24 or ((frame[0] >> 2) & 0x03) != 2:
            continue
        addr1, addr2, addr3 = frame[4:10], frame[10:16], frame[16:22]
        bssid = addr3 if addr3 != _BROADCAST else addr2
        if bssid == _BROADCAST:
            continue
        entry = out.setdefault(bssid.hex(), (set(), set()))
        for mac in {addr1, addr2} - {bssid, _BROADCAST}:
            entry[0].add(mac.hex())
            if is_randomised(mac):
                entry[1].add(mac.hex())
    return {bssid: (len(v[0]), len(v[1])) for bssid, v in out.items()}


def _has_hash(path: Path) -> bool:
    try:
        report = hc22000.convert(path)
    except (hc22000.CaptureFormatError, OSError, ValueError):
        return False
    return report.ok


#: Parsing a capture is not free, and a scan redraws constantly. Keyed on what
#: the answer actually depends on -- the set of files and their sizes -- so an
#: unchanged folder is read once and a new capture is picked up immediately.
_CACHE: tuple[tuple, dict[str, StationInfo]] | None = None


def survey(directory: Path | None = None) -> dict[str, StationInfo]:
    """The newest observation per access point, across every saved capture."""
    global _CACHE
    folder = directory or ensure_captures_dir()
    try:
        files = sorted(folder.glob("*.pcap*"))
    except OSError:
        return {}
    key = tuple((str(f), f.stat().st_mtime_ns, f.stat().st_size) for f in files)
    if _CACHE is not None and _CACHE[0] == key:
        return _CACHE[1]

    newest: dict[str, StationInfo] = {}
    for path in files:
        try:
            stamp = datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            continue
        found = _station_for(path)
        if not found:
            continue
        # Whether the hash is in hand has to be asked of *this* file. Asked of
        # whichever capture happened to sort last, it would credit a network
        # with a hash that lives in some other network's capture.
        cracked = _has_hash(path)
        for bssid, (devices, randomised) in found.items():
            # The most recent capture of a network supersedes the older ones:
            # what is on it now is what an attack has to deal with now.
            if bssid in newest and newest[bssid].captured_at > stamp:
                continue
            newest[bssid] = StationInfo(devices=devices, randomised=randomised,
                                         captured_at=stamp, has_hash=cracked)
    _CACHE = (key, newest)
    return newest


def forget() -> None:
    """Drop the cache, for tests and for a folder that changed underneath us."""
    global _CACHE
    _CACHE = None


def devices_on(network, directory: Path | None = None) -> StationInfo | None:
    """What the captures say about ``network``, or None if it was never captured.

    ``directory`` defaults to the project's own ``captures/``. It is a parameter
    rather than a constant so that a folder can be surveyed without the answer
    being cached against a path nobody is reading.
    """
    if not network.bssid:
        return None
    return survey(directory or ensure_captures_dir()).get(
        network.bssid.replace(":", "").lower())