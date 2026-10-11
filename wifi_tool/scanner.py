"""Network scanner built on `netsh wlan show networks mode=bssid`.

The parser is locale-tolerant: it keys off tokens that are identical in
English and Russian builds (``SSID <n> :`` and ``BSSID``) and matches the
signal / channel / auth labels by a set of known synonyms, so it keeps
working across Windows locales.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import List

from .models import Network
from .netsh import NetshError
from .netsh import run as run_netsh

#: Field labels, matched exactly. Russian netsh spells authentication
#: "Проверка подлинности" -- "Аутентификация" appears in no Windows build and used
#: to be the only Russian spelling here, which left ``auth`` empty on every
#: network and made the whole scan list uncrackable.
_SIGNAL_KEYS = ("Сигнал", "Качество сигнала", "Signal")
_CHANNEL_KEYS = ("Канал", "Channel")
_AUTH_KEYS = (
    "Проверка подлинности",
    "Аутентификация",
    "Authentication",
    "Auth",
)
_PROT_KEYS = ("Защита", "Protection", "Шифрование", "Encryption")
_RADIO_KEYS = ("Радиотип", "Radio type", "Тип радио", "Radio")
_ASSOC_KEYS = ("Ассоциирован", "Associated")

_SSID_RE = re.compile(r"^\s*SSID\s+(\d+)\s*:\s*(.*)$")
_BSSID_RE = re.compile(r"^\s*BSSID(?:\s+\d+)?\s*:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*$", re.MULTILINE | re.IGNORECASE)
_PCT_RE = re.compile(r"(\d{1,3})\s*%")


def _pick(line: str, keys) -> str:
    """Match an exact field label, excluding e.g. Channel Utilization."""
    label, separator, value = line.partition(":")
    if separator and label.strip().casefold() in {key.casefold() for key in keys}:
        return value.strip()
    return ""


def parse_networks(text: str) -> List[Network]:
    """Parse `netsh wlan show networks mode=bssid` output into Networks."""
    nets: List[Network] = []
    cur: Network | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        m = _SSID_RE.match(line)
        if m:
            cur = Network(ssid=m.group(2).strip(), bssid="")
            nets.append(cur)
            continue

        if cur is None:
            continue

        mb = _BSSID_RE.search(line)
        if mb:
            if cur.bssid:
                # One SSID may advertise multiple access points. Security is
                # shared, while signal, radio and channel belong to each BSSID.
                cur = Network(ssid=cur.ssid, bssid="", auth=cur.auth,
                              protection=cur.protection)
                nets.append(cur)
            cur.bssid = mb.group(1).lower()
            continue

        val = _pick(line, _SIGNAL_KEYS)
        if val:
            pm = _PCT_RE.search(val)
            if pm:
                cur.signal = int(pm.group(1))
            continue

        val = _pick(line, _CHANNEL_KEYS)
        if val:
            cm = re.search(r"\d+", val)
            if cm:
                cur.channel = int(cm.group(0))
            continue

        val = _pick(line, _AUTH_KEYS)
        if val:
            cur.auth = val
            continue

        val = _pick(line, _PROT_KEYS)
        if val:
            cur.protection = val
            continue

        val = _pick(line, _RADIO_KEYS)
        if val:
            cur.radio = val
            continue

        val = _pick(line, _ASSOC_KEYS)
        if val:
            cur.associated = any(w in val for w in ("Да", "Yes", "true", "True"))
            continue

    return nets


class ScanError(RuntimeError):
    """Raised when a scan could not be performed."""


# netsh prints these instead of a network list when the scan is refused.
_LOCATION_MARKERS = ("ms-settings:privacy-location", "службы определения местоположения")
_DENIED_MARKERS = (
    "не найден",
    "запрещено",
    "отказано в доступе",
    "request not permitted",
    "access is denied",
    "не установлен",
)


def _describe_refusal(out: str) -> str | None:
    """Turn netsh's refusal into an instruction that says why it matters.

    Windows gates the Wi-Fi scan API behind the "Location" privacy switch, so a
    refusal names it. The message used to read as though the program wanted the
    user's coordinates, because it never said the switch is about reading the
    list of nearby networks. Nothing here reads a position -- the whole scan is
    ``netsh wlan show networks mode=bssid`` -- and saying so is what makes the
    instruction reasonable to follow.
    """
    low = out.lower()
    if any(m in low for m in _LOCATION_MARKERS):
        return (
            "Windows не отдал список сетей.\n"
            "Нужен переключатель «Местоположение» — он управляет доступом к Wi-Fi, "
            "не координатами: Win+R -> ms-settings:privacy-location -> «Службы "
            "определения местоположения» -> Вкл."
        )
    if any(m in low for m in _DENIED_MARKERS):
        return (
            "Список сетей недоступен. Нужны права администратора и доступ к "
            "Wi-Fi в Windows: ms-settings:privacy-location -> Вкл."
        )
    return None


def _run_netsh(args: List[str], timeout: float) -> str:
    """Run a netsh command and return its stdout, raising ScanError on failure.

    Serialised and decoded by :mod:`wifi_tool.netsh`: netsh silently switches to
    the console code page when several of its own processes run at once, which
    destroys every Cyrillic field label and leaves the scan list with no auth, no
    signal and no channel.
    """
    try:
        out, code = run_netsh(args, timeout)
    except NetshError as exc:
        raise ScanError(str(exc)) from exc
    if not (_BSSID_RE.search(out) or _SSID_RE.search(out)):
        refusal = _describe_refusal(out)
        if refusal:
            raise ScanError(refusal)
    if code != 0:
        raise ScanError(f"netsh вернул код {code}")
    return out


def scan(timeout: float = 15.0) -> List[Network]:
    """Run the scan and return the parsed network list."""
    return parse_networks(_run_netsh(["wlan", "show", "networks", "mode=bssid"], timeout))


@dataclass
class AdapterInfo:
    name: str
    description: str
    mac: str
    state: str


# Exact netsh wlan field labels (RU + EN). Matching is exact on the label part
# before the colon -- "Состояние радио:" must not overwrite "Состояние:".
_LABELS = {
    "name": ("имя", "name"),
    "description": ("описание", "description"),
    "mac": ("физический адрес", "physical address"),
    "state": ("состояние", "state"),
}


def detect_adapter() -> AdapterInfo | None:
    """Return the primary wireless adapter, or None if absent."""
    try:
        out = _run_netsh(["wlan", "show", "interfaces"], 10.0)
    except ScanError:
        return None

    info = AdapterInfo(name="", description="", mac="", state="")
    lookup = {label: key for key, labels in _LABELS.items() for label in labels}
    mac_re = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")

    for raw in out.splitlines():
        if ":" not in raw:
            continue
        label, _, value = raw.partition(":")
        key = lookup.get(label.strip().lower())
        if key is None:
            continue
        value = value.strip()
        if key == "mac":
            m = mac_re.search(value)
            info.mac = m.group(1).lower() if m else ""
        elif not getattr(info, key):
            setattr(info, key, value)

    return info if info.description else None
