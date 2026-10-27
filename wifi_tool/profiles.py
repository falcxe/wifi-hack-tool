"""Saved Wi-Fi profiles: list them and read the stored key.

Windows keeps a profile for every network this machine has joined, and for
profiles owned by the current user ``netsh wlan show profile name=... key=clear``
returns the plaintext key. That works **without administrator rights** and
without any capture hardware, so it is the one path that is guaranteed to
produce results on a machine whose adapter cannot do monitor mode.

Field labels are localized, so both the Russian and English forms are matched:
``Все профили пользователей`` / ``All User Profile`` and
``Содержимое ключа`` / ``Contents of the key``.

**The switch.** :data:`HISTORY_ENABLED` decides whether the program looks here
at all. On by default, because a stored key is the one answer that needs no
capture and no luck. Turned off when the job is to get into a network rather
than to recall one this machine was already in: with it off, nothing reads a
profile, the «Сохранённые сети» screen is unreachable, and the automatic ladder
starts at the capture. One flag, read from the places that would consult it --
this module stays a plain reader, so nothing can reach the profiles by accident.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import netsh

#: False = ignore the connection history completely.
#:
#: Deliberately the one place to change: the pipeline, the run checklist and the
#: navigation all ask this, so turning it back on cannot leave one of them
#: quietly reading profiles anyway.
HISTORY_ENABLED = False

_PROFILE_LIST_RE = re.compile(
    r"^\s*(?:Все профили пользователей|All User Profile)\s*:\s*(.+?)\s*$",
    re.IGNORECASE,
)
# netsh prints "    Имя                    : BruceNet" -- label, pad, colon, value
_FIELD_RE = re.compile(r"^\s*(?P<label>[^:]+?)\s*:(?P<value>.*)$")

LABELS = {
    "ssid": ("имя ssid", "ssid name", "name ssid", "ssid"),
    "auth": ("проверка подлинности", "authentication", "auth"),
    "encryption": ("шифр", "cipher", "encryption"),
    "key": ("содержимое ключа", "contents of the key", "key content"),
    "key_present": ("ключ безопасности", "security key"),
}

#: Preference order when a profile lists several AKM/cipher pairs (a WPA3
#: transition-mode AP advertises both WPA3 and WPA2). WPA2 is preferred because
#: it is the one that offline cracking applies to.
_AUTH_PREFERENCE = ("wpa2-personal", "wpa2", "wpa3-personal", "wpa3", "wep", "open")
_CIPHER_PREFERENCE = ("ccmp", "aes", "gcmp", "tkip", "none")


def _pick(values: list[str], preference: tuple[str, ...]) -> str:
    if not values:
        return ""
    lowered = [(v, v.lower()) for v in values]
    for wanted in preference:
        for original, low in lowered:
            if wanted in low:
                return original
    return values[0]

#: Substrings that mean "this profile's key is not ours to read".
_KEY_UNAVAILABLE = (
    "профиль применен ко всем пользователям",
    "profile is applied to all users",
    "доступ запрещён",
    "access is denied",
)


class ProfileError(RuntimeError):
    """Raised when profiles cannot be read."""


@dataclass
class SavedProfile:
    """One saved network as stored by Windows."""

    name: str
    auth: str = ""
    encryption: str = ""
    key: str | None = None
    key_error: str = ""

    @property
    def has_key(self) -> bool:
        return bool(self.key)

    @property
    def open_network(self) -> bool:
        # Russian netsh reports "Открыть" (infinitive) and "Нет" for none.
        combined = f"{self.auth} {self.encryption}".lower()
        return any(
            marker in combined for marker in ("open", "открыт", "нет", "none")
        )


def _netsh(args: list[str], timeout: float = 25.0) -> str:
    """Run ``netsh wlan <args>`` and return its decoded output.

    The ``wlan`` context has to be added here: :mod:`wifi_tool.netsh` only knows
    the executable, and ``netsh show profiles`` is a different command that fails
    with "команда не найдена" rather than doing anything useful.
    """
    try:
        out, _code = netsh.run(["wlan", *args], timeout)
    except netsh.NetshError as exc:
        raise ProfileError(str(exc)) from exc
    return out


def list_profiles() -> list[str]:
    """Return the names of all saved profiles, in the order netsh lists them."""
    out = _netsh(["show", "profiles"])
    names: list[str] = []
    for line in out.splitlines():
        m = _PROFILE_LIST_RE.match(line)
        if m:
            name = m.group(1).strip()
            if name and name != "<Отсутствует>":
                names.append(name)
    return names


def _fields(text: str) -> dict[str, list[str]]:
    """Collect every ``label: value`` pair, keeping all values per label.

    Security sections repeat ``Проверка подлинности``/``Шифр`` once per
    supported AKM, so a label maps to a list rather than a single string.
    """
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = _FIELD_RE.match(line)
        if not m:
            continue
        label = m.group("label").strip().lower()
        raw_value = m.group("value")
        for key, names in LABELS.items():
            if any(name == label for name in names):
                if key == "key":
                    # netsh inserts one separator space after ':'. Everything
                    # after it is key material, including quotes and whitespace.
                    value = raw_value[1:] if raw_value.startswith(" ") else raw_value
                else:
                    value = raw_value.strip()
                    if key == "ssid" and value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                if value:
                    found.setdefault(key, []).append(value)
                break
    return found


def read_profile(name: str) -> SavedProfile:
    """Read one profile, including its key when the current user owns it."""
    # netsh re-parses its own command line rather than trusting argv as split
    # by the OS, so an unquoted "name=<value>" only works while <value> has no
    # spaces. A profile name is an SSID -- a string fully chosen by whichever
    # access point broadcast it, space and all -- so it is quoted the same way
    # capturer.py already has to quote an adapter name for the same reason.
    text = _netsh(["show", "profile", f'name="{name}"', "key=clear"])
    if not text.strip():
        raise ProfileError(f"профиль не найден: {name}")

    fields = _fields(text)
    ssids = fields.get("ssid") or []
    profile = SavedProfile(
        name=ssids[0] if ssids else name,
        auth=_pick(fields.get("auth", []), _AUTH_PREFERENCE),
        encryption=_pick(fields.get("encryption", []), _CIPHER_PREFERENCE),
    )

    keys = fields.get("key", [])
    low = text.lower()
    if any(marker in low for marker in _KEY_UNAVAILABLE):
        profile.key_error = "ключ защищён профилем «все пользователи»"
    elif keys:
        profile.key = keys[0]
    elif profile.open_network:
        profile.key = ""  # open network: nothing is stored
    else:
        profile.key_error = "ключ не показан"
    return profile


def read_all(limit: int | None = None) -> list[SavedProfile]:
    """Read every saved profile. Never raises per-profile failures."""
    names = list_profiles()
    if limit:
        names = names[:limit]
    out: list[SavedProfile] = []
    for name in names:
        try:
            out.append(read_profile(name))
        except ProfileError as exc:
            out.append(SavedProfile(name=name, key_error=str(exc)))
    return out


def find_profile(ssid: str) -> SavedProfile | None:
    """The saved profile for ``ssid``, or None when this machine never joined it.

    Only the profile list is read first, and a single profile is parsed when one
    matches: ``read_all`` shells out once per profile, which is far too slow to
    do on the way into an attack.
    """
    if not ssid:
        return None
    wanted = ssid.strip().strip('"')
    folded = wanted.casefold()
    try:
        names = list_profiles()
    except ProfileError:
        return None
    for candidate in names:
        if candidate == wanted:
            break
    else:
        # netsh quotes names containing spaces, and a profile name is the SSID,
        # so fall back to a case-insensitive match before giving up.
        matches = [n for n in names if n.casefold() == folded]
        if len(matches) != 1:
            return None
        candidate = matches[0]
    try:
        return read_profile(candidate)
    except ProfileError:
        return None


def find_key(ssid: str) -> str:
    """The plaintext key Windows stores for ``ssid`` -- "" when there is none.

    This is the only route in the project that does not depend on a guess being
    right, so the automatic ladder checks it before anything else: when this
    machine has joined the network the answer is already on disk.
    """
    profile = find_profile(ssid)
    return profile.key if profile is not None and profile.has_key else ""


def count_with_keys(profiles: list[SavedProfile]) -> int:
    return sum(1 for p in profiles if p.has_key)
