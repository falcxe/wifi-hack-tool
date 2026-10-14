"""Tests for saved Wi-Fi profile reading.

The parser is locale-sensitive (netsh labels differ between Russian and English),
so both label sets are exercised. Extraction is verified against the real
profiles on this machine when any are present, and skipped otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool import profiles  # noqa: E402

RU_SAMPLE = """
Имя файла профиля: Wi-Fi-BruceNet
Профиль Wi-Fi-BruceNet интерфейса Беспроводная сеть:
----------------------------------------------------------------------
Сведения о профиле
    Имя файла профиля      : Wi-Fi-BruceNet
    Имя                   : BruceNet

Параметры подключения
    Количество SSID        : 1
    Имя SSID               : "BruceNet"

Параметры безопасности
    Проверка подлинности: WPA3-Personal
    Шифр:                    GCMP-256
    Проверка подлинности: WPA2-Personal
    Шифр:                    CCMP
    Ключ безопасности:       Присутствует
    Содержимое ключа            : brucenet
"""

EN_SAMPLE = """
Profile Wi-Fi-Home on interface Wi-Fi:
-------------------------------------------------
Profile information
    Name                    : Home

Connection parameters
    SSID count              : 1
    SSID name               : "Home"

Security parameters
    Authentication          : WPA2-Personal
    Cipher                  : CCMP
    Security key            : Present
    Contents of the key     : hunter2
"""

RU_ALL_USERS = """
Профиль Corp интерфейса Беспроводная сеть:
    Имя SSID               : "Corp"
    Проверка подлинности: WPA2-Personal
    Ключ безопасности:       Отсутствует
    Этот профиль применен ко всем пользователям
    Содержимое ключа            :
"""


def main() -> None:
    # --- label sets ---------------------------------------------------------
    ru = profiles._fields(RU_SAMPLE)
    assert ru["ssid"] == ["BruceNet"], ru.get("ssid")
    assert ru["auth"] == ["WPA3-Personal", "WPA2-Personal"], ru.get("auth")
    assert ru["key"] == ["brucenet"], ru.get("key")
    print("russian labels: ok")

    en = profiles._fields(EN_SAMPLE)
    assert en["ssid"] == ["Home"], en.get("ssid")
    assert en["auth"] == ["WPA2-Personal"], en.get("auth")
    assert en["key"] == ["hunter2"], en.get("key")
    print("english labels: ok")

    # --- AKM / cipher preference -------------------------------------------
    # A WPA3 transition AP lists both; WPA2 is what offline cracking targets.
    assert profiles._pick(["WPA3-Personal", "WPA2-Personal"], profiles._AUTH_PREFERENCE) == "WPA2-Personal"
    assert profiles._pick(["GCMP-256", "CCMP"], profiles._CIPHER_PREFERENCE) == "CCMP"
    assert profiles._pick([], profiles._AUTH_PREFERENCE) == ""
    print("akm preference: ok")

    # --- open network detection, both languages ----------------------------
    assert profiles.SavedProfile("a", "Открыть", "Нет").open_network
    assert profiles.SavedProfile("b", "Open", "None").open_network
    assert not profiles.SavedProfile("c", "WPA2-Personal", "CCMP").open_network
    print("open network detection: ok")

    # --- all-users profile is refused rather than mis-parsed ----------------
    low = RU_ALL_USERS.lower()
    assert any(m in low for m in profiles._KEY_UNAVAILABLE)
    print("all-users profile: ok")

    # --- profile list parsing ----------------------------------------------
    listing = """
Профили интерфейса Беспроводная сеть:

Профили пользователей
    Все профили пользователей     : Home
    Все профили пользователей     : Office
"""
    listed = [
        m.group(1).strip()
        for line in listing.splitlines()
        if (m := profiles._PROFILE_LIST_RE.match(line))
    ]
    assert listed == ["Home", "Office"], listed
    print("profile list: ok")

    # --- against the real machine ------------------------------------------
    try:
        found = profiles.read_all()
    except profiles.ProfileError as exc:
        print(f"real profiles: SKIP ({exc})")
    else:
        if not found:
            print("real profiles: SKIP (none saved on this machine)")
        else:
            assert all(p.name for p in found), found
            keys = profiles.count_with_keys(found)
            print(f"real profiles: {len(found)} read, {keys} with a readable key")
            for p in found:
                if p.has_key:
                    assert p.key, p
    print("ALL OK")


if __name__ == "__main__":
    main()