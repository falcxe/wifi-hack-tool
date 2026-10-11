"""Parser self-test against real ``netsh wlan show networks mode=bssid`` output.

The Russian sample below is verbatim output from a Russian Windows 11 build,
captured with ``netsh wlan show networks mode=bssid``. That matters: the original
fixture invented the label "Аутентификация", which no Windows build emits. The
real label is "Проверка подлинности", so ``auth`` came back empty for every
network, ``Network.crackable`` was False across the whole scan list, and the tool
refused to attack anything. A synthetic fixture cannot catch that; this one can.
"""
from __future__ import annotations

import concurrent.futures
import subprocess

from wifi_tool import netsh
from wifi_tool.scanner import parse_networks, scan

#: Verbatim Russian netsh output, including the per-BSSID indentation and the
#: extra "Нагрузка BSS" block that real builds interleave.
REAL_RU = """
Имя интерфейса: Беспроводная сеть
Сейчас видно следующее количество сетей: 3.

SSID 1: MGTS_GPON5_D7F7
    Тип сети:                 Инфраструктура
    Проверка подлинности:     WPA2-Personal
    Шифрование:               CCMP
    BSSID 1                 : 10:50:72:01:25:a9
         Сигнал             : 70%
         Тип радио         : 802.11ac
         Диапазон               : 5 ГГц
         Канал            : 48
         Базовая скорость (мбит/с): 6

SSID 2: Obi_2.4
    Тип сети:                 Инфраструктура
    Проверка подлинности:     WPA3-Personal
    Шифрование:               CCMP
    BSSID 1                 : 78:9a:18:08:2f:d6
         Сигнал             : 72%
         Тип радио         : 802.11ax
         Канал            : 7
         Сведения            :  (поддерживается H2E)
         Нагрузка BSS:
             Подключенные станции: 3
             Использование канала:        101 (39%)

SSID 3: Cafe_Free
    Тип сети:                 Инфраструктура
    Проверка подлинности:     Открытая
    Шифрование:               Нет
    BSSID 1                 : 6c:5a:b0:34:39:82
         Сигнал             : 45%
         Тип радио         : 802.11n
         Канал            : 11
"""

#: The English label set, same layout.
REAL_EN = """
Interface name: Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 82%
         Radio type         : 802.11ax
         Channel            : 6

SSID 2 : Corp
    Network type            : Infrastructure
    Authentication          : WPA2-Enterprise
    Encryption              : AES
    BSSID 1                 : aa:bb:cc:dd:ee:02
         Signal             : 30%
         Radio type         : 802.11ac
         Channel            : 36
"""

nets = parse_networks(REAL_RU)
for n in nets:
    print(f"{n.label!r:18} bssid={n.bssid} ch={n.channel} sig={n.signal} "
          f"auth={n.auth!r} prot={n.protection!r} radio={n.radio!r} "
          f"crackable={n.crackable}")

assert len(nets) == 3, f"expected 3 networks, got {len(nets)}"

home, wpa3, open_net = nets

# The regression: without "Проверка подлинности" in the label set, auth is ""
# and nothing in the list is crackable.
assert home.auth == "WPA2-Personal", f"Russian auth not parsed: {home.auth!r}"
assert home.protection == "CCMP"
assert home.signal == 70
assert home.channel == 48
assert home.radio == "802.11ac"
assert home.bssid == "10:50:72:01:25:a9"
assert home.crackable, "a WPA2-Personal network must be a valid offline target"

assert wpa3.auth == "WPA3-Personal"
assert wpa3.crackable is False, "SAE has no offline handshake to capture"
assert wpa3.signal == 72
assert wpa3.channel == 7

assert open_net.auth == "Открытая"
assert open_net.crackable is False
assert open_net.signal == 45

# "Нагрузка BSS: Подключенные станции: 3" must not be mistaken for a field.
assert wpa3.signal == 72, "a BSS-load line overwrote the signal"

en = parse_networks(REAL_EN)
assert [n.auth for n in en] == ["WPA2-Personal", "WPA2-Enterprise"], en
assert en[0].crackable is True
assert en[1].crackable is False, "Enterprise needs a RADIUS server, not a dictionary"
assert en[0].signal == 82 and en[0].channel == 6

# And against the live scanner, so a Windows build change cannot slip past a
# fixture alone.
try:
    live = scan()
except Exception as exc:  # noqa: BLE001 - scanning is not available everywhere
    print(f"\nlive scan skipped: {exc}")
else:
    missing = [n.label for n in live if not n.auth]
    assert not missing, (
        f"networks parsed without an auth label: {missing}\n"
        "netsh probably renamed the field -- add it to _AUTH_KEYS"
    )
    usable = [n for n in live if n.crackable]
    print(f"\nlive scan: {len(live)} network(s), {len(usable)} with a WPA/PSK target")
    assert live, "the live scan returned nothing at all"

# The same call while other netsh work is in flight. netsh switches to the
# console code page once it is not the only netsh talking to the WLAN API, and
# decoding that as UTF-8 silently empties every Cyrillic label -- which made the
# whole scan list uncrackable while still looking perfectly normal.
def _churn() -> int:
    # read_all shells out once per saved profile; the app does this and the scan
    # at the same time on every startup.
    from wifi_tool import profiles

    return len(profiles.read_all())


with concurrent.futures.ThreadPoolExecutor(4) as pool:
    busy = pool.submit(_churn)
    concurrent_scans = [pool.submit(scan) for _ in range(3)]
    busy.result()
    stressed = [f.result() for f in concurrent_scans]

for index, nets in enumerate(stressed):
    blank = [n.label for n in nets if not n.auth]
    assert not blank, (
        f"concurrent scan {index} lost its auth labels for {blank[:3]} -- "
        "netsh fell back to the console code page and the decode missed it"
    )
    assert any(n.signal for n in nets), (
        f"concurrent scan {index} lost every signal reading"
    )
print(f"concurrent: {len(stressed)} scan(s) with profiles churning -- labels intact")

# And the decoder itself, on both encodings the same text can arrive in.
ru_line = "    Проверка подлинности:     WPA2-Personal"
assert netsh.decode(ru_line.encode("utf-8")).strip() == ru_line.strip()
assert netsh.decode(ru_line.encode("cp866")).strip() == ru_line.strip()
assert netsh.decode(b"SSID 1: Home\n") == "SSID 1: Home\n"
assert netsh.decode(b"") == ""
assert netsh.decode(None) == ""
assert netsh.decode("already text") == "already text"

# The label set has to survive netsh itself, whatever the system code page is.
raw = subprocess.run(
    ["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True
).stdout
for label in ("Проверка подлинности", "Authentication"):
    if label.encode("utf-8") in raw:
        assert label in netsh.decode(raw), f"netsh emits {label!r} but decode lost it"
        break
else:
    raise AssertionError(
        "netsh emitted neither the Russian nor the English auth label -- "
        "the parser needs updating for this Windows build"
    )

# Both encodings netsh is known to produce must yield the same parse result.
# The whole point of wifi_tool.netsh: whichever one arrives, the fields survive.
ru_lines = [ln for ln in REAL_RU.splitlines() if ln.strip()]
from_utf8 = parse_networks("\n".join(ru_lines))
from_cp866 = parse_networks(
    netsh.decode("\n".join(ru_lines).encode("cp866", errors="replace"))
)
assert [n.auth for n in from_utf8] == [n.auth for n in from_cp866]
assert [n.signal for n in from_utf8] == [n.signal for n in from_cp866]
assert [n.crackable for n in from_utf8] == [n.crackable for n in from_cp866]
assert from_cp866[0].auth == "WPA2-Personal", (
    f"a CP866-encoded scan did not parse: {from_cp866[0].auth!r}"
)
print("encodings: UTF-8 and CP866 scans parse identically")

print("\nALL PARSER ASSERTS PASSED")