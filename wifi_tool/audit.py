"""Read-only audit notes derived from a Windows Wi-Fi scan snapshot."""
from __future__ import annotations

from .models import Network


def findings_for(network: Network) -> list[str]:
    """Return cautious observations; a scan snapshot is not a full AP audit."""
    findings: list[str] = []
    haystack = network.haystack

    if network.is_open:
        findings.append(
            "Объявлена открытая сеть без WPA-аутентификации; проверьте, что это ожидаемая настройка."
        )
    if network.is_wep:
        findings.append("Обнаружен WEP — устаревшая схема защиты.")
    if "tkip" in haystack:
        findings.append("Обнаружен TKIP — устаревший алгоритм шифрования.")
    if not findings:
        findings.append("В опубликованных полях сканирования WEP и TKIP не обнаружены.")

    return findings
