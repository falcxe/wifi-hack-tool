"""Russian explanations of the audit methods actually provided by the TUI."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MethodInfo:
    title: str
    description: str
    advantage: str
    limitation: str


SOURCES = {
    "file": MethodInfo("Файл захвата", "Файл с EAPOL или PMKID выбранной сети.",
                       "Повторная проверка без подключения к сети.", "Нужны пригодные записи WPA/WPA2-PSK."),
    "live": MethodInfo("Захват сети", "Запись обмена WPA2 с последующей проверкой.",
                       "Данные и подбор в одном запуске.", "Нужны адаптер и драйвер с режимом монитора."),
}
METHODS = {
    "quick": MethodInfo("Быстрый словарь", "Небольшой список частых паролей.",
                        "Быстрый запуск.", "Проверяются только варианты из списка."),
    "rockyou": MethodInfo("RockYou WPA", "Готовый большой словарь.",
                          "Больше вариантов, чем в быстром списке.", "Проверка может упереться в лимит времени."),
    "custom": MethodInfo("Свой словарь", "Текстовый файл: один вариант на строку.",
                         "Вы задаёте список вариантов.", "Пароля вне списка не будет в результате."),
    "mask": MethodInfo("Маска", "Известный формат: Course?d?d — от Course00 до Course99.",
                       "Полный охват заданного формата.", "Число вариантов быстро растёт с длиной маски."),
}
RULES = MethodInfo("Мутации", "Правила меняют регистр, добавляют цифры и заменяют символы.",
                   "Больше вариантов из словаря.", "Дольше работают; с маской не применяются.")
RUNTIME = MethodInfo("Лимит времени", "Секунды работы подбора: 1800 — 30 минут. "
                     "В авторежиме это бюджет всей лестницы, а не одного запуска.",
                     "Ограничивает длительность.",
                     "Часть вариантов может остаться непроверенной — при 1800 с "
                     "лестница не добирает конца мутаций RockYou.")
SAVED = MethodInfo("Сохранённые сети", "Ключи из доступных профилей Windows.",
                  "Без словаря и захвата.", "Только сети, к которым этот ПК уже подключался.")


def contextual_info(field: str, values: dict) -> MethodInfo:
    if field in ("source", "capture", "bssid"):
        return SOURCES.get(values.get("source"), SOURCES["file"])
    if field in ("rules", "rules_path"):
        return RULES
    if field == "runtime":
        return RUNTIME
    if field == "deauth":
        from .forms import DEAUTH

        return DEAUTH
    return METHODS.get(values.get("mode"), METHODS["rockyou"])


def document() -> list[tuple[str, str]]:
    rows = [
        ("Данные для запуска", "title"),
        ("Для WPA/WPA2-PSK нужны EAPOL или PMKID. Имя сети само по себе не позволяет проверить пароль.", "text"),
        ("WPA3-SAE и Enterprise этим подбором не проверяются.", "minus"),
        ("", "text"),
    ]
    for entry in (SOURCES["file"], SOURCES["live"], METHODS["quick"], METHODS["rockyou"],
                  METHODS["custom"], METHODS["mask"], RULES, RUNTIME, SAVED):
        rows.extend([(entry.title, "title"), (entry.description, "text"),
                     ("Плюс: " + entry.advantage, "plus"),
                     ("Минус: " + entry.limitation, "minus"), ("", "text")])
    rows.extend([
        ("Символы маски", "title"),
        ("?d — цифра; ?l — строчная латинская; ?u — заглавная латинская.", "text"),
        ("", "text"),
        ("Результат", "title"),
        ("«Не найден» означает отсутствие совпадения среди проверенных вариантов.", "text"),
        ("", "text"),
    ])
    rows.extend(where_to_get_a_capture())
    return rows


def where_to_get_a_capture() -> list[tuple[str, str]]:
    return [
        ("Откуда взять файл захвата", "title"),
        ("Подходят .pcap, .pcapng, .cap, .22000 и .hc22000.", "text"),
        ("Захват можно получить с подключённой платы или адаптера с режимом монитора.", "text"),
        ("Живой захват слушает эфир до 5 минут и останавливается сам, как только "
         "рукопожатие поймано.", "text"),
        ("Захват пассивный: он ловит обмен только когда клиент сам подключается "
         "или переподключается к сети. Если устройств в сети нет — помогает "
         "только переподключение своего телефона во время захвата.", "text"),
        ("Во время захвата переподключите своё устройство к сети, чтобы появился обмен EAPOL.", "text"),
        ("Готовый файл выбирается в поле «Захват».", "text"),
    ]
