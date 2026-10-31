"""Everything the user is told, in words that describe an action.

The pipeline knows the machine in technical nouns: ``hashcat``, ``tshark``, an
Npcap backend, an interface index, a capture problem string. Those names are
right for a log and wrong for the screen someone reads before deciding what to
do, so this module is the single place that turns one into the other.

The rule it follows: **a line is written for a person who has never opened a
terminal.** It says what the machine can do now and what to press next. The
technical name never appears in the line -- it appears in
:func:`technical_lines`, which is what the collapsible «Подробности» section
shows. One place to change when a wording is wrong, and a lint
(``tools/check_plain_language.py``) that fails when a jargon word creeps back
into the user-facing half.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Scenario key -> what the screen calls it. Same order as the picker, so
#: "the second line" and the key always agree.
TITLES = {
    "network": "Проверить свою сеть",
    "file": "Разобрать готовый файл",
    "saved": "Найти сохранённый пароль",
}

#: One line under each title: what the user gets, in outcome words.
SUBTITLES = {
    "network": "Найти сеть рядом и подобрать пароль.",
    "file": "Проверить пароль по файлу, который уже есть на диске.",
    "saved": "Посмотреть, какие пароли этот компьютер уже знает.",
}

#: Words that may not appear in a user-facing line. Checked by the lint; kept
#: here so the list and the reason live together.
JARGON = (
    "hashcat", "tshark", "npcap", "cap80211", "eapol", "pmkid", "wpa2", "wpa3",
    "bssid", "ssid", "монитор", "интерфейс", "драйвер", "хэш", "словар",
    "ассоциация", "аутентификация", "шифрование", "вектор", "pbkdf2",
)

INSTALL_HINT = "Нажмите F1 и выберите «Установить компоненты»"


@dataclass(frozen=True)
class Fact:
    """One row of the readiness checklist, written as an action."""

    ok: bool
    title: str
    status: str
    todo: str = ""
    detail: str = ""
    #: Optional rows are alternatives, not blockers. The M5StickC board is one:
    #: its absence changes nothing as long as the built-in adapter can capture,
    #: so it must not be able to turn a working machine into a red one.
    optional: bool = False


def _name(path) -> str:
    from pathlib import Path

    return Path(path).name if path else ""


def _adapter_name(ready) -> str:
    return getattr(ready.adapter, "description", "") or "не найден"


def capture_fact(ready) -> Fact:
    """Can this machine record what is in the air right now?

    The composite of four separate answers (rights, driver, tool, adapter), so
    it is reported as one row with the first missing thing as its remedy rather
    than as four rows a beginner has to combine.
    """
    if ready is None:
        return Fact(False, "Захват в эфире", "проверяю…")
    if not ready.admin:
        return Fact(False, "Захват в эфире", "нужны права администратора",
                    "Закройте программу, запустите её правой кнопкой от администратора.",
                    ready.capture_problem or "")
    if ready.capture_problem:
        return Fact(False, "Захват в эфире", "этот адаптер не умеет записывать эфир",
                    "Подключите адаптер, который умеет, или берите готовый файл.",
                    ready.capture_problem)
    if ready.backend is None:
        return Fact(False, "Захват в эфире", "нет программы для записи",
                    INSTALL_HINT)
    if ready.iface is None:
        return Fact(False, "Захват в эфире", "Wi-Fi не найден",
                    "Проверьте, что адаптер включён и подключён.")
    return Fact(True, "Захват в эфире", f"можно, адаптер {_short_adapter(_adapter_name(ready))}")


def _short_adapter(description: str) -> str:
    """Adapter names run to fifty characters; the checkmark line does not."""
    text = description.replace("Intel(R) ", "").replace("Wireless-AC", "").strip()
    return text if len(text) <= 34 else text[:33] + "…"


def _program_fact(ready) -> Fact:
    found = ready is not None and ready.hashcat is not None
    return Fact(found, "Программа подбора",
                "установлена" if found else "не установлена",
                "" if found else INSTALL_HINT,
                _name(getattr(ready, "hashcat", None)))


def _list_fact(ready) -> Fact:
    found = ready is not None and ready.wordlist is not None
    return Fact(found, "Список частых паролей",
                "есть" if found else "нет",
                "" if found else INSTALL_HINT,
                _name(getattr(ready, "wordlist", None)))


def _board_fact(board) -> Fact:
    if isinstance(board, str):
        return Fact(True, "Плата M5StickC", f"подключена ({board})")
    return Fact(False, "Плата M5StickC", "не подключена",
                "Вставьте плату в USB — она умеет записывать эфир сама.",
                optional=True)


def facts(ready, scenario: str = "network", *, board=None) -> list[Fact]:
    """The checklist for one scenario: only what that scenario actually needs.

    A beginner reading four rows about one task cannot tell which row is
    blocking them, so each scenario gets its own short list instead of the union
    of all of them.
    """
    if scenario == "file":
        rows = [_program_fact(ready), _list_fact(ready)]
    elif scenario == "saved":
        rows = [Fact(True, "Пароли в истории Windows", "доступны без установки")]
    else:
        capture = capture_fact(ready)
        rows = [capture, _program_fact(ready), _list_fact(ready)]
        # The board is a second way to capture, so it is worth a row only when
        # the first way does not work.
        if not capture.ok:
            rows.append(_board_fact(board))
    return rows


def blocking(ready, scenario: str) -> list[Fact]:
    """The rows that stop this scenario -- optional alternatives excluded."""
    return [row for row in facts(ready, scenario) if not row.ok and not row.optional]


def headline(ready, scenario: str) -> str:
    """One sentence: can this scenario run here, right now."""
    if scenario == "saved":
        return "Готово. Права администратора не нужны."
    if ready is None:
        return "Проверяю компьютер…"
    missing = blocking(ready, scenario)
    if not missing:
        return "Готово. Можно начинать."
    names = ", ".join(row.title.lower() for row in missing)
    if scenario == "network" and missing[0].title == "Захват в эфире":
        return "Захват в эфире на этом компьютере невозможен — подойдёт готовый файл."
    return f"Не хватает: {names}."


def next_step(ready, scenario: str) -> str:
    """The single most useful thing to press, as one sentence."""
    if scenario == "saved":
        return "Enter — открыть список сетей, которые этот компьютер помнит."
    if ready is None:
        return "Подождите секунду: идёт проверка."
    todo = next((row.todo for row in blocking(ready, scenario) if row.todo), "")
    return todo or "Enter — начать."


def blocked_for(ready, scenario: str) -> bool:
    """Whether the primary action on this screen would fail as things stand."""
    return bool(blocking(ready, scenario))


def technical_lines(ready) -> list[str]:
    """The collapsible section: exact names, paths and messages, untranslated.

    This is the half that is deliberately *not* simplified. Someone who has to
    file a bug, read a manual or find a folder needs the real string, and
    hiding it behind the plain wording would make both tasks harder.
    """
    if ready is None:
        return ["Компоненты ещё проверяются…"]
    rows = [
        f"Права администратора: {'да' if ready.admin else 'нет'}",
        f"Wi-Fi адаптер: {_adapter_name(ready)}",
        f"Программа подбора: {getattr(ready, 'hashcat', None) or 'не найдена'}",
        f"Список паролей: {getattr(ready, 'wordlist', None) or 'не найден'}",
        f"Правила мутаций: {getattr(ready, 'rules', None) or 'не найдены'}",
        f"Инструмент захвата: {getattr(getattr(ready, 'backend', None), 'exe', None) or 'не найден'}",
        f"Интерфейс захвата: {ready.iface or 'не найден'}",
        f"Маска: {getattr(ready, 'mask', None) or '—'}",
    ]
    if ready.capture_problem:
        rows.append(f"Причина: {ready.capture_problem}")
    rows.extend(sorted(ready.problems))
    return rows