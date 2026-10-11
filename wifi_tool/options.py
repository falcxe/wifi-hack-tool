"""Explicit settings for a bounded password audit."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"

#: Where captures this program makes live, and where captures pulled off a board
#: are put. Inside the project on purpose: the user asked for the program to
#: keep its own files, and a capture is a thing you may need to send someone or
#: re-open later -- the temp directory is cleared by Windows on its own schedule
#: and without warning.
CAPTURES_DIR = PROJECT_ROOT / "captures"


def ensure_captures_dir() -> Path:
    """Create and return the captures folder, tolerating a read-only install."""
    try:
        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return CAPTURES_DIR

#: Dictionary file names accepted for the main wordlist, best first. These live
#: here, not in the settings form, because both the form and the pipeline have
#: to agree on what "a dictionary is present" means: the form used to hardcode
#: ``assets/rockyou-wpa.txt`` while the pipeline accepted any of these, so a
#: user with ``rockyou.txt`` saw the checklist say the dictionary was found and
#: then got "Словарь не найден" on the next screen.
WORDLIST_NAMES = (
    "rockyou-wpa.txt", "rockyou.txt", "wordlist.txt", "passwords.txt", "cracked.txt",
)

#: The small high-yield list, if the project ships it.
QUICK_WORDLIST_NAMES = ("probable-wpa.txt", "probable-v2-wpa-top4800.txt")


def find_wordlist(directory: Path | None = None) -> Path | None:
    """The first known dictionary present in ``directory`` (default assets/)."""
    base = directory or ASSETS_DIR
    for name in WORDLIST_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def find_quick_wordlist(directory: Path | None = None) -> Path | None:
    """The small high-yield dictionary, if it is on disk."""
    base = directory or ASSETS_DIR
    for name in QUICK_WORDLIST_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def normalize_bssid(value: str) -> str:
    compact = value.replace(":", "").replace("-", "").lower()
    if not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise ValueError("BSSID должен содержать 6 байт, например aa:bb:cc:dd:ee:ff")
    return compact


def validate_mask(mask: str) -> None:
    """Count byte positions, including hashcat's built-in character classes."""
    if mask.startswith("-"):
        raise ValueError("Маска не должна начинаться с дефиса")
    length = 0
    i = 0
    while i < len(mask):
        if mask[i] == "?":
            i += 1
            if i == len(mask) or mask[i] not in "ludsabhH?":
                raise ValueError("Неизвестный символ маски; доступны ?l ?u ?d ?s ?a ?b ?h ?H и ??")
            length += 1
        else:
            length += len(mask[i].encode("utf-8"))
        i += 1
    if not 8 <= length <= 63:
        raise ValueError("Для WPA-Personal маска должна задавать от 8 до 63 байт")


@dataclass(frozen=True)
class CrackOptions:
    wordlist: Path | None = None
    rules: Path | None = None
    mask: str | None = None
    #: Wall-clock ceiling in seconds. In the manual mode it bounds one hashcat
    #: run; in the automatic mode it is the whole ladder's budget -- which is why
    #: the default is 1800 and not something smaller: the stages that actually
    #: find home-router passwords (RockYou through best66, all-digit runs) need
    #: half an hour to be covered completely, and a default that stops halfway
    #: through the mutation stage spends the same time for a fraction of the odds.
    runtime: int = 1800
    bssid: str | None = None
    use_rules: bool = True
    #: Force clients off the network during the capture so they reconnect and
    #: produce a handshake, instead of waiting for one to happen by itself.
    #: Off by default because the effect is on every device using that network,
    #: not just on this program.
    deauth: bool = False

    def validate(self) -> None:
        if self.runtime <= 0:
            raise ValueError("Лимит времени должен быть положительным числом секунд")
        if self.mask is not None:
            validate_mask(self.mask)
            if self.wordlist is not None or self.rules is not None:
                raise ValueError("Для маски не используются словарь и файл правил")
        for title, path in (("Словарь", self.wordlist), ("Файл правил", self.rules)):
            if path is not None and not path.is_file():
                raise ValueError(f"{title} не найден: {path}")
        if self.rules is not None and not self.use_rules:
            raise ValueError("--rules и --no-rules нельзя использовать вместе")
        if self.bssid is not None:
            normalize_bssid(self.bssid)
