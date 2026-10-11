"""The single place netsh is run, because netsh is inconsistent about encoding.

Two problems this module exists to solve. Both were found by running the app on a
real Russian Windows 11 machine, not by reading the code:

**1. netsh changes output encoding under concurrency.** With a single netsh
process talking to the WLAN API it writes UTF-8. Start a second one and it falls
back to the console code page -- CP866 on a Russian build. The output is then
still valid text, just in a different encoding, and every Cyrillic field label
becomes replacement characters when decoded as UTF-8. The scan still lists SSIDs
and BSSIDs (ASCII), but signal, channel and authentication all come back empty,
``Network.crackable`` is False across the whole list, and the tool cheerfully
refuses to attack anything. The app starts ~10 netsh calls at once (adapter,
saved profiles, scan), so "only one at a time" is not something to assume.

**2. So netsh calls are serialised here**, behind one lock, which restores the
UTF-8 behaviour for the whole application.

Decoding does not rely on the lock alone. :func:`decode` accepts either encoding
and picks whichever produces more Cyrillic letters, because the field labels *are*
Cyrillic: a correct decode is directly measurable, and guessing from a BOM or a
locale guess is not. Labels stay readable even if netsh is replaced by something
else entirely, and ASCII-only output takes the fast path unchanged.
"""
from __future__ import annotations

import locale
import subprocess
import threading
from typing import Sequence

#: Serialises every netsh invocation in the process. Not reentrant use of netsh
#: that this guards -- it is the encoding fallback above that it prevents, which
#: no amount of correct decoding downstream can undo.
_NETSH_LOCK = threading.Lock()

#: netsh is not always on PATH on a trimmed Windows image; fall back to the
#: absolute path before giving up.
_NETSH_CANDIDATES = (r"%SystemRoot%\System32\netsh.exe", "netsh.exe")


class NetshError(RuntimeError):
    """Raised when netsh cannot be run or says nothing useful."""


def _netsh_command() -> str:
    import os

    for candidate in _NETSH_CANDIDATES:
        path = os.path.expandvars(candidate)
        if os.path.isfile(path):
            return path
    return "netsh.exe"


def _cyrillic_score(text: str) -> int:
    return sum("\u0400" <= ch <= "\u04ff" for ch in text)


def decode(raw: bytes | str | None) -> str:
    """Decode netsh output, which may be UTF-8 or the console code page.

    Scored rather than sniffed: the labels that matter are Cyrillic, so the
    encoding that yields more of them is the one that actually parsed the fields.
    """
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    best, score = "", -1
    for encoding in _fallback_encodings():
        try:
            candidate = raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        current = _cyrillic_score(candidate)
        if current > score:
            best, score = candidate, current
    return best or raw.decode("utf-8", errors="replace")


def _fallback_encodings() -> tuple[str, ...]:
    """Preferred encoding first, then the code pages netsh actually uses."""
    candidates = [locale.getpreferredencoding(False), "cp866", "cp1251", "cp1252"]
    seen: list[str] = []
    for name in candidates:
        if name and name.casefold() not in {n.casefold() for n in seen}:
            seen.append(name)
    return tuple(seen)


def run(args: Sequence[str], timeout: float = 25.0) -> tuple[str, int]:
    """Run ``netsh <args>`` and return (decoded stdout, return code).

    Serialised, so a caller never has to reason about whether some other part of
    the app is mid-``netsh`` and would make this one decode differently.
    """
    command = [_netsh_command(), *args]
    with _NETSH_LOCK:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise NetshError(f"netsh не ответил вовремя ({' '.join(args)})") from exc
        except (FileNotFoundError, OSError) as exc:
            raise NetshError(f"netsh недоступен: {exc}") from exc
    return decode(proc.stdout), proc.returncode