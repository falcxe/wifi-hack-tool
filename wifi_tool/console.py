"""Make the Windows console understand UTF-8 before anything is drawn.

Windows consoles default to a legacy code page -- 866 on a Russian machine, 437
in English locales -- while Python encodes its output as UTF-8. The result is
mojibake for every box-drawing character and every Cyrillic letter: ``╭─╮``
arrives as ``т╨тю═``.

``chcp 65001`` fixes it, but asking every user to type that (and remember it)
before each run is not acceptable, so it is done here instead, once, at startup.

Note this is *not* about which terminal is used: Windows Terminal and the legacy
conhost host both ignore UTF-8 bytes while the output code page is 866.
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading

UTF8_CODEPAGE = 65001

#: The session-long console watcher, if one was started.
_guard_thread = None
_guard_stop = None


def enable_utf8_console() -> list[str]:
    """Switch the console to UTF-8. Returns notes about what was changed."""
    notes: list[str] = []
    if os.name != "nt":
        return notes

    # Child processes (hashcat) parse our expectations, not the console's.
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")

    try:
        kernel32 = ctypes.windll.kernel32
    except Exception as exc:  # noqa: BLE001 - never block startup on this
        return [f"не удалось обратиться к консоли: {exc}"]

    try:
        kernel32.GetConsoleOutputCP.restype = ctypes.c_uint32
        kernel32.GetConsoleCP.restype = ctypes.c_uint32
        kernel32.SetConsoleOutputCP.argtypes = [ctypes.c_uint32]
        kernel32.SetConsoleCP.argtypes = [ctypes.c_uint32]
    except Exception:  # noqa: BLE001
        return notes

    try:
        out_cp = int(kernel32.GetConsoleOutputCP())
        in_cp = int(kernel32.GetConsoleCP())
    except Exception:  # noqa: BLE001
        return notes

    # A redirected stdout has no console for the code page to be set on, but
    # Python's own streams still encode as the locale's -- cp1251 on a Russian
    # machine -- so the file or pipe they go into gets mojibake instead of text.
    # Rebinding them is independent of any console, so it happens first and never
    # gets skipped: an earlier version returned early on a redirected stdout and
    # left precisely this unfixed.
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass

    if out_cp == 0:
        return notes

    if out_cp != UTF8_CODEPAGE:
        kernel32.SetConsoleOutputCP(UTF8_CODEPAGE)
        notes.append(f"кодовая страница вывода {out_cp} -> {UTF8_CODEPAGE}")

    # A raster font has no glyphs past U+00FF, so on a Russian console the page
    # change alone swaps "everything fine" for "ASCII fine, Cyrillic mojibake".
    note = _force_true_type_font()
    if note:
        notes.append(note)
    if in_cp != UTF8_CODEPAGE:
        # Affects keyboard input: without it, non-ASCII key names come back
        # mis-decoded and no key handler ever matches them.
        kernel32.SetConsoleCP(UTF8_CODEPAGE)
        notes.append(f"кодовая страница ввода {in_cp} -> {UTF8_CODEPAGE}")

    return notes


def start_codepage_guard(interval: float = 0.2) -> None:
    """Hold the console on UTF-8 for the rest of the session.

    Setting the code page at startup is a promise about the future that anything
    else attached to the same console can withdraw. This app is run next to a
    monitor-mode helper by definition, and such a helper switches the console
    back to the OEM page whenever it changes what it is doing.

    Fixing that by re-checking on a frame callback was tried and is not enough:
    the moments that need it are exactly the moments no callback is installed.
    A run that ends the instant it starts -- an SSID this machine has already
    joined needs no capture at all -- detaches its animation before the first
    frame, and the screen it lands on is drawn entirely after the reset. A
    daemon thread watching the page closes that hole without depending on when
    or whether a callback happens to be running.

    Silent by design: the UI thread reports a restore in its own log, and two
    threads writing the same buffer is how a fix becomes a second bug.
    """
    if os.name != "nt":
        return
    global _guard_thread, _guard_stop
    if _guard_thread is not None:
        return
    stop = threading.Event()

    def watch() -> None:
        while not stop.wait(interval):
            try:
                page = int(ctypes.windll.kernel32.GetConsoleOutputCP())
            except Exception:  # noqa: BLE001 - the watcher must never die
                return
            if page in (0, UTF8_CODEPAGE):
                continue
            try:
                ctypes.windll.kernel32.SetConsoleOutputCP(UTF8_CODEPAGE)
            except Exception:  # noqa: BLE001
                return

    thread = threading.Thread(target=watch, name="console-codepage", daemon=True)
    _guard_thread = thread
    _guard_stop = stop
    thread.start()


class _Coord(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _ConsoleFontInfoEx(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("dwFontIndex", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("FaceName", ctypes.c_wchar * 32),
        ("FontSize", _Coord),
    ]


#: TrueType faces to try, in order. Any of them fixes the problem; the first one
#: installed wins, and the list ends in the one that ships with every Windows.
UTF8_FONTS = ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Lucida Console")


def _console_output_handle():
    """The console's output handle, or None when there is no console.

    ``GetStdHandle`` answers INVALID_HANDLE_VALUE for a redirected stdout, and
    that value handed straight back to the console API is an access violation
    rather than a tidy failure -- so it is turned into None here, once, where
    every caller can simply skip.
    """
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetStdHandle.argtypes = [ctypes.c_ulong]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        kernel32.GetStdHandle.argtypes = None
        if not handle or int(handle) in (0, -1):
            return None
        return handle
    except Exception:  # noqa: BLE001
        return None


def _force_true_type_font() -> str:
    """Put a Unicode font on the console, and say which one.

    This is the second half of the UTF-8 switch, and skipping it is why "chcp
    65001" alone does not fix a Russian console. A console left on a raster font
    has a fixed single-byte character table: ASCII is there, the CP437 box
    drawing characters are there, and everything above U+00FF is not. Switch
    that console to UTF-8 and the ASCII and the frames keep rendering while
    every Cyrillic letter becomes mojibake -- which reads like an application
    bug and is not one, and which no amount of restarting will clear, because
    the font is a property of the console window rather than of any process.

    The current size is kept so the window does not jump: only the face changes.
    """
    handle = _console_output_handle()
    if handle is None:
        return ""
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentConsoleFontEx.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_ConsoleFontInfoEx)]
        kernel32.GetCurrentConsoleFontEx.restype = ctypes.c_int
        kernel32.SetCurrentConsoleFontEx.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(_ConsoleFontInfoEx)]
        kernel32.SetCurrentConsoleFontEx.restype = ctypes.c_int

        current = _ConsoleFontInfoEx()
        current.cbSize = ctypes.sizeof(current)
        if not kernel32.GetCurrentConsoleFontEx(handle, ctypes.byref(current)):
            return ""
        if current.FaceName:
            return ""  # already a Unicode font; nothing to fix
        for face in UTF8_FONTS:
            wanted = _ConsoleFontInfoEx()
            wanted.cbSize = ctypes.sizeof(wanted)
            wanted.dwFontIndex = 0
            wanted.dwFlags = current.dwFlags
            wanted.FaceName = face
            wanted.FontSize.X = current.FontSize.X
            wanted.FontSize.Y = current.FontSize.Y or 16
            if kernel32.SetCurrentConsoleFontEx(handle, 0, ctypes.byref(wanted)):
                return f"шрифт консоли заменён на {face} (был растровый)"
        return ""
    except Exception:  # noqa: BLE001 - a font is never worth failing a startup
        return ""
    finally:
        kernel32.GetCurrentConsoleFontEx.argtypes = None
        kernel32.SetCurrentConsoleFontEx.argtypes = None


def codepage_note() -> str:
    """Short description of the current console code page, for error messages."""
    if os.name != "nt":
        return "не Windows"
    try:
        cp = int(ctypes.windll.kernel32.GetConsoleOutputCP())
    except Exception:  # noqa: BLE001
        return "неизвестно"
    if cp == 0:
        return "вывод перенаправлен (консоли нет)"
    if cp == UTF8_CODEPAGE:
        return "UTF-8 (65001)"
    return f"{cp} — вывод будет кракозябрами"


def ensure_utf8_console() -> str:
    """Re-assert UTF-8 and say when it had to be put back.

    Setting the code page once at startup is not enough when something else
    shares the console. A monitor-mode helper or any other tool that attaches to
    the same window can set the output code page back to the OEM one at any
    moment, and from then on this program's writes are decoded by the wrong
    table. The damage is partial and looks like a text bug rather than a
    terminal one: whatever was drawn before the reset stays correct, and only
    the cells rewritten afterwards -- the spinner line, the status, the action
    list -- come out as ``РѕРёСЂСµСЂР>РµРѕ``. Those are exactly the parts a run
    screen updates continuously, which is why the header and the log stayed
    readable while everything around them turned to noise.

    Cheap enough to call per frame: a couple of GetConsoleOutputCP calls, and
    nothing more unless the page really moved.
    """
    if os.name != "nt":
        return ""
    try:
        kernel32 = ctypes.windll.kernel32
        current = int(kernel32.GetConsoleOutputCP())
    except Exception:  # noqa: BLE001 - never let this break a frame
        return ""
    if current in (0, UTF8_CODEPAGE):
        return ""
    try:
        kernel32.SetConsoleOutputCP(UTF8_CODEPAGE)
    except Exception:  # noqa: BLE001
        return ""
    # Python encodes its own writes as UTF-8 already; the page is what the
    # console decodes them with.
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    return f"кодовая страница вывода восстановлена {current} -> {UTF8_CODEPAGE}"