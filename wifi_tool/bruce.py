"""Talking to an ESP32 board running Bruce, over USB serial.

Why this exists
---------------
The PC's own adapter cannot capture a handshake: its driver reports managed mode
only and no amount of privilege changes that. An ESP32 board can, because its
radio does promiscuous capture natively. So the board becomes the ears and this
program stays the hands: it reads a capture off the board and does the
conversion and the cracking.

Protocol
--------
The local custom firmware adds ``capturehandshake``, ``brkcap`` and exact-size
``storage stream`` transfers to Bruce's serial shell. Upstream releases and
other custom builds may expose different commands. A rejected command is
reported immediately, and a saved capture is fetched only after the console
returns its ready prompt. Filesystem commands here only read the board.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import hc22000

try:
    import serial
    from serial.tools import list_ports
except ImportError as exc:  # pragma: no cover - pyserial is a dependency
    serial = None
    list_ports = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

#: The prompt Bruce prints when it is idle and ready for a line. Every command
#: answer ends with it, which is what makes a blocking read possible without
#: guessing at a timeout.
READY = "# "
_READY_PROMPT = re.compile(rb"(?:^|[\r\n])#[ \t]+[\r\n]*\Z")

#: Where Bruce stores handshake captures it made from its own menu.
HANDSHAKE_DIR = "/BrucePCAP/handshakes"

#: USB ids of the boards known to run Bruce. An M5StickC Plus 2 enumerates as a
#: WCH CH9102 bridge; plain ESP32 DevKit boards usually show up as CP2102 or
#: CH340. Matching on the id avoids picking up Bluetooth and debug ports, which
#: also claim to be serial.
KNOWN_USB_IDS = {
    (0x1A86, 0x55D4): "CH9102 (M5StickC Plus 2)",
    (0x1A86, 0x7523): "CH340",
    (0x1A86, 0x5523): "CH341",
    (0x10C4, 0xEA60): "CP2102",
    (0x303A, 0x1001): "Espressif USB JTAG",
}

#: Substrings that identify a board even when the USB id is unfamiliar.
_NAME_HINTS = ("ch9102", "ch340", "ch341", "cp210", "usb serial", "usb jtag",
               "espressif", "m5stick", "m5stack")

#: Extensions Bruce writes a capture under.
CAPTURE_SUFFIXES = (".pcap", ".cap", ".pcapng", ".22000")

#: Written straight to the port to cut a capture short. The capture loop watches
#: the line itself, because the command parser is busy for as long as it runs.
STOP_TOKEN = b"\r\nbrkcap\r\n"

#: How long to wait for the ready prompt before giving up on a command. Long
#: enough for ``ls`` on flash, short enough that a wedged board does not hang the
#: run screen -- the caller is on an asyncio loop and a blocking wait here would
#: freeze the animation.
DEFAULT_TIMEOUT = 6.0

#: Serial throughput at the board's 115200 baud, used to size a file transfer's
#: budget. Without it every download got the same six seconds, so a capture
#: larger than that was cut off mid-file and arrived looking like a capture with
#: no handshake in it.
_BAUD_BYTES_PER_SECOND = 115200 / 10.0


def _what_came_back(data: bytes) -> str:
    """Describe whatever the board returned instead of a file.

    Printed verbatim in the error: a board that says ``ERR: File is too big``
    is reporting a real limit of the firmware, and the number it gave is the
    only thing that tells whether raising it or shortening the capture is the
    fix.
    """
    text = data[:120].decode("utf-8", "replace").strip()
    return text if text.isprintable() else f"{len(data)} байт, начало {data[:8].hex()}"


def _only_new(spoken: str, chunk: bytes) -> str:
    """The part of ``chunk`` not already in ``spoken``, appended to it."""
    text = chunk.decode("utf-8", "replace")
    if text.startswith(spoken):
        return text[len(spoken):]
    # A boundary landed inside a character, or the board restarted its line.
    return text


#: CSI sequences the console draws with. Dropped whole: stripping only the
#: escape byte leaves the parameters ("[2K") visible as text, which reads as
#: corruption of the board's own output rather than as terminal noise.
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _loggable(text: str) -> list[str]:
    """The board's output, split into lines fit for a one-line log.

    Control bytes and runs of spaces are stripped because the console draws with
    cursor-movement sequences, and a line that carries them into the log renders
    as garbage over everything around it.
    """
    out: list[str] = []
    for raw in _ANSI_CSI.sub("", text).replace("\r", "\n").split("\n"):
        clean = "".join(ch for ch in raw if ch == " " or ch.isprintable())
        clean = " ".join(clean.split())
        if clean:
            out.append(clean[:160])
    return out


def _short(text: str, limit: int = 120) -> str:
    flat = " ".join(_loggable(text))
    return flat[:limit] + ("..." if len(flat) > limit else "") if flat else ""


class BoardError(RuntimeError):
    """The board was found but did not behave like a Bruce console."""


class BoardCommandError(BoardError):
    """A command was rejected or returned without producing a capture."""


@dataclass
class BoardInfo:
    """A serial port that might be a Bruce board, before it has been spoken to."""
    port: str
    description: str = ""
    vid: int | None = None
    pid: int | None = None
    known: bool = False
    label: str = ""

    def __str__(self) -> str:
        who = self.label or self.description or "?"
        return f"{self.port} ({who})"


@dataclass
class RemoteFile:
    name: str
    path: str
    size: int = 0
    is_dir: bool = False

    @property
    def bssid(self) -> str:
        """The network this capture belongs to, taken from its name.

        The firmware names handshakes ``HS_<bssid>_<essid>.pcap``, so the name
        says which access point a capture is for. That is what makes a capture
        from an earlier run usable: a stale file for the network being worked on
        *is* a handshake for it, and refusing it throws away a real handshake
        because of when it was caught.
        """
        match = re.match(r"(?:HS|hs)[-_]([0-9a-fA-F]{12})", self.name)
        return match.group(1).lower() if match else ""


def bssid_of(name: str) -> str:
    """The network a capture filename refers to, or "" if it does not say."""
    return RemoteFile(name, name).bssid


def available() -> bool:
    """Whether this program can talk to a board at all."""
    return serial is not None and list_ports is not None


#: Set to a false-y value to make the whole module report "no board".
#:
#: This exists because the board is real hardware on the developer's desk, and a
#: headless test run otherwise opened COM5 and waited for a prompt that only
#: arrives when a person happens to have the stick plugged in. Tests hung on a
#: serial port, which is the worst possible way for a unit test to fail.
#: ``WIFI_TOOL_NO_BOARD`` turns the whole subsystem off for a test session.
DISABLED = False


def _is_disabled() -> bool:
    global DISABLED
    import os

    if DISABLED:
        return True
    if os.environ.get("WIFI_TOOL_NO_BOARD"):
        DISABLED = True
        return True
    return False


def find_boards() -> list[BoardInfo]:
    """Every serial port that could be a Bruce board, most likely first.

    Sorted by confidence rather than by port name, because a machine usually has
    a motherboard COM1 that is definitely not a board, and the board that is
    definitely one.
    """
    if not available() or _is_disabled():
        return []
    found: list[BoardInfo] = []
    for port in list_ports.comports():
        desc = (port.description or "").lower()
        known = port.vid is not None and (port.vid, port.pid) in KNOWN_USB_IDS
        hinted = any(h in desc for h in _NAME_HINTS)
        if not (known or hinted):
            continue
        found.append(BoardInfo(
            port=port.device,
            description=port.description or "",
            vid=port.vid,
            pid=port.pid,
            known=known,
            label=KNOWN_USB_IDS.get((port.vid, port.pid), ""),
        ))
    found.sort(key=lambda b: (not b.known, b.port))
    return found


def _looks_like_bruce(text: str) -> bool:
    lowered = text.lower()
    return "command:" in lowered or "bruce" in lowered


class Board:
    """One board, on one port, for the length of a capture run."""

    def __init__(self, info: BoardInfo, *, baud: int = 115200) -> None:
        self.info = info
        self.baud = baud
        self._serial = None
        self.firmware: str = ""

    # -- lifecycle -------------------------------------------------------

    def open(self, *, timeout: float = DEFAULT_TIMEOUT) -> "Board":
        """Open the port and confirm a Bruce console is on the other end."""
        if serial is None:
            raise BoardError(f"не установлен pyserial: {_IMPORT_ERROR}")
        if _is_disabled():
            raise BoardError("работа с платой отключена (WIFI_TOOL_NO_BOARD)")
        try:
            self._serial = serial.Serial(self.info.port, self.baud, timeout=0.25)
        except Exception as exc:
            raise BoardError(f"не открыть порт {self.info.port}: {exc}") from exc
        # Bruce echoes input and can still be holding queued keystrokes from
        # before we arrived, so the port is drained and nudged before anything
        # is sent.
        self._drain()
        time.sleep(0.15)
        banner = self._wake()
        if not _looks_like_bruce(banner):
            self.close()
            # Said this way on purpose: a board that answers but does not greet
            # is almost always one still running a capture, and "not found"
            # sends the user off to check a cable that is plugged in fine.
            raise BoardError(
                f"{self.info.port} отвечает, но не печатает консоль Bruce "
                f"(получено: {banner.strip()[:60]!r}) — возможно, плата занята")
        self.firmware = self._firmware_from(banner)
        return self

    def close(self) -> None:
        if self._serial is not None:
            try:
                self._serial.close()
            except Exception:
                pass
            self._serial = None

    def __enter__(self) -> "Board":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    @staticmethod
    def _firmware_from(text: str) -> str:
        for line in text.splitlines():
            if "bruce" in line.lower():
                return line.strip()
        return ""

    # -- talking ---------------------------------------------------------

    def _drain(self) -> None:
        if self._serial is None:
            return
        try:
            self._serial.reset_input_buffer()
        except Exception:
            pass

    def send(self, command: str, *, timeout: float = DEFAULT_TIMEOUT) -> str:
        """Run one command, return everything up to the ready prompt.

        An empty ``command`` is how the board is woken: a bare newline makes it
        print its prompt without doing anything, which is also how a ping is
        implemented.
        """
        if self._serial is None:
            raise BoardError("порт не открыт")
        self._drain()
        payload = (command + "\n").encode("utf-8", "replace")
        self._serial.write(payload)
        self._serial.flush()

        chunks: list[bytes] = []
        deadline = time.monotonic() + timeout
        idle_since = None
        while time.monotonic() < deadline:
            try:
                chunk = self._serial.read(4096)
            except Exception as exc:
                raise BoardError(f"чтение {self.info.port} прервано: {exc}") from exc
            if chunk:
                chunks.append(chunk)
                text = b"".join(chunks)
                if _READY_PROMPT.search(text):
                    break
                idle_since = None
                continue
            # No data. Give the board a moment: ``storage read`` of a real
            # capture dribbles out slowly, so silence is not yet an answer.
            if idle_since is None:
                idle_since = time.monotonic()
            elif time.monotonic() - idle_since > 1.2:
                break
            time.sleep(0.06)
        return b"".join(chunks).decode("utf-8", "replace")

    def wait_ready(self, *, timeout: float = 3.0, initial: str = "") -> bool:
        """Wait for the command's prompt without discarding pending output.

        A saved file and an idle console are separate events. Storage commands
        must wait for the latter instead of being sent into the capture loop.
        """
        if self._serial is None:
            raise BoardError("порт не открыт")
        buf = initial.encode("utf-8", "replace")
        deadline = time.monotonic() + timeout
        while not _READY_PROMPT.search(buf):
            if time.monotonic() >= deadline:
                return False
            try:
                chunk = self._serial.read(4096)
            except Exception as exc:
                raise BoardError(f"Не дождаться консоли платы: {exc}") from exc
            if chunk:
                buf = (buf + chunk)[-8192:]
            else:
                time.sleep(0.005)
        return True

    # -- storage ---------------------------------------------------------

    def list_dir(self, path: str = "/") -> list[RemoteFile]:
        """One directory listing. Bruce prints ``name<TAB>size`` or ``<DIR>``."""
        out = self.send(f"ls {path}".strip())
        entries: list[RemoteFile] = []
        for raw in out.splitlines():
            line = raw.strip()
            if not line or line.startswith("COMMAND:") or line.startswith("#"):
                continue
            if line.endswith("<DIR>"):
                entries.append(RemoteFile(line[:-5].strip(), _join(path, line[:-5].strip()),
                                          is_dir=True))
                continue
            name, _, size = line.partition("\t")
            name = name.strip()
            if not name:
                continue
            try:
                size_i = int(size.strip())
            except ValueError:
                size_i = 0
            entries.append(RemoteFile(name, _join(path, name), size_i))
        return entries

    def read_file(self, path: str, *, timeout: float = DEFAULT_TIMEOUT,
                  size: int = 0) -> bytes:
        """Read one file off the board, byte for byte.

        A capture is binary, and it used to be pulled through text: ``send``
        decodes with ``errors="replace"`` so the console stays readable, which
        turns every non-UTF-8 byte into U+FFFD. The file arrived larger than it
        was on the board and no longer started with a pcap signature, so the
        parser found no handshake in a capture the board had caught perfectly.

        So this reads the port itself and never decodes. The end of the transfer
        is decided by the byte count the directory listing already gave us: the
        prompt marker cannot be used, because binary data contains it too and
        waiting for it truncated real captures to a few dozen bytes.

        The bytes are checked before they are handed back. A board that cannot
        read the file answers with its own error text, and that answer used to
        be trimmed, written out under the capture's name and handed to the
        converter as if it were packets -- a handshake the board had caught,
        reported as a network where nobody reconnected.
        """
        if self._serial is None:
            raise BoardError("порт не открыт")
        command = f"storage stream {path}".encode()
        # A fixed budget is what truncated a capture that happened to be larger
        # than it: at 115200 baud a few kilobytes take seconds, and the wait
        # stopped counting on the clock rather than on the data.
        budget = max(timeout, size / _BAUD_BYTES_PER_SECOND * 3.0 + 2.0) if size else timeout
        deadline = time.monotonic() + budget
        buf = bytearray()
        header = None
        payload_size = 0
        self._serial.reset_input_buffer()
        self._serial.write(command + b"\r\n")
        self._serial.flush()
        while time.monotonic() < deadline:
            chunk = self._serial.read(4096)
            if not chunk:
                # Sleeping rather than spinning: a busy read loop starves the
                # reader the port itself is served from, which is exactly how a
                # transfer that should take half a second takes all of them.
                time.sleep(0.005)
                continue
            buf.extend(chunk)
            if header is None:
                header = re.search(rb"(?:^|\n)STREAM[ \t]+(\d+)\r?\n", buf)
                if header is not None:
                    payload_size = int(header.group(1))
                    if size and payload_size != size:
                        raise BoardError(
                            f"размер {path} изменился: в списке {size}, в потоке {payload_size} байт")
                elif b"# " in buf[-40:]:
                    break
            # Binary packets may contain END, newlines and even the prompt.
            # Only the STREAM byte count determines the end of the payload.
            if header is not None and len(buf) >= header.end() + payload_size:
                break
        if header is None:
            raise BoardError(
                f"плата не отдала файл {path} — вместо данных пришло: "
                f"{_what_came_back(bytes(buf))!r}")
        data = bytes(buf[header.end():header.end() + payload_size])
        if len(data) != payload_size:
            raise BoardError(
                f"загрузка {path} оборвалась: получено {len(data)} из {payload_size} байт")
        if not data:
            raise BoardError(f"плата не вернула содержимое {path}")
        if not hc22000.looks_like_capture(data):
            raise BoardError(
                f"плата не отдала файл {path} — вместо данных пришло: "
                f"{_what_came_back(data)!r}"
            )
        return data

    def pull_captures(self, dest: Path, *, remote_dir: str = HANDSHAKE_DIR,
                      timeout: float = DEFAULT_TIMEOUT) -> list[Path]:
        """Copy every capture from ``remote_dir`` into ``dest``; return the new files.

        Existing files with the same name are skipped and reported by omission:
        re-pulling the same capture on every poll would otherwise fill the folder
        with copies and make "which one is new?" unanswerable.
        """
        dest.mkdir(parents=True, exist_ok=True)
        pulled: list[Path] = []
        for entry in self.list_dir(remote_dir):
            if entry.is_dir:
                continue
            target = dest / entry.name
            if target.exists():
                continue
            data = self.read_file(entry.path, timeout=timeout, size=entry.size)
            if not data:
                continue
            target.write_bytes(data)
            pulled.append(target)
        return pulled

    def pull_capture(self, entry: RemoteFile, dest: Path,
                     *, timeout: float = DEFAULT_TIMEOUT) -> Path | None:
        """Copy one known capture from the board into ``dest``.

        Pulling a single named entry is what makes "wait for the handshake the
        human just started" possible: the files already sitting on the board
        were listed beforehand, so anything new that shows up is unambiguously
        this run's capture.

        ``entry.size`` is passed on. The listing is the only reliable measure of
        how long the transfer is meant to be, and dropping it is what let a
        board answering with an error message pass for a capture file.
        """
        dest.mkdir(parents=True, exist_ok=True)
        if Path(entry.name).name != entry.name or "\\" in entry.name:
            raise BoardError("плата вернула некорректное имя файла")
        target = dest / entry.name
        data = self.read_file(entry.path, timeout=timeout, size=entry.size)
        if not data:
            return None
        temporary = target.with_name(target.name + ".part")
        temporary.write_bytes(data)
        temporary.replace(target)
        return target

    def stop_capture(self, *, timeout: float = 3.0) -> bool:
        """Tell a running capture to stop, without disturbing the line.

        ``capture_handshake`` owns the board's serial line until it is done, so
        a normal command cannot get through while it runs. The loop watches the
        port itself for this token, which is the one thing that reaches it
        without needing the command line back.
        """
        try:
            self._serial.write(STOP_TOKEN)
            self._serial.flush()
        except Exception:  # noqa: BLE001 - stopping is best effort by design
            return False
        return True

    # -- handshake capture ------------------------------------------------

    def start_capture(self, bssid: str, channel: int, *, ssid: str = "",
                      timeout: float = DEFAULT_TIMEOUT,
                      on_output: Callable[[str], None] | None = None) -> str:
        """Ask the board to capture a handshake for ``bssid``, deauthing as it goes.

        ``capture_handshake`` in the firmware turns the interface promiscuous,
        then re-sends a deauth burst every 10-15 seconds until it has all four
        messages, so the target client reconnects by itself and nobody has to
        touch the phone. The burst is unconditional in that function -- the
        ``sniffer`` menu's own deauth flag stays off and is not reachable from
        serial, which is exactly why this path exists.

        ``on_output`` receives the board's own lines as they arrive. It exists
        because everything the board said used to be thrown away: the capture
        ran to completion, the file was found, and the program had shown nothing
        but its own two lines -- so a board that reported a caught handshake, or
        an error, or a wrong command, looked identical to a board doing nothing.
        """
        # The firmware parses this with sscanf("%hhx:%hhx:..."), so the
        # separators are load-bearing: sent without them the scan matches
        # nothing and the board deauths whatever garbage was left on the stack.
        parts = [p for p in bssid.replace("-", ":").split(":") if p.strip()]
        if len(parts) != 6 or not all(len(p) == 2 for p in parts):
            raise BoardError(f"Некорректный BSSID: {bssid!r}")
        mac = ":".join(p.upper().zfill(2) for p in parts)
        if channel <= 0:
            raise BoardError("У сети неизвестен канал")
        if channel > 14:
            # The board is an ESP32: 2.4 GHz only. Asking it for channel 48 does
            # not fail loudly -- the firmware prints "Error changing channel" on
            # every burst and carries on for the whole window, so the run looks
            # exactly like a network that refuses to give up a client. The
            # capture can only ever succeed on the 2.4 GHz band; for 5 GHz the
            # tool is the PC's own adapter.
            raise BoardError(
                f"Канал {channel} — это 5 ГГц, плата их не принимает "
                "(ESP32 работает только в 2.4 ГГц, каналы 1–14). "
                "Для такой сети нужен адаптер с режимом монитора на компе."
            )
        # The SSID is only used to name the saved file, and a space would end
        # the argument, so a target with one goes across as its BSSID instead.
        name = ssid.strip()
        if not name or any(ch.isspace() for ch in name):
            name = mac
        line = f"capturehandshake -mac {mac} -ssid {name} -channel {channel}"
        return self._run_until_capture_ends(line, timeout=timeout, on_output=on_output)

    # The firmware names the file it just wrote, and that name is on the wire
        # before any of the prose below. Matching on it is what lets a capture be
        # noticed the moment it lands, rather than whenever the loop next prints.
    #: Printed by the firmware once the capture loop has actually returned,
    #: immediately before the prompt comes back. Waiting for this rather than
    #: for the prompt is the whole point: while capturing, the board keeps
    #: printing its status, and read-until-prompt returned after a few seconds
    #: and left the capture running with nobody watching it.
    CAPTURE_DONE = "Done. Check /BrucePCAP/handshakes"

    #: Lines that mean the handshake is already written to flash, whether or not
    #: the firmware's capture loop has decided to stop. Waiting only for
    #: ``CAPTURE_DONE`` is what left the program sitting out its whole deadline
    #: with the file sitting on the board: the board had it, the board said so,
    #: and the read kept going because the loop was still deauthing.
    CAPTURE_SAVED_MARKERS = (
        CAPTURE_DONE,
        "Check /BrucePCAP/handshakes",
        "handshake captured",
        "handshake saved",
        "saved to",
    )

    @classmethod
    def capture_saved(cls, raw: bytes) -> bool:
        """Whether the board's output so far says the capture is on flash.

        The file's own name is matched too: the firmware prints the ``HS_...``
        name the moment it writes the file, which is earlier and more certain
        than any prose it may or may not follow with.
        """
        text = raw.decode("utf-8", "replace").lower()
        if re.search(r"hs_[0-9a-f]{12}(?:_[^\r\n/]*)?\.(?:pcapng|pcap|cap|22000)\b", text):
            return True
        return any(marker.lower() in text for marker in cls.CAPTURE_SAVED_MARKERS)

    #: How many times to knock before deciding the board is not there. One blank
    #: reply was enough to fail the whole connection, and a firmware that takes a
    #: moment to redraw its prompt returns nothing for the first newline -- which
    #: surfaced as "the board was not found" with the cable plugged in.
    WAKE_ATTEMPTS = 3

    def _wake(self) -> str:
        """Knock until the board prints its banner, or say it did not."""
        last = ""
        for attempt in range(self.WAKE_ATTEMPTS):
            last = self.send("", timeout=DEFAULT_TIMEOUT)
            if _looks_like_bruce(last):
                return last
            time.sleep(0.2)
        return last

    def _run_until_capture_ends(self, line: str, *, timeout: float,
                                on_output: Callable[[str], None] | None = None) -> str:
        """Send ``line`` and read until the board has the capture.

        Returns as soon as the board says the file is written. Staying until the
        loop gives up instead costs the user the rest of the deadline for
        nothing: the capture exists the moment it is saved, and pulling it while
        the loop is still deauthing is what makes a caught handshake feel
        ignored.

        Everything the board prints is handed to ``on_output`` as it arrives, and
        the whole transcript also goes into the error when the deadline passes.
        A board that says "command not found", or explains why it stopped, has
        answered the question -- that answer used to be thrown away, leaving the
        program to sit silent through the entire deadline.
        """
        deadline = time.monotonic() + timeout
        buf = b""
        try:
            self._serial.reset_input_buffer()
            self._serial.write(line.encode() + b"\r\n")
            self._serial.flush()
        except Exception as exc:  # noqa: BLE001 - reported as a board problem
            raise BoardError(f"Не удалось отправить команду плате: {exc}") from exc
        spoken = ""
        while time.monotonic() < deadline:
            try:
                chunk = self._serial.read(4096)
            except (TypeError, OSError) as exc:
                # The port was closed underneath this reader, which is what the
                # owner closing it on the way out looks like from in here.
                # pyserial cannot report it as anything but a byref TypeError,
                # and there is nothing left to wait for either way.
                raise BoardError(f"Порт закрыт во время захвата: {exc}") from exc
            if not chunk:
                time.sleep(0.005)
                continue
            buf += chunk
            if on_output is not None:
                fresh = _only_new(spoken, chunk)
                if fresh:
                    spoken += fresh
                    for text in _loggable(fresh):
                        on_output(text)
            if self.capture_saved(buf):
                if on_output is not None:
                    for text in _loggable(_only_new(spoken, b"")):
                        on_output(text)
                return buf.decode("utf-8", "replace")
            if _READY_PROMPT.search(buf) or b"command not found" in buf.lower():
                raise BoardCommandError(
                    "Плата завершила команду без сохранения захвата: " + _short(buf.decode("utf-8", "replace")))
        if on_output is not None:
            for text in _loggable(_only_new(spoken, b"")):
                on_output(text)
        raise BoardError(
            "Плата не закончила захват за отведённое время"
            + (f" (плата написала: {_short(spoken)})" if spoken.strip() else "")
        )

    def captures_present(self, *, remote_dir: str = HANDSHAKE_DIR) -> list[RemoteFile]:
        """Captures waiting on the board, without pulling them yet.

        Every regular file in the directory counts. This used to keep only a
        short list of known suffixes, and a file the firmware happened to name
        differently was skipped in silence -- the board said it had caught the
        handshake and the program reported there was nothing there.
        """
        entries = self.list_dir(remote_dir)
        return [e for e in entries if not e.is_dir]

    # -- sniffing --------------------------------------------------------

    def start_sniffer(self, *, timeout: float = 8.0) -> str:
        """Tell the board to start sniffing, and return what it said.

        This is the one piece of the wireless side that *is* reachable from
        serial, and it is enough. ``sniffer_setup`` in the firmware turns on
        promiscuous capture, hops all channels by itself (``CHANNEL_HOPPING``,
        214 ms apart, so no channel has to be configured anywhere), and saves
        EAPOL only (``EAPOL_ONLY``), which matters: a full raw capture would be
        megabytes at 115200 baud, while an EAPOL-only file is a few kilobytes.
        With no SD card it falls back to the board's internal flash.

        It also requires M1+M2+M3+M4 before it writes anything, so a half
        handshake never becomes a file that looks usable.

        The board prints SD-card errors on the way in and then "Sniffer
        started!" -- those errors are expected on a board with no card and are
        not a failure. What matters is the last line.
        """
        out = self.send("sniffer", timeout=timeout)
        if "sniffer started" in out.lower():
            return out
        # The mount errors are long and noisy; say the useful part instead.
        raise BoardError(
            "плата не подтвердила запуск сниффера"
            + (f": {out.strip().splitlines()[-1][:80]}" if out.strip() else ""))

    def sniffer_running(self) -> bool:
        """Whether the board looks like it is sniffing right now.

        Best-effort, and deliberately not trusted for anything important: the
        firmware has no serial command that reports sniffer state, so this only
        confirms the console still answers -- a board stuck in the sniffer loop
        would still answer, and a board that crashed would not.
        """
        try:
            return _looks_like_bruce(self.send("", timeout=3.0))
        except BoardError:
            return False


def _join(directory: str, name: str) -> str:
    if directory.endswith("/"):
        return directory + name
    return f"{directory}/{name}"


@dataclass
class BoardOpenResult:
    """Why a board was or was not opened.

    Exists because "the board was not found" and "the board was found and
    would not open" are different problems with different fixes, and collapsing
    them is how a board that is merely busy mid-capture gets reported as
    unplugged.
    """

    board: "Board | None" = None
    #: Empty when a board was opened; otherwise the reason, already specific.
    reason: str = ""
    #: One line per port that was tried, for the log.
    tried: list[str] = field(default_factory=list)


def open_first() -> BoardOpenResult:
    """Open the most likely board, saying exactly what got in the way.

    Never raises for a board that merely misbehaved: the reason is the useful
    part, and turning it into "not found" throws away the only thing the user
    can act on.
    """
    result = BoardOpenResult()
    candidates = find_boards()
    if not candidates:
        result.reason = ("плата не подключена: COM-портов с известной платой нет")
        return result
    for info in candidates:
        board = Board(info)
        try:
            result.board = board.open()
            return result
        except BoardError as exc:
            result.tried.append(f"{info.port}: {exc}")
            _ = exc  # collected; reported below
    details = "; ".join(result.tried)
    result.reason = (
        f"плата найдена на порту {candidates[0].port}, но не открылась — {details}."
        + (" Похоже, она занята: на ней уже идёт захват. Дождись конца "
           "или выключи и включи плату."
           if any("не похож" in line for line in result.tried) else "")
    )
    return result


def first_board() -> Board | None:
    """Open the most likely board, or None when there is none or it is busy."""
    return open_first().board
