"""hashcat wrapper: runs ``hashcat -m 22000`` and reports progress live."""
from __future__ import annotations

import asyncio
import contextlib
import json
import math
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List
from uuid import uuid4

from . import app_dir
from .options import validate_mask
from .processes import terminate as _terminate

HASHCAT_MODE = 22000


class HashcatError(RuntimeError):
    """Raised when hashcat is missing, unusable, or did not finish cleanly."""


@dataclass
class HashStatus:
    """Progress snapshot parsed from hashcat's ``--status`` output."""

    speed: str = ""
    depth: int = 0
    combinator: float = 0.0
    progress: float = 0.0
    rejected: float = 0.0
    candidates: str = ""
    eta: str = ""
    running: bool = False
    exhausted: bool = False
    #: hashcat reported a recovered hash. Distinct from ``exhausted``: 6 and 5 in
    #: its device status codes, and conflating them reported a successful crack as
    #: an exhausted keyspace.
    cracked: bool = False

    @property
    def percent(self) -> float:
        return max(0.0, min(100.0, self.progress))


@dataclass
class CrackOutcome:
    password: str = ""
    cracked: bool = False
    exhausted: bool = False
    cancelled: bool = False
    timed_out: bool = False
    returncode: int = -1
    elapsed: float = 0.0
    status: HashStatus = field(default_factory=HashStatus)
    log: List[str] = field(default_factory=list)
    #: Backend devices hashcat announced at startup ("* Device #1: ..."), so
    #: the caller can show *what actually ran this* instead of assuming the
    #: GPU was picked up -- a silent fall-through to CPU-only is otherwise
    #: indistinguishable from a GPU run until the speed figure gives it away.
    devices: List[str] = field(default_factory=list)
    #: The hashcat ``--session`` name this run used. Needed back by the
    #: caller only when it asked to resume: see ``crack(resumable=...)``.
    session: str = ""
    #: True once this outcome left a ``<session>.restore`` file behind on
    #: purpose, for a later call to pick back up with ``resumable=True``.
    resumable: bool = False


def find_hashcat() -> Path | None:
    """Locate hashcat.exe.

    Checked in order: assets/hashcat.exe, assets/hashcat-<version>/hashcat.exe
    (how the official archive unpacks), then PATH.
    """
    here = app_dir()
    assets = here / "assets"
    for candidate in (assets / "hashcat.exe", assets / "hashcat"):
        if candidate.exists():
            return candidate
    # The official 7-Zip unpacks into assets/hashcat-<version>/.
    for candidate in sorted(assets.glob("hashcat-*/hashcat.exe"), reverse=True):
        if candidate.exists():
            return candidate
    found = shutil.which("hashcat") or shutil.which("hashcat.exe")
    return Path(found) if found else None


# ``STATUS<TAB>1<SPEED>`` is the header line; real payloads start at key 2.
_STATUS_RE = re.compile(r"^STATUS\t(\d+)\t([A-Z_]+)\t?(.*)$")
_PCT_RE = re.compile(r"([0-9]+\.?[0-9]*)%")
#: hashcat's startup banner: "* Device #1: NVIDIA GeForce RTX 3060, ...".
_DEVICE_RE = re.compile(r"^\*\s*Device\s*#\d+:\s*(.+)$")

#: Device status codes from hashcat's own ``docs/device_status_code.txt``. The
#: important part is that *cracked* and *exhausted* are two different numbers:
#: treating 6 as exhausted declared a successful crack exhausted, and the real
#: exhaustion (5) was never recognised at all.
DEVICE_INITIALIZING = 0
DEVICE_RUNNING = 3
DEVICE_PAUSED = 4
DEVICE_EXHAUSTED = 5
DEVICE_CRACKED = 6
DEVICE_ABORTED = 7
DEVICE_QUIT = 8

#: Exit codes from ``docs/exit_status_code.txt``.
EXIT_OK = 0
EXIT_EXHAUSTED = 1
EXIT_ABORTED = 2
EXIT_ABORTED_CHECKPOINT = 3
EXIT_ABORTED_RUNTIME = 4
EXIT_ABORTED_FINISH = 5


def parse_status(line: str, st: HashStatus) -> bool:
    """Update ``st`` from one line of hashcat output. True if it was STATUS."""
    if line.lstrip().startswith("{"):
        try:
            data = json.loads(line)
            current, total = data["progress"]
            number = int(data["status"])
            current, total = int(current), int(total)
            speed = sum(float(device.get("speed", 0)) for device in data.get("devices", []))
            if current < 0 or total < 0 or not math.isfinite(speed):
                return False
            st.progress = 100.0 * current / total if total else 0.0
            st.depth = current
            st.candidates = f"{total:,}".replace(",", " ")
            st.speed = f"{speed / 1000:.1f} kH/s" if speed >= 1000 else f"{speed:.0f} H/s"
            st.rejected = 100.0 * int(data.get("rejected", 0)) / current if current else 0.0
            st.running = number == DEVICE_RUNNING
            # Cracked and exhausted are different states, not a progression: a
            # recovered hash is never an exhausted keyspace. hashcat can report
            # Cracked and then a final Exhausted line as the rest of the hashes
            # run out, so a crack has to win permanently.
            if number == DEVICE_CRACKED:
                st.cracked = True
                st.exhausted = False
            elif number == DEVICE_EXHAUSTED and not st.cracked:
                st.exhausted = True
            eta = max(0, int(data.get("estimated_stop", time.time()) - time.time()))
            st.eta = f"{eta // 60}м {eta % 60}с" if eta else ""
            return True
        except (ValueError, TypeError, KeyError, AttributeError):
            return False
    m = _STATUS_RE.match(line)
    if not m:
        return False
    key, value = m.group(2), m.group(3).strip()
    if key == "SPEED":
        st.speed = value
        st.running = True
    elif key == "DEPTH":
        st.depth = int(value) if value.isdigit() else st.depth
    elif key == "COMBINATOR":
        st.combinator = _pct(value)
    elif key == "PROGRESS":
        st.progress = _pct(value)
        st.running = True
    elif key == "REJECTED":
        st.rejected = _pct(value)
    elif key == "CANDIDATES":
        st.candidates = value
    elif key == "ETA":
        st.eta = value
    elif key == "EXHAUSTED" or key == "ABORTED":
        st.exhausted = True
    elif key == "RUNNING":
        st.running = True
    return True


def _pct(value: str) -> float:
    m = _PCT_RE.search(value)
    return float(m.group(1)) if m else 0.0


def show_cracked(
    hashcat: Path, hashfile: Path, potfile: Path | None = None
) -> dict[str, str]:
    """Read recovered plaintext through an unambiguous hex output field.

    The potfile matches the one written by this run. Mode 22000's identifier
    contains colons, so only the final, hex-encoded field is decoded.
    """
    # Hex plaintext is unambiguous even when a password contains ':' or spaces.
    cmd = [str(hashcat), "-m", str(HASHCAT_MODE), str(hashfile), "--show", "--outfile-format=1,3"]
    if potfile:
        cmd.insert(1, f"--potfile-path={potfile}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            # hashcat resolves ./OpenCL and friends relative to its own folder,
            # so it must be invoked from there or --show fails to start.
            cwd=str(hashcat.parent),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {}
    out: dict[str, str] = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        # mode 22000 prints: <MIC>:<MAC_AP>:<MAC_CLIENT>:<ESSID>:<password>
        identifier, _, password = line.rpartition(":")
        identifier = identifier.strip()
        try:
            password = bytes.fromhex(password.strip()).decode("utf-8", "replace")
        except ValueError:
            continue
        if not identifier or not password:
            continue
        if identifier.lower().startswith(("hash", "session", "status")):
            continue
        out[identifier] = password
    return out


#: WPA passphrases are 8-63 bytes, but ``-O`` restricts hashcat's optimized
#: kernels to candidates of at most 32 -- a real limit, not a rounding
#: artefact. The trade is accepted because it covers effectively every
#: wordlist and mask this tool ships or generates (rockyou, probable-wpa,
#: masks built from digits/years) and buys roughly 2-3x the speed on mode
#: 22000; a candidate longer than 32 is silently skipped rather than tried,
#: which only matters for a custom wordlist deliberately stocked with long
#: passphrases.
OPTIMIZED_KERNELS = True


def _build_command(
    hashcat: Path,
    hashfile: Path,
    wordlist: Path | None,
    rules: Path | None,
    potfile: Path | None,
    *,
    mask: str | None = None,
    timeout: float | None = None,
    session: str | None = None,
    resume: bool = False,
    resumable: bool = False,
    optimized: bool = OPTIMIZED_KERNELS,
) -> list[str]:
    session = session or f"wifi_tool_{uuid4().hex}"
    if resume:
        # A restored run replays the *exact* arguments it was started with,
        # status flags included -- handing it the hashfile, wordlist, -O or
        # --status again is refused as a conflicting option, not merely
        # redundant.
        return [str(hashcat), f"--session={session}", "--restore"]
    cmd = [
        str(hashcat),
        "-m",
        str(HASHCAT_MODE),
        "--status",
        "--status-json",
        "--status-timer=1",
        f"--session={session}",
        "-a", "3" if mask is not None else "0",
    ]
    if not resumable:
        # Default: no checkpoint is kept, so a run that stops leaves nothing
        # to clean up. A caller that asks to be able to resume (a long
        # wordlist a user may pause and come back to) gets a real
        # ``<session>.restore`` file instead -- see ``crack(resumable=...)``.
        cmd.append("--restore-disable")
    if optimized:
        cmd.append("-O")
    if timeout is not None:
        cmd.append(f"--runtime={max(1, math.ceil(timeout))}")
    if potfile:
        # hashcat 7.x: -p is --separator; the potfile path is long-form only.
        cmd.append(f"--potfile-path={potfile}")
    cmd.append(str(hashfile))
    if mask is None and rules:
        cmd += ["-r", str(rules)]
    cmd.append(mask if mask is not None else str(wordlist))
    return cmd


async def crack(
    hashfile: str | Path,
    wordlist: str | Path | None = None,
    rules: str | Path | None = None,
    *,
    hashcat: Path | None = None,
    on_status: Callable[[HashStatus], None] | None = None,
    on_log: Callable[[str], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    timeout: float | None = None,
    mask: str | None = None,
    potfile: str | Path | None = None,
    session: str | None = None,
    resumable: bool = False,
) -> CrackOutcome:
    """Run hashcat against ``hashfile``; stream status and return the outcome.

    Async so that progress updates land on the event loop that owns the UI
    signals -- no cross-thread writes, no blocked frames.

    ``resumable`` trades a bit of disk (one ``<session>.restore`` checkpoint,
    rewritten periodically by hashcat itself) for the ability to continue a
    run that was deliberately stopped or ran out of its time budget without
    recovering a password: pass the same ``session`` back in on the next call
    and, if a checkpoint for it is still on disk, hashcat picks up from there
    instead of starting the wordlist over. A run that finishes on its own --
    cracked or exhausted -- always clears its checkpoint, resumable or not,
    because there is nothing left to continue. Without ``resumable`` this
    behaves exactly as before: no checkpoint is ever written.
    """
    hashfile = Path(hashfile)
    wordlist = Path(wordlist) if wordlist is not None else None
    rules = Path(rules) if rules else None

    # hashcat runs with cwd set to its own directory, so any relative path handed
    # to it would not resolve. Make them absolute first.
    hashfile = hashfile.resolve()
    if wordlist is not None:
        wordlist = wordlist.resolve()
    if rules:
        rules = rules.resolve()

    exe = Path(hashcat) if hashcat else find_hashcat()
    if exe is None or not exe.exists():
        raise HashcatError(
            "hashcat не найден. Положи hashcat.exe в папку assets/ "
            "или добавь её в PATH."
        )
    exe = exe.resolve()

    session = session or f"wifi_tool_{uuid4().hex}"
    # hashcat's own default location for both files: next to the executable,
    # since that is also where ``cwd`` is set below.
    session_log = exe.parent / f"{session}.log"
    session_restore = exe.parent / f"{session}.restore"
    resuming = resumable and session_restore.is_file()

    if not resuming:
        # These only matter for a fresh invocation: a restore replays the
        # hashfile, wordlist and mask it was first started with, and hashcat
        # refuses to be handed any of them again.
        if not hashfile.is_file():
            raise HashcatError(f"файл хэшей не найден: {hashfile}")
        if mask is not None:
            try:
                validate_mask(mask)
            except ValueError as exc:
                raise HashcatError(str(exc)) from exc
            if rules is not None:
                raise HashcatError("Правила словаря не применяются к маске")
        elif wordlist is None or not wordlist.is_file():
            raise HashcatError(f"словарь не найден: {wordlist}")
        if rules is not None and not rules.is_file():
            raise HashcatError(f"файл правил не найден: {rules}")
    if timeout is not None and (timeout <= 0 or not math.isfinite(timeout)):
        raise HashcatError("лимит времени должен быть положительным числом")

    potfile = Path(potfile).resolve() if potfile else exe.parent / "wifi_tool.potfile"
    cmd = _build_command(exe, hashfile, wordlist, rules, potfile, mask=mask, timeout=timeout,
                         session=session, resume=resuming, resumable=resumable)
    started = time.monotonic()
    outcome = CrackOutcome(session=session)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            # hashcat draws an interactive [s]tatus/[p]ause prompt; with a pipe on
            # stdin it can block forever waiting for a key. Give it EOF instead.
            stdin=asyncio.subprocess.DEVNULL,
            cwd=str(exe.parent),
            # Keep the child's console handling and key reader away from the
            # TUI. Redirecting stdio alone still attaches it to our conhost.
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except OSError as exc:
        raise HashcatError(f"не удалось запустить hashcat: {exc}") from exc

    def log(line: str) -> None:
        outcome.log.append(line)
        if len(outcome.log) > 200:
            del outcome.log[:-200]
        if on_log:
            on_log(line)

    log("$ " + " ".join(cmd))
    assert proc.stdout is not None
    try:
        await _collect_output(proc, outcome, log, on_status, should_stop, timeout, started)
        if not (outcome.cancelled or outcome.timed_out):
            # wait_for raises TimeoutError, which is not a HashcatError and would
            # escape as a bare "TimeoutError" through the pipeline -- whose
            # handlers only know about HashcatError. A hashcat that will not exit
            # after 30s of silence is reported as a HashcatError like any other
            # unusable run.
            try:
                await asyncio.wait_for(proc.wait(), timeout=30)
            except asyncio.TimeoutError as exc:
                raise HashcatError(
                    "hashcat не завершился за 30 с после остановки чтения вывода"
                ) from exc
    finally:
        # Hard kill (see processes.terminate's own docstring for why nothing
        # gentler is safe here): hashcat gets no chance to react to this one.
        # That costs nothing towards resuming though -- it checkpoints the
        # restore file on its own timer (every 60s by default) while it runs,
        # not on the way out, so what is on disk is at most a minute stale.
        await _terminate(proc)
        # The debug log is never read back, resumable or not -- without this
        # it accumulated a file per run in the hashcat folder (127 files,
        # ~800 KB, on this machine).
        with contextlib.suppress(OSError):
            session_log.unlink(missing_ok=True)

    outcome.returncode = proc.returncode
    outcome.elapsed = time.monotonic() - started
    outcome.exhausted = outcome.exhausted or outcome.returncode == EXIT_EXHAUSTED
    outcome.cancelled = outcome.cancelled or outcome.returncode in (
        EXIT_ABORTED, EXIT_ABORTED_CHECKPOINT, EXIT_ABORTED_FINISH,
    )
    outcome.timed_out = outcome.timed_out or outcome.returncode == EXIT_ABORTED_RUNTIME
    outcome.status.running = False
    outcome.status.exhausted = outcome.exhausted

    # A cracked run must never be reported as an exhausted one, whichever signal
    # arrived first.
    if outcome.cracked:
        outcome.exhausted = False

    if outcome.returncode not in (
        EXIT_OK, EXIT_EXHAUSTED, EXIT_ABORTED, EXIT_ABORTED_CHECKPOINT,
        EXIT_ABORTED_RUNTIME, EXIT_ABORTED_FINISH,
    ) and not (outcome.cancelled or outcome.timed_out):
        detail = "\n".join(outcome.log[-12:])
        raise HashcatError(f"hashcat завершился с кодом {outcome.returncode}\n{detail}")
    found = await asyncio.to_thread(show_cracked, exe, hashfile, potfile)
    if found:
        outcome.cracked = True
        outcome.password = next(iter(found.values()))
        outcome.exhausted = False
        outcome.status.cracked = True
        outcome.status.exhausted = False

    # A run that finished on its own has nothing left to continue, whether or
    # not it was asked to be resumable; one that was cut short -- stopped or
    # out of time, password still unknown -- is exactly the case the
    # checkpoint exists for, so it is left in place for the next call.
    done_for_good = outcome.cracked or outcome.exhausted or not (
        outcome.cancelled or outcome.timed_out
    )
    if done_for_good or not resumable:
        with contextlib.suppress(OSError):
            session_restore.unlink(missing_ok=True)
    else:
        outcome.resumable = session_restore.is_file()

    if on_status:
        on_status(outcome.status)
    return outcome


async def _collect_output(proc, outcome, log, on_status, should_stop, timeout, started):
    last_push = 0.0
    assert proc.stdout is not None
    while True:
        try:
            raw = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
        except asyncio.TimeoutError:
            raw = b""
        if raw:
            # hashcat clears its prompt with carriage returns before JSON.
            # Splitting those fragments keeps the status parseable even when
            # stdout.readline() returns the prompt and the JSON together.
            for fragment in raw.decode("utf-8", "replace").splitlines():
                line = fragment.strip()
                if not line:
                    continue
                parsed = parse_status(line, outcome.status)
                if parsed and on_status:
                    on_status(outcome.status)
                    last_push = time.monotonic()
                low = line.lower()
                if "exhausted" in low:
                    outcome.exhausted = True
                if "aborted" in low:
                    outcome.cancelled = True
                device = _DEVICE_RE.match(line)
                if device:
                    # What actually ran this, not what was hoped for: a
                    # machine whose GPU driver hashcat cannot use falls back
                    # to CPU-only silently -- no error, just a device list
                    # that says "CPU" instead of a GPU name, and a speed
                    # figure a hundred times lower than expected. Recorded
                    # structurally, not just left in the scrolling log, so a
                    # caller can show it as a one-line fact up front.
                    outcome.devices.append(device.group(1).strip())
                # Status has its own UI fields; raw JSON and keyboard prompts
                # otherwise fill the bounded journal and hide useful errors.
                if not parsed and not line.startswith("[s]tatus"):
                    log(line)
        elif proc.returncode is not None:
            # Reap explicitly. Spinning on already-resolved reads would starve
            # the child watcher and livelock the event loop.
            break
        elif not raw and proc.stdout.at_eof():
            # Stream closed but the process is still winding down.
            await asyncio.sleep(0.05)

        now = time.monotonic()
        if on_status and now - last_push > 0.5:
            on_status(outcome.status)
            last_push = now
        if should_stop is not None and should_stop():
            outcome.cancelled = True
            log("[остановлено]")
            break
        if timeout is not None and now - started > timeout:
            outcome.timed_out = True
            log("[достигнут лимит времени]")
            break
