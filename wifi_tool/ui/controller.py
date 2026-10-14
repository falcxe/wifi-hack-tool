"""Glue between the async pipeline and the reactive UI signals.

**Why the pipeline runs on its own event loop.** ``opentui.render()`` calls
``renderer.run()``, which is a *blocking* frame loop built on ``time.sleep`` --
not asyncio. It never returns until the app quits, so the asyncio loop that
``main.py`` entered is frozen for the entire life of the UI. Work scheduled on
it with ``create_task`` therefore never ran at all: bootstrap never detected the
adapter, the scan never started, and the screen sat on "Сканирую эфир..."
forever with no error to explain why.

So the async pipeline gets a private event loop on a daemon thread. Signals publish pipeline updates while input parsing and animation callbacks
run on the renderer thread. The Windows input adapter keeps blocking console
reads off that thread so frames continue even when no keys are pressed.
"""
from __future__ import annotations

import asyncio
import os
import re
import contextlib
import threading
import time
from pathlib import Path
from dataclasses import replace
from typing import List, Optional

from .. import hc22000, pipeline
from ..console import ensure_utf8_console, start_codepage_guard
from ..models import CrackResult, Network, RunRequest
from ..options import CrackOptions
from .theme import crack_hint
from . import navigation, state

_loop: Optional[asyncio.AbstractEventLoop] = None
_loop_thread: Optional[threading.Thread] = None
_loop_lock = threading.Lock()
_renderer = None
tasks: set = set()

#: Ceiling on how long a capture listens. The real value lives in the pipeline
#: because both entry points have to agree on it; the countdown shown during the
#: capture stage is drawn against this number.
CAPTURE_SECONDS = pipeline.CAPTURE_SECONDS
_crack_options = CrackOptions()

#: Wall-clock budget for the one-key ladder. Long enough to sweep the generated
#: candidates, both dictionaries and most of the mutation stage; Esc stops it.
AUTO_RUNTIME = pipeline.AUTO_RUNTIME


def _auto_budget(options: CrackOptions | None = None) -> float:
    """The ladder's budget in seconds: the configured limit, not a constant.

    The settings screen's «Лимит времени» used to be read only by the manual
    run, while the automatic mode ran on a hardcoded half hour no matter what --
    so setting it to two hours changed nothing. That is the one setting a user
    reaches for exactly when the ladder came up short, and it was the setting
    that did nothing. :data:`AUTO_RUNTIME` is the default the form starts from,
    not an override of the user's answer.
    """
    runtime = int((options or _crack_options).runtime or 0)
    return float(runtime or AUTO_RUNTIME)


def configure_cracking(options: CrackOptions) -> None:
    global _crack_options
    options.validate()
    _crack_options = options


def open_crack_form(network=None, *, capture: str = "", from_cli: bool = False) -> None:
    from .forms import open_form
    open_form(network if network is not None else state.selected_network(),
              options=_crack_options if from_cli else None, capture=capture)


def _apply_options(readiness: pipeline.Readiness, options: CrackOptions) -> pipeline.Readiness:
    if options.wordlist is not None:
        readiness.wordlist = options.wordlist
    if options.rules is not None:
        readiness.rules = options.rules
    if not options.use_rules or options.mask is not None:
        readiness.rules = None
    readiness.mask = options.mask
    return readiness


def _readiness(options: CrackOptions | None = None) -> pipeline.Readiness:
    """The machine description as last probed, or None if nothing is known yet.

    Deliberately does no I/O. The settings form's start button calls this from
    the render thread, and the real probe is two netsh calls plus two tshark
    calls with ten-second timeouts each -- doing it here froze the whole TUI for
    as long as the slowest probe took, with no feedback at all. The blocking
    probe is :func:`probe_readiness`, which only ever runs on the pipeline's own
    loop.
    """
    options = options or _crack_options
    ready = state.readiness.peek()
    return _apply_options(ready, options) if ready is not None else None


async def probe_readiness(options: CrackOptions | None = None) -> pipeline.Readiness:
    """Actually re-probe the machine. Blocking, so only for the pipeline loop."""
    options = options or _crack_options
    ready = await asyncio.to_thread(pipeline.check_readiness)
    ready = _apply_options(ready, options)
    state.readiness.set(ready)
    return ready


def probe_readiness_sync(options: CrackOptions | None = None) -> pipeline.Readiness:
    """Blocking probe for synchronous callers on the pipeline loop."""
    options = options or _crack_options
    ready = _apply_options(pipeline.check_readiness(), options)
    state.readiness.set(ready)
    return ready


def bind(renderer=None) -> None:
    """Called at startup with the renderer used by :func:`quit_app`."""
    global _renderer, _last_codepage_note
    if renderer is not None:
        if renderer is not _renderer:
            stop_ticking()
        _renderer = renderer
        # Last chance before the first frame, and the one that matters for a run
        # that ends immediately. ``main`` sets the code page at startup, but
        # anything sharing this console -- a monitor-mode helper, which this app
        # is run next to by definition -- can put it back afterwards, and a run
        # that finds its answer in a saved Windows profile finishes before the
        # tick callback has run even once, so the guard inside the animation
        # would never get its chance.
        note = ensure_utf8_console()
        if note and note != _last_codepage_note:
            _last_codepage_note = note
            state.push_log(f"[консоль] {note}")
        # And keep watching for the rest of the session: the moments that need
        # this are exactly the ones with no callback installed, because a run
        # that finishes immediately detaches its animation before the first frame.
        start_codepage_guard()
        # The animation is a frame callback and needs this renderer. A run that
        # started before the renderer existed -- ``--auto`` from the command line
        # boots the pipeline before the first frame -- would otherwise sit on a
        # screen that never moves, which is the same bug wearing a different hat.
        if state.phase.peek() == "crack" and state.run_stages.peek():
            start_ticking()


def _ensure_loop() -> asyncio.AbstractEventLoop:
    """The background event loop the pipeline runs on, started on first use."""
    global _loop, _loop_thread
    if _loop is not None:
        return _loop
    with _loop_lock:
        if _loop is not None:
            return _loop
        ready = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            global _loop
            _loop = loop
            ready.set()
            with contextlib.suppress(RuntimeError):
                loop.run_forever()

        _loop_thread = threading.Thread(
            target=run, name="wifi-tool-pipeline", daemon=True
        )
        _loop_thread.start()
        if not ready.wait(timeout=10):  # pragma: no cover - defensive
            raise RuntimeError("контроллер: не удалось запустить event loop пайплайна")
        return _loop


def _done(future) -> None:
    tasks.discard(future)
    if future.cancelled():
        return
    exc = future.exception()
    if exc is not None:
        # Never let a background failure disappear silently: the UI is the only
        # place the user would otherwise see it.
        state.push_log(f"[ошибка фоновой задачи] {type(exc).__name__}: {exc}")


def _spawn(coro):
    """Schedule ``coro`` on the pipeline's background event loop.

    Returns the ``concurrent.futures.Future`` that tracks it.
    """
    loop = _ensure_loop()
    try:
        future = asyncio.run_coroutine_threadsafe(coro, loop)
    except RuntimeError:
        coro.close()
        raise
    tasks.add(future)
    future.add_done_callback(_done)
    return future


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


async def start_scan() -> None:
    """Scan for networks and update the scan signals."""
    state.scanning.set(True)
    state.scan_error.set("")
    try:
        nets = await pipeline.scan_networks(state.push_log)
        state.replace_networks(nets)
        # What the saved captures know about who is on each network. Parsing
        # them belongs here rather than in the redraw: the first pass over a
        # folder of captures is real work, and the render thread is the one
        # place a user would see it as a freeze.
        await asyncio.to_thread(state.refresh_station_counts)
    except pipeline.PipelineError as exc:
        state.scan_error.set(str(exc))
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - surface anything unexpected
        state.scan_error.set(f"непредвиденная ошибка сканирования: {exc}")
    finally:
        state.scanning.set(False)


def bootstrap_task() -> asyncio.Task:
    """Kick off adapter detection + the first scan off the mount callback.

    Kept separate from the synchronous ``on_mount`` path because blocking
    subprocess calls during mount make the renderer repaint mid-layout.
    """
    return _spawn(bootstrap())


async def refresh_readiness() -> pipeline.Readiness:
    """Re-probe external tools; route to the setup screen when cracking is impossible.

    Runs the blocking probe off the render thread: this is the coroutine the
    pipeline's own loop awaits.
    """
    readiness = await probe_readiness(_crack_options)
    state.readiness.set(readiness)
    return readiness


def recheck_readiness() -> None:
    """Re-probe the tools while keeping the current screen open."""
    _spawn(_recheck())


#: Spinner steps per second. The frame callback fires at whatever rate the
#: renderer manages, so the counter is scaled by time rather than by frames --
#: otherwise a fast machine would spin three times as fast as a slow one.
SPIN_HZ = 8.0

_tick_callback = None
_tick_renderer = None


#: Last console code page this session had to restore, so the note is logged
#: once per occurrence rather than on every frame it is still wrong.
_last_codepage_note = ""


def start_ticking() -> None:
    """Animate the active run using one removable callback on its renderer."""
    global _tick_callback, _tick_renderer
    if _tick_callback is not None:
        return
    renderer = _renderer
    if renderer is None or not hasattr(renderer, "set_frame_callback"):
        return
    started = time.monotonic()
    last_tick = -1

    def on_frame(delta: float) -> None:
        nonlocal last_tick
        global _last_codepage_note
        # Removing a callback is optional on small test renderers. An obsolete
        # closure must also be inert if that renderer retains it.
        if _tick_callback is not on_frame or state.phase.peek() != "crack":
            return
        # Keep UTF-8 rather than set it once at startup. ``main`` puts the
        # console on 65001 before the first frame, but this app is run next to a
        # monitor-mode helper that attaches to the same console and can put the
        # page back to the OEM one at any moment. From then on this program's
        # writes are decoded by the wrong table.
        #
        # It looks like a text bug rather than a terminal one, which is why it
        # survives so long: a TUI rewrites only what changed, so the header and
        # the log keep the glyphs they were drawn with while everything rewritten
        # after the reset -- this line, the status, the action list -- comes out
        # as ``РѕРёСЂСµСЂР>РµРѕ``. Half a screen in the right alphabet and half in
        # the wrong one is not something a string in the source explains.
        note = ensure_utf8_console()
        if note and note != _last_codepage_note:
            _last_codepage_note = note
            state.push_log(f"[консоль] {note}")
        elapsed = max(0.0, time.monotonic() - started)
        tick = int(elapsed * SPIN_HZ)
        if tick != last_tick:
            last_tick = tick
            state.elapsed.set(elapsed)
            state.tick.set(tick)

    _tick_callback = on_frame
    _tick_renderer = renderer
    renderer.set_frame_callback(on_frame)


def stop_ticking() -> None:
    """Detach the previous run's callback before another run can start."""
    global _tick_callback, _tick_renderer
    callback, renderer = _tick_callback, _tick_renderer
    _tick_callback = None
    _tick_renderer = None
    if callback is not None and renderer is not None:
        remove = getattr(renderer, "remove_frame_callback", None)
        if remove is not None:
            remove(callback)
    state.elapsed.set(0.0)


async def _check_audit_key(net: Network) -> None:
    """Look up this network's stored key while the audit screen is drawn.

    The answer decides what the screen should offer next, and it used to stay
    unknown until the run started: a network this machine had joined showed the
    file picker as an equal alternative, so the one route that was about to
    succeed instantly looked like the fallback.
    """
    from .. import profiles as profiles_mod

    if state.audit_network.peek() is not net:
        return
    if not net.ssid or net.is_open:
        state.audit_has_key.set(False)
        return
    try:
        key = await asyncio.to_thread(profiles_mod.find_key, net.ssid)
    except profiles_mod.ProfileError:
        key = ""
    except Exception:  # noqa: BLE001
        key = ""
    if state.audit_network.peek() is net:
        state.audit_has_key.set(bool(key))


def check_audit_key(net: Network) -> None:
    """Ask whether ``net`` has a stored key, in the background."""
    _spawn(_check_audit_key(net))


def probe_board() -> None:
    """Look for a Bruce board, in the background.

    Opening the serial port and waiting for its prompt takes a moment, and the
    audit screen should never block on that, so the answer arrives as a signal.
    """
    _spawn(_probe_board())


#: One COM port, one opener, for the whole session.
#:
#: Probing and running used to race: the audit screen starts a probe when it
#: opens, and pressing the board line starts a second open at the same moment.
#: The loser reported "the board is not connected" while the screen plainly
#: showed it connected -- true about the port, false about the board, and the
#: most confusing message available.
#:
#: It has to be held for the whole session, not just the open. Releasing it as
#: soon as the handle came back left exactly the same race, one line later.
_board_lock = threading.Lock()

#: Set while a board run owns the port. A background probe must not touch the
#: port in that window: the board is busy and will not answer, and the probe
#: would then report it as missing in the middle of a working run.
_board_busy = False


def _open_board_blocking():
    """Open the board and take the port lock. Caller must :func:`_release_board`.

    The reason is kept even on success: ``None`` is the answer the caller acts
    on, and throwing away why would leave the failure screen with nothing to say.
    """
    from .. import bruce

    global _board_last_failure
    _board_lock.acquire()
    try:
        result = bruce.open_first()
        _board_last_failure = result.reason
        return result.board
    except BaseException:
        _board_lock.release()
        raise


def _release_board(board) -> None:
    """Close ``board`` and hand the port back, whatever happened before."""
    if board is not None:
        try:
            board.close()
        except Exception:  # noqa: BLE001
            pass
    try:
        _board_lock.release()
    except RuntimeError:
        pass


async def _probe_board() -> None:
    from .. import bruce

    if _board_busy:
        # Leave the last known state alone: whatever it says is still truer
        # than "not found" from a board that is simply mid-capture.
        return
    if not bruce.available():
        state.board.set(False)
        return
    try:
        board = await asyncio.to_thread(_open_board_blocking)
    except Exception:  # noqa: BLE001 - a probe must never take the screen down
        state.board.set(False)
        return
    try:
        if board is None:
            state.board.set(False)
            return
        label = f"{board.info.port} {board.info.label or board.info.description}".strip()
        state.board.set(label or True)
    finally:
        await asyncio.to_thread(_release_board, board)


def board_is_plugged() -> bool:
    """True when a board is attached, even if it is busy and cannot answer.

    Detection opens the port, and a board mid-capture keeps the serial line for
    itself, so a plain probe fails exactly while the capture action is the thing
    someone wants. Treating "did not answer" as "not present" made the action
    disappear from the screen at the only moment it was needed.
    """
    from .. import bruce

    if not bruce.available():
        return False
    try:
        ports = list(bruce.find_boards())
    except Exception:  # noqa: BLE001 - presence must never take the screen down
        return False
    return bool(ports)


def board_label() -> str:
    """A short name for the connected board, or "" when there is none."""
    value = state.board.peek()
    return value if isinstance(value, str) else ""


def pull_board_capture() -> None:
    """Alias kept for callers that only care about the file."""
    start_board_capture()


#: How long to listen before giving up. Long enough for someone to notice the
#: prompt, walk to the phone and toggle Wi-Fi; short enough that a run does not
#: sit open forever. Five minutes rather than three, because the thing being
#: waited for is a client that reassociates on its own schedule -- and because a
#: phone in deep sleep can take a couple of minutes to wake and notice it has
#: been dropped.
BOARD_LISTEN_SECONDS = 300


def _listen_seconds() -> float:
    """The wait, overridable without editing the source.

    Three minutes is a guess about how long a phone takes to notice it was
    dropped, and that guess is wrong in both directions: a device in deep sleep
    needs longer, a user who has just toggled Wi-Fi needs none of it. So the
    number is settled at run time by ``WIFI_TOOL_LISTEN_SECONDS`` when that is
    set, which is the difference between adjusting it and recompiling.
    """
    raw = os.environ.get("WIFI_TOOL_LISTEN_SECONDS", "").strip()
    if not raw:
        return float(BOARD_LISTEN_SECONDS)
    try:
        seconds = float(raw)
    except ValueError:
        return float(BOARD_LISTEN_SECONDS)
    return seconds if seconds >= 10 else float(BOARD_LISTEN_SECONDS)


def start_board_capture(network: Network | None = None) -> None:
    """Listen on the board for a handshake, then crack it here. One entry point.

    The board listens and this program guesses; that split is forced by the
    hardware, not chosen. The PC's adapter cannot do monitor mode at all, the
    ESP32's can, and the board already has Bruce's sniffer behind it -- promiscuous
    capture, automatic channel hopping, EAPOL-only saving, and a check that all
    four handshake messages arrived before it writes anything.

    What no one can automate is a client reconnecting, because a handshake *is*
    a client reconnecting. So the wait is a real phase on the running screen with
    the phone instruction on it, rather than a button that looks stuck.

    Everything happens here: start the sniffer, wait, pull, launch. Splitting
    that across the screen and a second poller meant the F1 menu entry for the
    same action pulled a file and left it there.
    """
    if state.phase.peek() == "crack":
        return
    _prepare_board_view(network)
    _spawn(_board_capture_run())


def _set_run_context(source: str, context: str) -> None:
    state.run_source.set(source)
    state.run_context.set(context)
    state.board_deadline.set(None)
    state.capture_left.set(None)
    state.capture_total.set(None)
    state.capture_bytes.set(0)
    state.capture_found.set("")
    state.capture_clients.set(None)
    state.capture_eapol.set(0)
    state.progress_known.set(False)
    state.run_speed.set("")
    state.run_eta.set("")
    state.revealed_secret.set(None)
    focus = dict(state.control_focus.peek())
    focus.pop("crack", None)
    state.control_focus.set(focus)


def _prepare_board_view(network: Network | None = None) -> None:
    """Publish the operation before a serial probe can take any time."""
    origin = state.phase.peek()
    if network is None:
        network = (state.audit_network.peek() if origin == "audit" else
                   state.form_network.peek() if origin == "crack_form" else
                   state.selected_network())
    state.cracking_network.set(network)
    _set_run_context("board", network.label if network else "Плата M5StickC")
    state.cancelled.set(False)
    state.capture_left.set(None)
    state.capture_found.set("")
    state.progress.set(0.0)
    state.stage.set("")
    state.status.set("")
    state.log.set([])
    state.log_scroll.set(0)
    state.begin_run_stages(["board"])
    state.advance_run_stage("board")
    state.current_activity.set("Подключение к плате")
    navigation.push("crack")
    start_ticking()


def _board_devices(devices: int, eapol: int) -> None:
    """What the board can hear on the network, onto the screen while it waits.

    The count is a lower bound on what is connected -- devices that have not
    said anything are not in it -- but it is the one number that distinguishes
    "the handshake is coming" from "there is nobody here to knock over", and the
    two are indistinguishable from silence.
    """
    state.capture_clients.set(devices)
    state.capture_eapol.set(eapol)
    if not devices and not eapol:
        state.status.set("Ждём, но устройств на сети не слышно")


def _board_failure(message: str) -> None:
    # Only the result headline carries this: it is the reason the run ended, and
    # writing it into the log as well just repeated it on the same screen.
    elapsed = state.elapsed.peek()
    state.cancelled.set(False)
    _show_completed_result(CrackResult(network=_network_hint(), method="захват",
                                      elapsed=elapsed, error=message),
                           RunRequest("board", _crack_options,
                                      capture_seconds=BOARD_LISTEN_SECONDS))


#: Maximum wait for a single command, not a mandatory delay. A saved-file
#: message ends the read early; the ready prompt then gates storage commands.
#: Restarting more often discards in-flight capture state and repeats Wi-Fi
#: setup. Actual reassociation depends on the client and its PMF negotiation.
BOARD_CAPTURE_ROUND = 90.0


async def _board_capture_rounds(board, target: Network, dest: Path,
                                deadline: float, stale: set[str]) -> Path | None:
    """Run the board's capture in rounds, checking for a file after each.

    Returns the capture it found, or None if the run ended without one.
    """
    from .. import bruce

    round_no = 0
    while time.monotonic() < deadline and not state.cancelled.peek():
        round_no += 1
        window = min(BOARD_CAPTURE_ROUND, deadline - time.monotonic())
        task = asyncio.ensure_future(asyncio.to_thread(
            board.start_capture, target.bssid, target.channel,
            ssid=target.ssid, timeout=window, on_output=_board_says,
            on_clients=_board_devices))
        while not task.done():
            # ``asyncio.wait`` and not a sleep-polling loop: awaiting a
            # coroutine that never awaits a future does not let the loop process
            # the thread pool's completion callback, so the task can never
            # become done and the wait spins forever. This waits on the task.
            await asyncio.wait({task}, timeout=0.5)
            if state.cancelled.peek():
                await asyncio.to_thread(board.stop_capture)
                await _drain(task)
                state.push_log("[плата] захват прерван по запросу")
                return None
        error = task.exception()
        if isinstance(error, bruce.BoardCommandError):
            raise error
        transcript = "" if error is not None else str(task.result())
        if error is not None:
            state.push_log(f"[плата] раунд {round_no}: {error}")
            # The command timed out, so the firmware's loop is very likely still
            # running and still holding the serial line. It has to be stopped
            # before the board can be asked anything at all, or the answer
            # arrives mixed into the deauth spam and every line of it parses as a
            # broken filename.
            await asyncio.to_thread(board.stop_capture)
            await _drain(task)
        else:
            state.push_log(f"[плата] раунд {round_no}: захват сохранён, ожидаю консоль")
            if bruce.Board.CAPTURE_DONE.lower() not in transcript.lower():
                await asyncio.to_thread(board.stop_capture)
        if not await asyncio.to_thread(board.wait_ready, initial=transcript, timeout=3.0):
            raise bruce.BoardError("Плата не подтвердила остановку захвата; консоль всё ещё занята")
        if state.cancelled.peek():
            return None

        try:
            fresh = [e for e in await asyncio.to_thread(board.captures_present)
                     if e.name not in stale and
                     (not bruce.bssid_of(e.name) or bruce.bssid_of(e.name) == _bssid_key(target.bssid))]
        except bruce.BoardError as exc:
            state.push_log(f"[плата] не прочитать содержимое: {exc}")
            fresh = []
        if not fresh:
            continue
        entry = fresh[-1]
        try:
            chosen = await asyncio.to_thread(board.pull_capture, entry, dest)
        except bruce.BoardError as exc:
            state.push_log(f"[плата] не прочитать захват: {exc}")
            continue
        if chosen is not None:
            state.push_log(
                f"[плата] получен {chosen.name} ({chosen.stat().st_size} байт)")
            return chosen
    return None


async def _drain(task) -> None:
    """Wait for a wrapped thread task to finish, without cancelling it."""
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=8.0)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass
    except Exception:  # noqa: BLE001 - stopping is best effort
        pass


def _bssid_key(value: str) -> str:

    """A BSSID as twelve bare hex digits, the way filenames spell it.

    Comparing a network from the scan against one read out of a filename has to
    ignore colons, case and dashes, or "08:9A:C7:E7:51:66" and "089ac7e75166"
    stop looking like the same access point.
    """
    return re.sub(r"[^0-9a-f]", "", (value or "").lower())


def _capture_names(board) -> set[str]:
    """Names of the captures already waiting on the board.

    A board that is busy or briefly unresponsive must not abort the run before
    it has even started, so a read failure here yields an empty set: the effect
    is that nothing is treated as stale, which only risks picking up an older
    file, never losing a new one.
    """
    from .. import bruce
    try:
        return {e.name for e in board.captures_present()}
    except bruce.BoardError:
        return set()


def _board_says(line: str) -> None:
    """Put one line the board printed into the run log.

    The board narrates its own capture -- when it deauths, when it sees a
    client, when it saved the file. All of that used to be read into a buffer
    and discarded, so the run screen showed two fixed lines of our own while the
    stick was visibly busy and, later, visibly done. Showing the board's own
    words as they arrive is also the only way to tell "still working" from "gave
    up and said why" without guessing.
    """
    state.push_log(f"[плата] {line}")


#: Why the last connection attempt failed, kept so the result screen can say it
#: instead of guessing. Set by :func:`_board_capture_run`, read by
#: :func:`_board_open_reason`.
_board_last_failure = ""


def _board_open_reason() -> str:
    if _board_last_failure:
        return _board_last_failure
    return "плата не подключена: COM-портов с известной платой нет"


async def _board_capture_run() -> None:
    global _board_busy, _board_last_failure
    from .. import bruce
    from ..options import ensure_captures_dir

    if state.run_source.peek() != "board":
        _prepare_board_view()
    _board_busy = True
    try:
        dest = ensure_captures_dir()
        board = await asyncio.to_thread(_open_board_blocking)
    except Exception as exc:
        _board_busy = False
        _board_failure(f"Не удалось подключить плату: {exc}")
        return
    if board is None:
        await asyncio.to_thread(_release_board, board)
        # Whatever kept the port shut, verbatim. "Плата не найдена" when the
        # port was there and merely refused to open is the one message that
        # sends the user to the wrong place to look.
        _board_failure("Плата недоступна: " + _board_open_reason())
        _board_busy = False
        return

    try:
        if state.cancelled.peek():
            _board_failure("Ожидание остановлено")
            return
        state.current_activity.set("Ожидание рукопожатия")
        state.push_log("Плата подключена")

        network = state.networks.peek()
        # The network this run was started for. Never the one this computer is
        # itself joined to: that is a different radio, and deauting it just
        # because it is "associated" is not what was asked for.
        target = state.cracking_network.peek() or state.audit_network.peek()
        if target is None and network:
            target = network[0]

        deadline = time.monotonic() + _listen_seconds()
        state.board_deadline.set(deadline)

        chosen: Path | None = None

        if target is not None and target.channel > 14:
            # The board's radio is 2.4 GHz only, so a 5 GHz channel can never
            # produce a handshake. Saying so now beats letting the countdown
            # run out with nothing to show for it.
            _board_failure(
                f"{target.ssid}: канал {target.channel} — это 5 ГГц, "
                f"а M5StickC ловит только 2,4 ГГц")
            return

        if target is not None and target.channel > 0:
            # What is already on the board, by name. Only a file that appears
            # during this run counts as *new* -- but a file the board already
            # holds for this very access point is a handshake for it, and making
            # the user sit through another deauth loop to catch a second copy of
            # something already on flash is the whole reason the board looked
            # deaf: it had the handshake, and the screen said it was waiting.
            stale = await asyncio.to_thread(_capture_names, board)
            want_bssid = _bssid_key(target.bssid)
            if want_bssid:
                try:
                    on_board = await asyncio.to_thread(board.captures_present)
                except bruce.BoardError as exc:
                    _board_failure(f"Не удалось прочитать захват с платы: {exc}")
                    return
                already = [e for e in on_board if e.bssid == want_bssid]
                if already:
                    state.push_log(
                        f"[плата] на плате уже есть хэндшейк для {target.ssid} "
                        f"({already[-1].name}), беру его")
                    state.current_activity.set("Забираю хэндшейк с платы")
                    try:
                        chosen = await asyncio.to_thread(
                            board.pull_capture, already[-1], dest)
                    except bruce.BoardError as exc:
                        _board_failure(f"Не удалось прочитать захват с платы: {exc}")
                        return
                    if chosen is not None:
                        state.push_log(
                            f"[плата] получен {chosen.name} ({chosen.stat().st_size} байт)")
                elif on_board:
                    # Russian plurals, because "1 захватов" in a message the
                    # user reads while deciding what to do next is the sort of
                    # detail that makes the rest of the sentence harder to trust.
                    word = "захват" if len(on_board) == 1 else "захвата"
                    state.push_log(
                        f"[плата] на плате {len(on_board)} {word}, "
                        "но ни одного для этой сети")

            if chosen is None:
                state.push_log(f"[плата] запускаю захват {target.ssid} (канал {target.channel})")
                state.current_activity.set("Плата деаутит и ловит рукопожатие")
                state.status.set("Ждём переподключения клиента и запись файла")

                # The board writes the file the moment the handshake is, but
                # its capture loop keeps deauthing until the firmware decides
                # otherwise, and that decision is not ours to observe. So the
                # command runs in rounds and the board is asked between them.
                try:
                    chosen = await _board_capture_rounds(board, target, dest, deadline, stale)
                except bruce.BoardError as exc:
                    _board_failure(str(exc))
                    return
                if state.cancelled.peek():
                    _board_failure("Ожидание остановлено")
                    return
                if chosen is None:
                    _board_failure(
                        f"За {BOARD_LISTEN_SECONDS:.0f} с рукопожатия не поймано "
                        f"— убедитесь, что телефон подключён к {target.ssid}")
                    return
        else:
            # No usable network on screen: the board still needs the human, and
            # saying so on the watched screen beats saying it only in the log.
            state.status.set("На плате: WiFi Atks → сеть → Capture Handshake")
            try:
                stale = await asyncio.to_thread(_capture_names, board)
            except bruce.BoardError as exc:
                _board_failure(f"Не удалось прочитать содержимое платы: {exc}")
                return

        # Only for a run that has to wait: the loop below polls the board for a capture
        # the human is starting by hand. Once the capture branch above has a file,
        # going round that loop again means sitting out the whole deadline on a
        # capture already in hand -- the file was there, and the screen kept
        # saying it was waiting.
        while chosen is None and time.monotonic() < deadline and not state.cancelled.peek():
            await asyncio.sleep(2.0)
            if state.cancelled.peek():
                break
            try:
                fresh = [e for e in await asyncio.to_thread(board.captures_present)
                         if e.name not in stale]
            except bruce.BoardError as exc:
                _board_failure(f"Не удалось прочитать захват с платы: {exc}")
                return
            if not fresh:
                continue
            # The board names each capture after its own handshake, so the last
            # one is the one that was just written.
            entry = fresh[-1]
            try:
                chosen = await asyncio.to_thread(board.pull_capture, entry, dest)
            except bruce.BoardError as exc:
                _board_failure(f"Не удалось прочитать захват с платы: {exc}")
                return
            if chosen is not None:
                state.push_log(
                    f"[плата] получен {chosen.name} ({chosen.stat().st_size} байт)")
                break

        if state.cancelled.peek():
            _board_failure("Ожидание остановлено")
            return
        if chosen is None:
            _board_failure("Рукопожатие не получено за отведённое время")
            return
        state.status.set("")
        state.status.set("")
        # The sniffer's file is a normal capture as far as the pipeline is
        # concerned, so it goes in by exactly the same door as a picked file.
        open_capture(chosen, automatic=True)
    finally:
        state.board_deadline.set(None)
        _board_busy = False
        await asyncio.to_thread(_release_board, board)


def _network_hint() -> Network:
    """A stand-in network so a "nothing caught" result has somewhere to live."""
    net = state.cracking_network.peek()
    if net is not None:
        return net
    return Network(ssid="плата", bssid="", auth="")


async def _recheck() -> None:
    # The return value is the point: ``refresh_readiness`` publishes the probe
    # into ``state.readiness``, which is what the audit screen draws its verdict
    # from. The coroutine exists only to keep the blocking probe off the render
    # thread.
    await refresh_readiness()


def refresh_readiness_here() -> None:
    """Re-check readiness from the merged settings/parameters screen.

    This does not navigate: the user is asking "has anything changed?" while
    looking at the checklist, and yanking them back
    to the network list would throw away the parameters they just filled in.
    """
    state.form_error.set("")
    recheck_readiness()


def start_when_ready(options: CrackOptions) -> None:
    """Probe the environment, then submit the settings form with the answer.

    Readiness probes are blocking subprocesses -- two netsh calls and two tshark
    calls, ten seconds each. Running them on the render thread (which is what the
    form's start button used to do) froze the whole TUI with no feedback for as
    long as the slowest probe took. Here they run on the pipeline's own loop,
    and the form continues when they finish.
    """
    _spawn(_start_when_ready(options))


async def _start_when_ready(options: CrackOptions) -> None:
    from . import forms

    readiness = await refresh_readiness()
    forms._launch(options, state.form_values.peek(), readiness)


# --- installer -------------------------------------------------------------


def download_tools(keys: Optional[List[str]] = None) -> None:
    """Download the missing tools from the setup screen."""
    if state.install_state.peek() != "idle":
        return
    _spawn(_install(keys))


async def _install(keys: Optional[List[str]]) -> None:
    from .. import installer

    state.install_state.set("working")
    state.install_progress.set("")

    def on_log(line: str) -> None:
        state.push_log(line)

    def on_progress(key: str, done: int, total: int) -> None:
        pct = int(done * 100 / total) if total else 0
        state.install_progress.set(f"{key}: {pct}%")

    try:
        results = await installer.install_all(keys, on_log=on_log, on_progress=on_progress)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        state.form_error.set(f"Не удалось установить компоненты: {exc}. Повторите установку через F1.")
        on_log(state.form_error.peek())
        return
    finally:
        state.install_progress.set("")
        state.install_state.set("idle")

    failed = {k: v for k, v in results.items() if v != "ok"}
    if failed:
        state.form_error.set("Не установлены компоненты: " + ", ".join(failed) +
                             ". F1 → Компоненты: подробности; затем повторите установку.")
    else:
        state.form_error.set("")
    readiness = await refresh_readiness()
    if failed and not readiness.hashcat and state.phase.peek() == "crack_form":
        # Without hashcat there is nothing to configure, so the merged screen is
        # also where the user has to be told: it is the only screen that shows
        # the checklist and can download.
        navigation.replace("crack_form")
    for key, message in failed.items():
        on_log(f"{key}: {message.splitlines()[0]}")
    if not failed:
        on_log("Установка завершена")


async def bootstrap() -> None:
    """Detect the adapter and permissions, then run the initial scan.

    Readiness is probed once here so the scan screen can tell the user up front
    whether the live capture path is usable at all -- on an adapter without
    monitor-mode support that button would otherwise always fail.

    Saved profiles are loaded too: they tell the user, for each scanned network,
    whether the key is already on this machine, which is the fastest possible
    answer for a network they own.
    """
    readiness = await refresh_readiness()
    state.is_admin.set(readiness.admin)
    state.adapter.set(readiness.adapter)
    refresh_saved()  # spawns its own task; do not await it here
    # Look for the board at startup, not when the audit screen happens to open.
    # On a machine whose own adapter cannot capture, whether a board is plugged
    # in decides what the run can even attempt, and that is worth knowing on the
    # scan screen rather than after selecting a network.
    probe_board()  # spawns its own task; do not await it here
    await start_scan()


def boot() -> asyncio.Task:
    """Start the app on the scan screen -- the primary flow."""
    navigation.home()
    return _spawn(bootstrap())


def boot_auto() -> asyncio.Task:
    """Start the app and run the one-key path on the first usable network.

    What ``--auto`` means on the command line: the same thing Enter does on a
    selected network, without the questions. Bootstrap still runs first, because
    the stored-key route works with no capture hardware at all and the scan is
    what names the target.
    """
    navigation.home()
    return _spawn(_boot_auto())


async def _boot_auto() -> None:
    await bootstrap()
    nets = state.networks.peek()
    target = next((net for net in nets if net.crackable), None)
    if target is None:
        state.scan_notice.set(
            "Автоматический режим: нет сетей, доступных для офлайн-подбора."
        )
        state.push_log("Автоматический режим: подходящих сетей не найдено")
        return
    state.push_log(f"Автоматический режим: беру первую подходящую сеть «{target.label}»")
    state.selected.set(next(i for i, net in enumerate(nets) if net is target))
    begin_auto_for(target)


def go_to_setup() -> None:
    """Open the parameters from the scan screen.

    The separate "НАСТРОЙКА" screen is gone -- the checklist and the parameters
    both answer "can this run, and how", so they live on one screen now. The name
    and the return destination stay tied to the screen the user came from.
    """
    open_crack_form()


def continue_to_scan() -> None:
    """Back to the network list, keeping the parameters that were filled in."""
    navigation.home()


def request_rescan() -> None:
    if not state.scanning.peek():
        _spawn(start_scan())


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------


def select_index(index: int) -> None:
    """Move the selection, clamped to the current list."""
    nets = state.networks.peek()
    if not nets:
        state.selected.set(0)
        return
    state.selected.set(max(0, min(len(nets) - 1, index)))


def current_network() -> Network | None:
    nets = state.networks.peek()
    idx = state.selected.peek()
    return nets[idx] if 0 <= idx < len(nets) else None


# ---------------------------------------------------------------------------
# attack
# ---------------------------------------------------------------------------


def _on_status(st) -> None:
    state.progress.set(st.percent)
    state.progress_known.set(state.progress_known.peek() or st.percent > 0 or
                             bool(str(st.candidates).replace(" ", "").strip("0")))
    state.run_speed.set(st.speed or "")
    state.run_eta.set(st.eta or "")
    bits = []
    if st.speed:
        bits.append(st.speed)
    if st.depth:
        bits.append(f"{st.depth:,} кандидатов".replace(",", " "))
    if st.candidates:
        bits.append(f"всего {st.candidates}")
    if st.eta:
        bits.append(f"осталось ~{st.eta}")
    state.status.set("   ·   ".join(bits))


PHASE_LABELS = {
    "board": "Ожидание рукопожатия",
    "saved": "Проверка истории подключений",
    "capture": "Захват данных сети",
    "convert": "Обработка файла захвата",
    "crack": "Проверка паролей",
}

#: The stages a run reports, in order. Which of them a given run actually uses
#: depends on the source: a capture file skips live capture, a capture-only run
#: stops before the password stage. The screen draws whatever is here, so the
#: plan is visible before it starts rather than inferred afterwards.
def begin_run(*keys: str) -> None:
    """Publish a run's plan, already under way.

    Called from the keypress, not from the coroutine -- navigation to the run
    screen is synchronous, so a plan set inside the coroutine meant the screen
    painted once with nothing on it, for as long as the first probe took.

    The first stage is marked current and written to the journal straight away
    for the same reason: the pipeline announces its first phase only once the
    task is actually scheduled, and until then the screen showed four pending
    rows and an empty log. That reads as "nothing is happening" during the one
    moment the user is watching hardest.
    """
    state.begin_run_stages(list(keys))
    if not keys:
        return
    state.advance_run_stage(keys[0])
    state.push_log(f"· {PHASE_LABELS.get(keys[0], keys[0])}")


def _pipeline_callbacks() -> pipeline.Callbacks:
    return pipeline.Callbacks(
        on_phase=_on_phase,
        on_log=state.push_log,
        on_status=_on_status,
        should_stop=lambda: state.cancelled.peek(),
        on_stage=_on_stage,
        on_capture=_on_capture,
        on_capture_result=_on_capture_result,
    )


def _on_stage(index: int, total: int, title: str) -> None:
    state.stage.set(f"Этап {index + 1}/{total}: {title}")
    state.progress.set(0.0)
    state.progress_known.set(False)
    state.run_speed.set("")
    state.run_eta.set("")
    state.status.set("")


def _on_capture_result(report) -> None:
    """Record what the capture produced, in the user's own terms.

    A 4 MB file that contains no handshake is the single most common way this
    run ends, and "0 рукопожатий" is a fact the user can act on -- reconnect a
    device and capture again -- where "не найдено" is not.
    """
    state.capture_left.set(None)
    state.capture_found.set(hc22000.summarise(report))


def _on_phase(name: str) -> None:
    """Entering or leaving the capture stage resets its own indicators.

    Only the capture signals are touched: the stage arriving is what clears the
    countdown, and the conversion report is what fills in what it found. Leaving
    capture (``convert``/``crack``) is the signal to stop drawing a countdown that
    has already elapsed.

    The stage is also written to the log. The journal used to stay at
    "ожидание…" until the pipeline happened to say something, so a run that was
    visibly on its second stage looked stalled -- the screen was busy and the
    journal was empty, which is the exact combination people read as a hang.
    """
    if name == "capture":
        state.capture_found.set("")
    elif name != "crack":
        state.capture_left.set(None)
    label = PHASE_LABELS.get(name, name)
    state.current_activity.set(label)
    # Always, including into an empty journal. Skipping it when the log happened
    # to be empty left the worst possible picture: a run visibly on its first
    # stage, and a journal reading "ожидание…" because the stage line was the
    # thing that would have filled it.
    state.push_log(f"· {label}")
    state.advance_run_stage(name)
    if name == "crack":
        state.progress.set(0.0)
    state.progress_known.set(False)
    state.run_speed.set("")
    state.run_eta.set("")
    state.status.set("")


def _on_capture(seconds_left: int, size: int) -> None:
    state.capture_left.set(seconds_left)
    state.capture_bytes.set(size)


async def run_attack(net: Network, *, request: RunRequest | None = None) -> None:
    """Run the full pipeline for ``net`` and land on the result screen."""
    request = request or RunRequest("manual", _crack_options, capture_seconds=CAPTURE_SECONDS)
    state.capture_total.set(request.capture_seconds)
    options = request.options
    begin_run("capture", "convert", "crack")
    try:
        readiness = await probe_readiness(options)
        result = await pipeline.attack(
            net,
            readiness=readiness,
            capture_seconds=request.capture_seconds,

            deauth=options.deauth,
            mask=options.mask,
            timeout=options.runtime,
            use_rules=options.use_rules,
            cb=_pipeline_callbacks(),
        )
    except asyncio.CancelledError:
        raise
    except pipeline.PipelineError as exc:
        result = CrackResult(
            network=net,
            success=False,
            error=str(exc),
            remedy=getattr(exc, "remedy", ""),
        )
    except Exception as exc:  # noqa: BLE001
        result = CrackResult(network=net, success=False, error=f"ошибка: {exc}")
    finally:
        state.cancelled.set(False)

    _show_completed_result(result, request)


async def run_auto_attack(net: Network, *, request: RunRequest | None = None) -> None:
    """The one-key path: stored key, then capture, then the whole ladder.

    Deliberately asks nothing. Whatever is available on this machine is used in
    the order most likely to succeed, and an exhausted ladder is a result, not
    an error.
    """
    request = request or RunRequest("auto", _crack_options, capture_seconds=CAPTURE_SECONDS,
                                    total_runtime=_auto_budget(_crack_options))
    state.capture_total.set(request.capture_seconds)
    begin_run(*_run_stages())
    try:
        def readiness_after_profile_check() -> pipeline.Readiness:
            return probe_readiness_sync(request.options)

        result = await pipeline.auto_attack(
            net,
            readiness_factory=readiness_after_profile_check,
            capture_seconds=request.capture_seconds,

            deauth=request.options.deauth,
            total_runtime=request.total_runtime,
            wordlist=request.options.wordlist,
            rules=request.options.rules if request.options.use_rules else None,
            # A mask typed into the settings has to reach the ladder, or Enter on
            # a network quietly ignores the format the user described.
            mask=request.options.mask,
            cb=_pipeline_callbacks(),
        )
    except asyncio.CancelledError:
        raise
    except pipeline.PipelineError as exc:
        result = CrackResult(
            network=net,
            success=False,
            error=str(exc),
            remedy=getattr(exc, "remedy", ""),
        )
    except Exception as exc:  # noqa: BLE001
        result = CrackResult(network=net, success=False, error=f"ошибка: {exc}")
    finally:
        state.cancelled.set(False)

    _show_completed_result(result, request)


def _select(net: Network) -> None:
    """Mark ``net`` as the target and reset the per-run signals."""
    nets = state.networks.peek()
    for i, candidate in enumerate(nets):
        if candidate is net:
            state.selected.set(i)
            break
    state.select_network(state.selected.peek())
    state.cracking_network.set(net)
    _set_run_context("live", net.label)


def _show_completed_result(result: CrackResult, request: RunRequest | None = None) -> None:
    """Retain the last result independently of the currently viewed history entry.

    Also settles the run checklist. It has to happen here rather than in each
    caller: an exhausted ladder, a cancelled run and a key found in the Windows
    profile all arrive at this one function, and each of them ends in a
    different stage. Leaving a stage spinning after the run is over was the last
    thing the checklist was still wrong about.
    """
    state.finish_run_stages()
    state.board_deadline.set(None)
    stop_ticking()
    if not result.log:
        result = replace(result, log=list(state.log.peek()))
    if request is not None:
        result = replace(result, request=request)
    state.last_result.set(result)
    state.result.set(result)
    state.revealed_secret.set(None)
    state.log_scroll.set(0)
    focus = dict(state.control_focus.peek())
    focus.pop("result", None)
    state.control_focus.set(focus)
    navigation.replace("result")


def start_attack(net: Network, *, request: RunRequest | None = None) -> None:
    """Select ``net`` and start the pipeline."""
    _select(net)
    request = request or RunRequest("manual", _crack_options, capture_seconds=CAPTURE_SECONDS)
    # Published on the keypress for the same reason as the automatic run above.
    begin_run("capture", "convert", "crack")
    start_ticking()
    _spawn(run_attack(net, request=request))


def start_auto_attack(net: Network, *, request: RunRequest | None = None) -> None:
    """Select ``net`` and run the automatic ladder over it."""
    _select(net)
    request = request or RunRequest("auto", _crack_options, capture_seconds=CAPTURE_SECONDS,
                                    total_runtime=_auto_budget(_crack_options))
    # The plan is published here, on the keypress, not inside the coroutine it
    # spawns. Navigation to the run screen happens synchronously above, so with
    # the plan set in the coroutine the screen painted once with no checklist and
    # an empty journal -- for as long as the first probe took, which is seconds.
    begin_run(*_run_stages())
    start_ticking()
    _spawn(run_auto_attack(net, request=request))


def begin_auto() -> None:
    """The single key on the scan screen: do everything that can be done."""
    net = state.selected_network()
    if net is None:
        # The cursor is on the list but nothing is usable there; say so where
        # the user is looking rather than only in the log.
        state.scan_notice.set("Сначала выбери сеть в списке.")
        state.push_log("Сначала просканируй и выбери сеть")
        return
    begin_auto_for(net)


def begin_auto_for(net: Network) -> None:
    """Start password recovery against ``net`` from any screen.

    The local Windows-profile lookup works without monitor mode. WPA/WPA2 can
    continue to the capture and candidate stages when the key is not stored.
    """
    can_check_profile = bool(net.ssid and not net.is_open)
    if not net.crackable and not can_check_profile:
        state.scan_notice.set(f"{net.label}: {crack_hint(net.auth)}")
        state.push_log(f"{net.label}: {crack_hint(net.auth)}")
        return
    state.scan_notice.set("")
    start_auto_attack(net)


def begin_capture_for(net: Network, *, request: RunRequest | None = None) -> None:
    """Record a handshake for ``net`` and show what came out. Nothing else.

    The capture is the step that fails for hardware reasons, so it is worth being
    able to run it on its own. That matters most in the one situation where the
    full run is unhelpful: an adapter with no monitor mode makes the whole ladder
    abort, but a user who has since attached one -- or who wants to record from
    their own router -- can capture here and check the result immediately.

    Deliberately does not refuse when capture is blocked. The blocker is the
    answer: it names the missing driver or interface, and it appears on the
    running screen rather than being swallowed.
    """
    _select(net)
    request = request or RunRequest("capture", _crack_options, capture_seconds=CAPTURE_SECONDS)
    begin_run("capture", "convert")
    start_ticking()
    _spawn(run_capture_only(net, request=request))


async def run_capture_only(net: Network, *, request: RunRequest | None = None) -> None:
    """Capture, convert, report. No dictionary, no hashcat, no guessing.

    Ends on the result screen either way, because "captured, nothing in it" is a
    result too -- and the one that explains itself with a count of EAPOL/PMKID is
    far more use than an error the user has to interpret.
    """
    request = request or RunRequest("capture", _crack_options, capture_seconds=CAPTURE_SECONDS)
    state.capture_total.set(request.capture_seconds)
    try:
        readiness = await probe_readiness(request.options)
        state.readiness.set(readiness)
        _, report = await pipeline.obtain_hashes(
            net,
            readiness,
            capture_seconds=request.capture_seconds,

            deauth=request.options.deauth,
            cb=_pipeline_callbacks(),
        )
        found = hc22000.summarise(report)
        state.push_log(f"Захват завершён: {found}")
        result = CrackResult(
            network=net, success=report.ok, method="захват", summary=found,
            error="" if report.ok else (
                "Захват сохранён, но рукопожатий и PMKID в нём нет.\n\n"
                f"{found}\n\n"
                "Рукопожатие появляется, когда устройство подключается к сети. "
                "Повтори захват и переподключи телефон или ноутбук."),
            remedy="Готовый файл .pcapng можно выбрать в параметрах: «Файл».",
        )
    except asyncio.CancelledError:
        raise
    except pipeline.PipelineError as exc:
        result = CrackResult(network=net, success=False, method="захват", error=str(exc),
                             remedy=getattr(exc, "remedy", ""))
    except Exception as exc:  # noqa: BLE001
        result = CrackResult(network=net, success=False, method="захват", error=f"ошибка: {exc}")
    finally:
        state.cancelled.set(False)
        # The capture and its hash file were only ever a means to that report.
        pipeline.cleanup_temp()

    _show_completed_result(result, request)


def begin_crack() -> None:
    """The ВЗЛОМАТЬ button / Enter: run the pipeline for the selected network."""
    net = state.selected_network()
    if net is None:
        state.push_log("Сначала просканируй и выбери сеть")
        return
    if not net.crackable:
        state.push_log(f"{net.label}: {crack_hint(net.auth)}")
        return
    # Refuse early, and say what does work instead, rather than starting an
    # attack whose capture stage cannot run on this machine.
    readiness = state.readiness.peek()
    if readiness is not None and not readiness.can_crack:
        state.push_log(f"{net.label}: {_capture_blocker(readiness)}")
        return
    start_attack(net)


def open_audit(network: Network | None = None) -> None:
    """Show a passive report for the selected or explicitly supplied network.

    Readiness is re-probed on arrival rather than left over from whenever the
    screen was last drawn. It used to be whatever boot had found, so the verdict
    under the start button described a machine state from minutes earlier and
    only became true after Enter -- at which point the screen had already been
    trusted. The probe is the slow part (netsh and tshark, seconds each), so the
    previous verdict stays on screen until the new one lands.
    """
    net = network or state.selected_network()
    if net is None:
        state.scan_notice.set("Сначала выберите сеть в списке.")
        return
    state.scan_notice.set("")
    focus = dict(state.control_focus.peek())
    focus.pop("audit", None)
    state.control_focus.set(focus)
    navigation.push("audit")
    state.audit_network.set(net)
    state.audit_has_key.set(None)
    recheck_readiness()
    check_audit_key(net)
    probe_board()


def back_from_audit() -> None:
    """Return to the list that opened the report."""
    navigation.back()


def _capture_blocker(readiness) -> str:
    """One line explaining why live capture cannot run, plus what does work."""
    if not readiness.admin:
        return "нет прав администратора — захват невозможен. Запусти от админа."
    if readiness.capture_problem:
        return readiness.capture_problem
    if readiness.backend is None:
        return (
            "нет инструмента захвата (cap80211/tshark) — живой захват не запустится. "
            "Кнопка «Файл» на экране параметров: откуда взять .pcapng — в справке."
        )
    if readiness.iface is None:
        return next((p for p in readiness.problems if p.startswith("Интерфейс захвата:")),
                    "Wi-Fi интерфейс для захвата не найден. "
                    "Кнопка «Файл» на экране параметров.")
    if readiness.hashcat is None:
        return "hashcat не найден. F1 → Установить компоненты."
    if readiness.wordlist is None:
        return "Словарь не найден. F1 → Установить компоненты."
    return "захват недоступен на этом адаптере."


def _run_stages() -> tuple[str, ...]:
    """The checklist for an automatic run, minus whatever is switched off.

    The history stage is the first one because it is the only answer that needs
    no capture and no luck, and the first one to disappear when that shortcut is
    turned off -- the list is built here so the screen cannot promise a stage
    the pipeline will not take.
    """
    from .. import profiles as profiles_mod

    stages = ("capture", "convert", "crack")
    return ("saved", *stages) if profiles_mod.HISTORY_ENABLED else stages


def go_to_saved() -> None:
    """Switch to the saved-networks screen and load its profiles."""
    from .. import profiles as profiles_mod

    if not profiles_mod.HISTORY_ENABLED:
        state.push_log("Просмотр истории подключений отключён — сети берутся "
                       "только своим хендшейком.")
        return
    navigation.push("saved")
    state.saved_loading.set(True)
    refresh_saved()


def back_from_saved() -> None:
    """Return to the screen that opened the saved-profile list."""
    navigation.back()


def go_to_scan() -> None:
    """Back to the scan screen."""
    navigation.home()
    if not state.networks.peek():
        request_rescan()


# --- offline mode ----------------------------------------------------------


def pick_capture_file() -> None:
    """Choose a capture here and run on it the moment it is chosen.

    The blocker text used to end with "F1 -> «Параметры» -> источник «Файл
    захвата» -> Enter на поле «Захват»" -- four steps of menu walking, from a
    screen whose entire message is that live capture cannot run here. The file is
    the way forward, so the way forward is one action away from that screen, and
    it applies itself: choosing a file starts the run, with no field to fill and
    no second Enter.
    """
    from . import forms

    forms.pick_file_directly(
        lambda path: open_capture(path, choose_target=True)
    )


def open_capture(path: str | Path, *, choose_target: bool = False,
                 request: RunRequest | None = None, automatic: bool = False) -> None:
    """Crack an existing capture file, skipping the scan and live capture."""
    _set_run_context("file", Path(path).name)
    state.cracking_network.set(None)
    state.cancelled.set(False)
    state.capture_left.set(None)
    if state.phase.peek() == "capture_targets":
        navigation.replace("crack")
    else:
        navigation.push("crack")
    request = request or RunRequest("file", _crack_options, capture_path=str(Path(path).resolve()))
    # After the navigation above, for the same reason as the other entry points:
    # the run screen has to arrive with its plan already drawn.
    state.log.set([])
    begin_run("convert", "crack")
    start_ticking()
    _spawn(_open_capture(Path(path), choose_target=choose_target, request=request,
                         automatic=automatic))


def start_capture_run(path: str | Path) -> None:
    """``--auto --file``: convert and run the one-key ladder straight away.

    The capture already names its own target, so there is nothing to ask about;
    opening the parameters form first would just be a keypress the flag promised
    not to need.
    """
    open_capture(path, automatic=True)


async def _open_capture(path: Path, *, choose_target: bool = False,
                        request: RunRequest | None = None,
                        automatic: bool = False) -> None:
    """Convert a capture on disk, then run only the cracking stage."""
    from .. import hc22000
    if state.run_source.peek() != "file":
        _set_run_context("file", path.name)
    if automatic and request is None:
        request = RunRequest("auto", _crack_options, capture_path=str(path.resolve()),
                             total_runtime=_auto_budget(_crack_options))
    request = request or RunRequest("file", _crack_options, capture_path=str(path.resolve()))
    options = request.options
    # The plan was published by ``open_capture`` before this coroutine was
    # scheduled; re-publishing it here would wipe the stage line that has since
    # been written into the journal.

    if not path.exists():
        _show_completed_result(
            CrackResult(network=Network(ssid=path.name, bssid=""),
                        error=f"Файл не найден: {path}", log=[f"Файл не найден: {path}"]), request
        )
        return

    state.cancelled.set(False)
    state.cracking_network.set(None)
    state.log_scroll.set(0)
    state.progress.set(0.0)
    state.stage.set("")
    navigation.replace("crack")
    cb = _pipeline_callbacks()
    # Reported as a phase, not poked into the label directly: the conversion is
    # the first stage of this run's plan, and a plan whose first stage is later
    # reported as "skipped" because nobody announced it is worse than no plan.
    cb.phase("convert")
    try:
        hash_path, report = await pipeline.convert_capture(path, options.bssid, state.push_log,
                                                           should_stop=cb.should_stop)
        if not report.ok:
            raise pipeline.PipelineError(
                "В этом файле нет пригодных хэшей.\n\n" + hc22000.summarise(report)
            )
        targets = {line.split("*")[3].lower() for line in report.pmkid + report.eapol}
        if len(targets) != 1:
            if choose_target:
                networks = []
                for ap in sorted(targets):
                    lines = [line for line in report.pmkid + report.eapol if line.split("*")[3].lower() == ap]
                    subset = hc22000.ConversionReport(pmkid=lines)
                    networks.append(Network(ssid=_first_essid(subset), bssid=_first_bssid(subset), auth="WPA2-Personal"))
                state.capture_targets.set(networks)
                state.capture_selected.set(0)
                state.capture_source.set(str(path))
                navigation.replace("capture_targets")
                return
            raise pipeline.PipelineError(
                "В файле несколько точек доступа. Укажи цель: --bssid aa:bb:cc:dd:ee:ff"
            )
        essid = _first_essid(report)
        bssid = _first_bssid(report)
        net = Network(ssid=essid, bssid=bssid, auth="WPA2-Personal")
        state.cracking_network.set(net)
        state.push_log(f"Сеть: {net.label or '(без имени)'}  {net.bssid}")
        request = replace(request, options=replace(options, bssid=net.bssid))
        readiness = await probe_readiness(options)
        if automatic:
            # --auto: the ladder, which needs no dictionary chosen by hand and
            # no time limit typed in.
            result = await pipeline.auto_attack(
                net,
                readiness=readiness,
                hash_path=hash_path,
                report=report,
                capture_path=str(path),
                wordlist=options.wordlist,
                rules=options.rules if options.use_rules else None,
                total_runtime=request.total_runtime,
                mask=options.mask,
                cb=cb,
            )
        else:
            result = await pipeline.attack(
                net,
                readiness=readiness,
                hash_path=hash_path,
                report=report,
                mask=options.mask,
                timeout=options.runtime,
                use_rules=options.use_rules,
                cb=cb,
            )
    except asyncio.CancelledError:
        raise
    except pipeline.PipelineError as exc:
        result = CrackResult(
            network=state.cracking_network.peek() or Network(ssid=path.name, bssid=""),
            success=False,
            error=str(exc),
            remedy=getattr(exc, "remedy", ""),
        )
    except Exception as exc:  # noqa: BLE001
        result = CrackResult(
            network=Network(ssid=path.name, bssid=""), success=False, error=str(exc)
        )
    finally:
        state.cancelled.set(False)
        pipeline.cleanup_temp()

    _show_completed_result(result, request)


def retry_result(result: CrackResult) -> None:
    """Repeat the original operation, including offline source and options."""
    request = result.request
    if request is None:
        open_crack_form(result.network)
        return
    try:
        configure_cracking(request.options)
    except (ValueError, OSError) as exc:
        _show_completed_result(CrackResult(network=result.network, error=str(exc),
                                          remedy="Открой параметры и выбери доступный файл."), request)
        return
    if request.mode == "file":
        open_capture(request.capture_path, choose_target=True, request=request)
    elif request.mode == "manual":
        start_attack(result.network, request=request)
    elif request.mode == "capture":
        begin_capture_for(result.network, request=request)
    elif request.mode == "board":
        start_board_capture(result.network)
    else:
        start_auto_attack(result.network, request=request)


def choose_capture_target() -> None:
    targets = state.capture_targets.peek()
    index = state.capture_selected.peek()
    if not 0 <= index < len(targets):
        return
    network = targets[index]
    configure_cracking(replace(_crack_options, bssid=network.bssid))
    from .forms import set_value
    set_value("bssid", network.bssid)
    open_capture(state.capture_source.peek(), choose_target=True)


def _first_essid(report) -> str:
    for line in report.pmkid + report.eapol:
        parts = line.split("*")
        if len(parts) > 5:
            try:
                return bytes.fromhex(parts[5]).decode("utf-8", "replace")
            except ValueError:
                continue
    return ""


def _first_bssid(report) -> str:
    for line in report.pmkid + report.eapol:
        parts = line.split("*")
        if len(parts) > 3:
            try:
                raw = bytes.fromhex(parts[3])
                if len(raw) == 6:
                    return ":".join(f"{b:02x}" for b in raw)
            except ValueError:
                continue
    return ""


def cancel_attack() -> None:
    state.cancelled.set(True)
    state.status.set("Останавливаю...")
    state.push_log("[запрошена остановка]")


def back_to_scan() -> None:
    go_to_scan()


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


def quit_app() -> None:
    state.cancelled.set(True)
    if _renderer is not None:
        _renderer.stop()


def stop_pending() -> None:
    """Wait for child-process cleanup when the terminal UI closes."""
    stop_ticking()
    if _loop is None or not _loop.is_running():
        return

    async def cleanup() -> None:
        current = asyncio.current_task()
        pending = [task for task in asyncio.all_tasks() if task is not current]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    future = asyncio.run_coroutine_threadsafe(cleanup(), _loop)
    future.result(timeout=8)


# ---------------------------------------------------------------------------
# saved profiles
# ---------------------------------------------------------------------------


def refresh_saved() -> None:
    """Re-read the saved Wi-Fi profiles."""
    from .. import profiles as profiles_mod

    if not profiles_mod.HISTORY_ENABLED:
        state.saved.set([])
        state.saved_loading.set(False)
        return
    state.saved_loading.set(True)
    _spawn(_load_saved())


def saved_boot() -> asyncio.Task | None:
    """Show the saved-networks screen: it needs no hardware and no admin."""
    from .. import profiles as profiles_mod

    if not profiles_mod.HISTORY_ENABLED:
        state.push_log("Просмотр истории подключений отключён")
        return None
    state.saved_loading.set(True)
    navigation.push("saved")
    return _spawn(_load_saved())


async def _load_saved() -> None:
    from .. import profiles as profiles_mod

    current = state.saved.peek()
    cursor = state.saved_selected.peek()
    selected_name = current[cursor].name if 0 <= cursor < len(current) else ""
    state.saved_error.set("")
    try:
        found = await asyncio.to_thread(profiles_mod.read_all)
    except Exception as exc:  # noqa: BLE001
        state.push_log(f"Не удалось прочитать профили: {exc}")
        state.saved_error.set(f"Не удалось прочитать профили: {exc}. Выберите «Обновить».")
        found = []
    state.saved.set(found)
    state.saved_selected.set(next((i for i, profile in enumerate(found) if profile.name == selected_name),
                                  min(cursor, max(0, len(found) - 1))))
    state.saved_loading.set(False)
