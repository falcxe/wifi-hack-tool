"""Reactive application state (module-level Signals shared by all screens)."""
from __future__ import annotations

from opentui.signals import Signal

from ..models import CrackResult, Network
from ..scanner import AdapterInfo

# Phase machine: scan -> audit (legacy capture flow remains separate).
phase: Signal = Signal("scan", name="phase")
# Focus belongs to the screen, so opening a dialog preserves the active control.
control_focus: Signal = Signal({}, name="control_focus")

# Scan screen
networks: Signal = Signal([], name="networks")
selected: Signal = Signal(0, name="selected")
network_scroll_offset: Signal = Signal(0, name="network_scroll_offset")
scan_query: Signal = Signal("", name="scan_query")
scan_query_cursor: Signal = Signal(0, name="scan_query_cursor")
scan_anchor: Signal = Signal("", name="scan_anchor")
scanning: Signal = Signal(False, name="scanning")
scan_error: Signal = Signal("", name="scan_error")
scan_notice: Signal = Signal("", name="scan_notice")
adapter: Signal = Signal(None, name="adapter")
is_admin: Signal = Signal(False, name="is_admin")

# Passive audit view
audit_network: Signal = Signal(None, name="audit_network")

# Crack screen
cracking_network: Signal = Signal(None, name="cracking_network")
log: Signal = Signal([], name="log")
log_scroll: Signal = Signal(0, name="log_scroll")
log_page: Signal = Signal(1, name="log_page")
progress: Signal = Signal(0.0, name="progress")
progress_known: Signal = Signal(False, name="progress_known")
run_speed: Signal = Signal("", name="run_speed")
run_eta: Signal = Signal("", name="run_eta")
status: Signal = Signal("", name="status")
current_activity: Signal = Signal("", name="current_activity")
run_source: Signal = Signal("", name="run_source")
run_context: Signal = Signal("", name="run_context")
board_deadline: Signal = Signal(None, name="board_deadline")
#: Live capture stage: seconds left and bytes written so far. ``None`` means the
#: run is not capturing, so the crack screen can show its normal hashcat view.
capture_left: Signal = Signal(None, name="capture_left")
capture_total: Signal = Signal(None, name="capture_total")
capture_bytes: Signal = Signal(0, name="capture_bytes")
#: What the capture produced: EAPOL handshakes and PMKIDs found, or "" while it
#: is still running / never ran. Set once, from the conversion report.
capture_found: Signal = Signal("", name="capture_found")
#: Which rung of the automatic ladder is running, e.g. "Этап 3/6: RockYou WPA".
stage: Signal = Signal("", name="stage")
cancelled: Signal = Signal(False, name="cancelled")

#: A free-running counter used to animate the run screen. A frame is redrawn
#: when a signal changes and at no other time, so a spinner that only reads this
#: signal sat frozen until a key was pressed -- which made a run that was working
#: look hung. Subscribing to it is what makes the screen move on its own.
tick: Signal = Signal(0, name="tick")

#: Seconds the current run has been going. Driven by the renderer's own frame
#: clock, not by a timer thread -- see :func:`wifi_tool.ui.controller.start_ticking`.
elapsed: Signal = Signal(0.0, name="elapsed")

#: Whether the machine has a stored key for the network on the audit screen.
#: ``None`` means "not looked yet"; the check runs in the background so the
#: screen is never waiting on it.
audit_has_key: Signal = Signal(None, name="audit_has_key")

#: An ESP32 board running Bruce, as far as the background probe knows: ``None``
#: while it is looking, ``False`` when there is none, and a short label like
#: "COM5 (CH9102)" when one answered. On a machine whose own adapter cannot do
#: monitor mode this board is the only capture route there is, so its presence
#: decides what the audit screen is honestly able to offer.
board: Signal = Signal(False, name="board")

#: A capture taken off the board and waiting to be cracked: ``(path, label)``.
board_capture: Signal = Signal(None, name="board_capture")

#: The run as an explicit checklist, so nothing it does is a surprise: the keys
#: are the stages the pipeline reports (:meth:`Callbacks.phase`) and the values
#: are ``pending`` / ``current`` / ``done`` / ``skipped``. Reading the password
#: out of the machine's own connection history used to be an invisible step --
#: it either produced the answer or nobody knew it was tried.
run_stages: Signal = Signal([], name="run_stages")


def begin_run_stages(keys: list[str]) -> None:
    """Start a run's checklist at ``keys``, all of them pending."""
    run_stages.set([(key, "pending") for key in keys])


def advance_run_stage(key: str) -> None:
    """Mark ``key`` current, everything before it done, everything after pending.

    A stage the pipeline skipped stays skipped: a capture file means live capture
    never ran, and showing it as "done" would be a lie.
    """
    rows = list(run_stages.peek())
    if not any(k == key for k, _ in rows):
        return
    out: list[tuple[str, str]] = []
    passed = False
    for existing, status in rows:
        if existing == key:
            passed = True
            out.append((existing, "current"))
        elif not passed:
            out.append((existing, "done" if status == "current" else status))
        else:
            out.append((existing, status))
    run_stages.set(out)


def settle_run_stage(key: str, status: str) -> None:
    """Set one stage to a final status without touching the others.

    The run ending does not tell us which stage ended it: a stored key found in
    Windows history finishes while "capture" is still the current stage, and a
    failed capture finishes while it is too. So the ending stage is named, and
    only that one moves.
    """
    if status not in ("done", "skipped"):
        raise ValueError(f"settle: {status!r} is not a final status")
    rows = list(run_stages.peek())
    if not any(k == key for k, _ in rows):
        return
    run_stages.set([(k, status if k == key else s) for k, s in rows])


def finish_run_stages(stage: str | None = None, status: str = "done") -> None:
    """The run is over.

    The stage the run ended in is the one still marked ``current``: a stored
    Windows key answers while "capture" has not started, and a failed capture
    ends while it is still current. That stage ran, so it is settled as
    finished; everything still ``pending`` never ran at all and is marked
    ``skipped`` rather than done, which is also the answer to "why did it stop
    this early?".

    ``stage``/``status`` override the derivation when the caller knows better.
    """
    if status not in ("done", "skipped"):
        raise ValueError(f"finish_run_stages: {status!r} is not a final status")
    rows = list(run_stages.peek())
    if stage is None:
        stage = next((k for k, s in rows if s == "current"), None)
        status = "done" if stage is not None else status
    if stage is not None and any(k == stage for k, _ in rows):
        rows = [(k, status if k == stage else s) for k, s in rows]
    run_stages.set([(k, "skipped" if s == "pending" else s) for k, s in rows])

# Result screen
result: Signal = Signal(None, name="result")
last_result: Signal = Signal(None, name="last_result")
revealed_secret: Signal = Signal(None, name="revealed_secret")

# Setup / readiness -- describes the machine, not the current run.
readiness: Signal = Signal(None, name="readiness")

# Installer
install_state: Signal = Signal("idle", name="install_state")  # idle | working
install_progress: Signal = Signal("", name="install_progress")

# Saved profiles (Windows stores a key for every network this machine joined)
saved: Signal = Signal([], name="saved")
saved_loading: Signal = Signal(False, name="saved_loading")
saved_error: Signal = Signal("", name="saved_error")
#: Cursor over the saved-profile list, so up/down can walk it and Enter can act
#: on a row. Separate from ``selected`` (the scanned networks) on purpose: the two
#: lists are unrelated and share nothing but the screen they are drawn on.
saved_selected: Signal = Signal(0, name="saved_selected")

#: Optional callable run once at mount, used by ``main.py --file`` to jump
#: straight into cracking a capture without touching the scan screen.
pending_start = None

# Interactive audit setup and the in-terminal file/network pickers.
form_values: Signal = Signal({}, name="form_values")
form_focus: Signal = Signal(0, name="form_focus")
form_cursor: Signal = Signal(0, name="form_cursor")
form_select_all: Signal = Signal(False, name="form_select_all")
form_error: Signal = Signal("", name="form_error")
form_advanced: Signal = Signal(False, name="form_advanced")
form_drafts: Signal = Signal({}, name="form_drafts")
form_network: Signal = Signal(None, name="form_network")
help_scroll: Signal = Signal(0, name="help_scroll")
help_lines: Signal = Signal(0, name="help_lines")
help_page: Signal = Signal(1, name="help_page")
file_directory: Signal = Signal("", name="file_directory")
file_entries: Signal = Signal([], name="file_entries")
file_selected: Signal = Signal(0, name="file_selected")
file_field: Signal = Signal("", name="file_field")
file_error: Signal = Signal("", name="file_error")
list_pages: Signal = Signal({}, name="list_pages")
capture_targets: Signal = Signal([], name="capture_targets")
capture_selected: Signal = Signal(0, name="capture_selected")
capture_source: Signal = Signal("", name="capture_source")


def reset() -> None:
    """Reset all state back to a fresh scan screen.

    ``adapter``, ``is_admin`` and ``readiness`` are deliberately preserved:
    they describe the machine rather than the current run, and are refreshed
    by :func:`wifi_tool.ui.controller.refresh_readiness`.
    """
    from . import motion, navigation

    navigation.reset()
    motion.reset()
    phase.set("scan")
    control_focus.set({})
    networks.set([])
    selected.set(0)
    network_scroll_offset.set(0)
    scan_query.set("")
    scan_query_cursor.set(0)
    scan_anchor.set("")
    scanning.set(False)
    scan_error.set("")
    scan_notice.set("")
    saved_selected.set(0)
    saved.set([])
    saved_loading.set(False)
    saved_error.set("")
    revealed_secret.set(None)
    audit_network.set(None)
    cracking_network.set(None)
    log.set([])
    log_scroll.set(0)
    log_page.set(1)
    progress.set(0.0)
    progress_known.set(False)
    run_speed.set("")
    run_eta.set("")
    status.set("")
    current_activity.set("")
    run_source.set("")
    run_context.set("")
    board_deadline.set(None)
    stage.set("")
    capture_left.set(None)
    capture_total.set(None)
    capture_bytes.set(0)
    capture_found.set("")
    cancelled.set(False)
    run_stages.set([])
    tick.set(0)
    elapsed.set(0.0)
    board.set(False)
    board_capture.set(None)
    audit_has_key.set(None)
    result.set(None)
    last_result.set(None)
    # The download indicator is a transient UI flag, not machine state. Left
    # set, it makes the merged settings screen render the "installing" view
    # instead of the parameters -- and nothing but a successful download would
    # ever clear it, so the screen would be stuck.
    install_state.set("idle")
    install_progress.set("")
    form_drafts.set({})
    form_advanced.set(False)
    form_error.set("")
    list_pages.set({})


def network_identity(network) -> str:
    return (network.bssid.replace("-", ":").casefold() if network.bssid else
            f"{network.ssid}\0{network.auth}".casefold())


def replace_networks(items: list[Network]) -> None:
    """Refresh data without changing the user's network, query or focus."""
    previous = selected_network()
    identity = network_identity(previous) if previous else scan_anchor.peek()
    old_index = selected.peek()
    networks.set(items)
    from .screens.scan import filtered_networks
    visible = filtered_networks()
    match = next((i for i, net in visible if network_identity(net) == identity), None)
    selected.set(match if match is not None else
                 visible[min(max(0, old_index), len(visible) - 1)][0] if visible else -1)
    if selected_network():
        scan_anchor.set(network_identity(selected_network()))


def push_log(line: str) -> None:
    lines = list(log.peek())
    # The run screen writes a stage line on entry to each stage, and a stage can
    # be entered more than once -- a re-probe restarts it, and a ladder that
    # falls back to the capture re-enters it. Three identical lines of
    # "· Проверка истории подключений" is a bug report, not a log.
    if lines and lines[-1] == line:
        return
    lines.append(line)
    if log_scroll.peek():
        log_scroll.set(min(log_scroll.peek() + 1, max(0, min(400, len(lines)) - log_page.peek())))
    # keep the tail so the buffer stays bounded
    if len(lines) > 400:
        lines = lines[-400:]
    log.set(lines)


def select_network(index: int) -> None:
    """Mark a network as the cracking target and move to the crack phase."""
    nets = networks.peek()
    if 0 <= index < len(nets):
        cracking_network.set(nets[index])
    cancelled.set(False)
    log.set([])
    log_scroll.set(0)
    progress.set(0.0)
    status.set("")
    current_activity.set("")
    stage.set("")
    from . import navigation

    navigation.push("crack")


def selected_network():
    """The network under the cursor on the scan screen, or None."""
    from ..models import Network  # local import keeps this module dependency-free

    nets = networks.peek()
    index = selected.peek()
    if 0 <= index < len(nets) and isinstance(nets[index], Network):
        return nets[index]
    return None
