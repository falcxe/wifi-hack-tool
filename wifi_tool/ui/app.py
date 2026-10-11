"""Root component: picks a screen from the phase signal.

Phases include ``scan`` -> ``audit`` for the passive Wi-Fi report. The legacy
capture flow remains available to its existing entry points.

The primary interactive flow is scan -> select -> passive audit report.

Note: bootstrapping deliberately does **not** rely on ``on_mount``. Mount
callbacks are not flushed by the headless test harness, and the root component
must start working in every context. The renderer is bound in the component body
(synchronous, reads no signals) and the boot task is started by ``main.py`` on the
controller's background event loop because OpenTUI blocks while rendering.
"""
from __future__ import annotations

from copy import copy

from opentui import Box, Switch, component
from opentui import hooks
from opentui.hooks import use_keyboard, use_paste, use_renderer, use_terminal_dimensions

from . import commands, controller, dialogs, motion, navigation, state
from .dialogs import DialogLayer
from .theme import CANVAS
from .screens.crack import CrackScreen
from .screens.audit import AuditScreen
from .screens.result import ResultScreen
from .screens.saved import SavedScreen
from .screens.scan import ScanScreen
from .screens.crack_form import CrackFormScreen, FilePickerScreen, CaptureTargetsScreen, MethodHelpScreen

def _dispatch_key(event) -> None:
    if getattr(event, "event_type", "press") == "release":
        event.stop_propagation()
        return
    count = getattr(event, "repeat_count", 1)
    # Lists can commit a burst as one cursor movement. Menus and forms retain
    # their per-key wrapping, disabled-item and field-navigation behavior.
    phase = state.phase.peek()
    default = "document" if phase == "method_help" else "list"
    aggregate = not dialogs.active() and phase in {
        "scan", "saved", "file_picker", "capture_targets", "method_help"
    } and state.control_focus.peek().get(phase, default) == default
    if count == 1 or aggregate:
        _route_key(event)
    else:
        for _ in range(count):
            repeated = copy(event)
            repeated.repeat_count = 1
            repeated._propagation_stopped = False
            _route_key(repeated)
        event.stop_propagation()


def _route_key(event) -> None:
    # OpenTUI 0.1.2 snapshots hooks when binding native terminal input. Screens
    # mounted later are absent from that snapshot. Keep one root hook bound
    # throughout the session and forward to the current screen's live hooks.
    if dialogs.handle_key(event) or commands.handle_global(event):
        return
    for handler in hooks.get_keyboard_handlers():
        if getattr(handler, "_original_handler", handler) is _dispatch_key:
            continue
        if event.propagation_stopped:
            break
        handler(event)


def _dispatch_paste(event) -> None:
    if dialogs.handle_paste(event):
        return
    for handler in hooks.get_paste_handlers():
        if handler is _dispatch_paste:
            continue
        if event.propagation_stopped:
            break
        handler(event)
    # Both native input and the headless harness may still hold screen hooks
    # in their outer dispatch snapshot; consume a paste exactly once.
    event.stop_propagation()


def _cases() -> dict:
    # "setup" is gone: the component checklist and the cracking parameters were
    # two screens answering one question, and they are merged into "crack_form".
    return {
        "saved": SavedScreen,
        "scan": ScanScreen,
        "audit": AuditScreen,
        "crack": CrackScreen,
        "crack_form": CrackFormScreen,
        "method_help": MethodHelpScreen,
        "file_picker": FilePickerScreen,
        "capture_targets": CaptureTargetsScreen,
        "result": ResultScreen,
    }


@component
def App():
    """Switch between the phases."""
    use_keyboard(_dispatch_key)
    use_paste(_dispatch_paste)
    renderer = use_renderer()
    width, height = use_terminal_dimensions()
    # Body, not on_mount: this must happen during tree construction so quit_app
    # always has a renderer to stop.
    controller.bind(renderer)
    motion.bind(renderer)
    motion.context((state.phase.peek(), width, height))

    if state.phase.peek() not in _cases():
        navigation.home()

    # Layout kwargs target the component's Mount. Anchor and size the Mount
    # itself so both drawing and mouse hit testing reach the dialog. Omit the
    # idle layer entirely so it cannot intercept clicks on the screen below.
    children = [Switch(on=state.phase, cases=_cases())]
    if dialogs.stack():
        children.append(DialogLayer(position="absolute", top=0, left=0,
                                    width=width, height=height, z_index=3000))
    return Box(*children,
               width=width, height=height, overflow="hidden",
               background_color=CANVAS)
