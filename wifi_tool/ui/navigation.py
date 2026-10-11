"""Screen history, independent of the command dialog's focus.

Dialogs follow OpenCode's modal stack. This screen stack also preserves the
identity of reports when the same screen is visited from another list.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from opentui.signals import Signal

from . import state

LABELS = {
    "scan": "Сети",
    "audit": "Проверка сети",
    "saved": "Сохранённые сети",
    "crack_form": "Параметры",
    "file_picker": "Файл",
    "method_help": "Справка",
    "capture_targets": "Сеть из файла",
    "crack": "Подбор",
    "result": "Результат",
}


@dataclass(frozen=True)
class Route:
    phase: str
    context: tuple[tuple[str, object], ...] = ()


history: Signal = Signal([], name="screen_history")
_lock = RLock()
_CONTEXT = {
    "scan": ("network_scroll_offset", "scan_query", "scan_query_cursor"),
    "audit": ("audit_network",),
    "saved": (),
    "crack_form": ("form_values", "form_network", "form_focus", "form_cursor",
                   "form_select_all", "form_error", "form_advanced"),
    "result": ("result", "log_scroll"),
}


def _leave() -> None:
    from . import dialogs

    dialogs.clear()
    state.revealed_secret.set(None)
    if state.phase.peek() == "crack_form":
        from .forms import save_draft

        save_draft()


def push(phase: str) -> None:
    if phase == state.phase.peek():
        return
    with _lock:
        current = state.phase.peek()
        names = _CONTEXT.get(current, ())
        # Pickers and help edit the current form; returning must retain those edits.
        if current == "crack_form" and phase in ("file_picker", "method_help", "crack"):
            names = ()
        context = tuple((name, getattr(state, name).peek())
                        for name in names)
        if current == "scan":
            net = state.selected_network()
            context += (("network_identity", state.network_identity(net) if net else ""),)
        if current == "saved":
            items, cursor = state.saved.peek(), state.saved_selected.peek()
            context += (("saved_identity", items[cursor].name if 0 <= cursor < len(items) else ""),)
        _leave()
        history.set([*history.peek(), Route(current, context)])
        state.phase.set(phase)


def replace(phase: str) -> None:
    """Finish a transient step, keeping its parent as the destination for Back."""
    with _lock:
        _leave()
        state.phase.set(phase)


def back(fallback: str = "scan") -> None:
    with _lock:
        _leave()
        routes = history.peek()
        if routes:
            route = routes[-1]
            history.set(routes[:-1])
            for name, value in route.context:
                if name == "network_identity":
                    state.selected.set(next((i for i, net in enumerate(state.networks.peek())
                                             if state.network_identity(net) == value), -1))
                elif name == "saved_identity":
                    state.saved_selected.set(next((i for i, item in enumerate(state.saved.peek())
                                                   if item.name == value), 0))
                else:
                    getattr(state, name).set(value)
            if route.phase == "scan":
                from .screens.scan import ensure_selection
                ensure_selection()
            elif route.phase == "saved":
                state.saved_selected.set(min(state.saved_selected.peek(), max(0, len(state.saved.peek()) - 1)))
            state.phase.set(route.phase)
        else:
            state.phase.set(fallback)


def home() -> None:
    with _lock:
        _leave()
        history.set([])
        state.phase.set("scan")


def reset() -> None:
    history.set([])
    from . import dialogs

    dialogs.clear()


def back_label() -> str:
    routes = history()
    return LABELS.get(routes[-1].phase, "Сети") if routes else "Сети"


def breadcrumb() -> str:
    phases = [route.phase for route in history()] + [state.phase()]
    labels = [LABELS.get(phase, phase) for phase in phases]
    return " / ".join((["…"] + labels[-3:]) if len(labels) > 3 else labels)
