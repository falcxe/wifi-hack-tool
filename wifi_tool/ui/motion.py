"""Short, interruptible terminal transitions, driven by the renderer's clock.

The logical cursor changes immediately. Only viewport position and row colors
are eased; a selected row outside a moving viewport is pinned to its edge.
Headless captures settle immediately unless explicitly enabled by a motion test.
"""
from __future__ import annotations

import os
import weakref
from dataclasses import dataclass, field

from opentui.signals import Signal

from .theme import CANVAS, FOCUS_SURFACE, SURFACE, SELECTION_SURFACE

SCROLL_SECONDS = 0.16
FOCUS_SECONDS = 0.14


def blend(first: str, second: str, amount: float) -> str:
    amount = max(0.0, min(1.0, amount))
    channels = [round(int(first[i:i + 2], 16) * (1 - amount)
                      + int(second[i:i + 2], 16) * amount) for i in (1, 3, 5)]
    return "#" + "".join(f"{channel:02x}" for channel in channels)


def _ease(progress: float) -> float:
    return 1 - (1 - max(0.0, min(1.0, progress))) ** 3


@dataclass
class Scroll:
    token: object
    origin: float
    target: int
    started: float
    duration: float = 0.0

    def value(self, now: float) -> float:
        progress = 1.0 if not self.duration else _ease((now - self.started) / self.duration)
        return self.origin + (self.target - self.origin) * progress


@dataclass
class Highlight:
    token: object
    selected: object
    started: float
    origin: dict = field(default_factory=dict)
    duration: float = 0.0

    def weights(self, now: float) -> dict:
        progress = 1.0 if not self.duration else _ease((now - self.started) / self.duration)
        values = {key: weight * (1 - progress) for key, weight in self.origin.items()}
        values[self.selected] = values.get(self.selected, 0.0) + progress
        return {key: value for key, value in values.items() if value > .01}


class Motion:
    def __init__(self):
        self.revision = Signal(0, name="motion_frame")
        self.scrolls: dict[str, Scroll] = {}
        self.highlights: dict[str, Highlight] = {}
        self.paints = {}
        self.now = 0.0
        self.enabled = False
        self.scope = None
        self._renderer_ref = None
        self._callback = None
        self._generation = 0

    def bind(self, renderer, *, enabled: bool | None = None) -> None:
        previous = self._renderer_ref() if self._renderer_ref else None
        if previous is renderer:
            if enabled is not None:
                self.enabled = enabled
            return
        self.unbind()
        self._renderer_ref = weakref.ref(renderer)
        testing = getattr(getattr(renderer, "_config", None), "testing", False)
        reduced = os.getenv("WIFI_TOOL_REDUCED_MOTION", "").lower() in ("1", "true", "yes")
        self.enabled = (not testing and not reduced) if enabled is None else enabled
        generation = self._generation

        def on_frame(delta):
            if generation == self._generation:
                self.advance(delta)

        self._callback = on_frame
        renderer.set_frame_callback(on_frame)

    def unbind(self) -> None:
        renderer = self._renderer_ref() if self._renderer_ref else None
        if renderer is not None and self._callback is not None:
            renderer.remove_frame_callback(self._callback)
        self._renderer_ref = self._callback = None
        self._generation += 1
        self.reset()

    def reset(self) -> None:
        self.scrolls.clear()
        self.highlights.clear()
        self.paints.clear()
        self.scope = None

    def context(self, scope) -> None:
        if scope != self.scope:
            self.reset()
            self.scope = scope

    def forget(self, key: str) -> None:
        self.scrolls.pop(key, None)
        self.highlights.pop(key, None)
        self.paints.pop(key, None)

    def active(self) -> bool:
        return self.enabled and any(
            lane.duration and self.now - lane.started < lane.duration
            for lane in (*self.scrolls.values(), *self.highlights.values()))

    def advance(self, delta: float) -> None:
        if not self.active():
            return
        previous = self.now
        self.now += max(0.0, float(delta))
        # Colors only dirty existing native boxes; they never rebuild a screen
        # or rerun its layout. A cell-based viewport changes only at cell edges.
        for key, rows in list(self.paints.items()):
            lane = self.highlights.get(key)
            for index, (reference, options) in list(rows.items()):
                box = reference()
                if box is None or box.is_destroyed:
                    rows.pop(index, None)
                    continue
                if lane is not None:
                    box.background_color = self.row(key, lane.selected, index, **options)
        if any(round(lane.value(previous)) != round(lane.value(self.now))
               for lane in self.scrolls.values()):
            self.revision.set(self.revision.peek() + 1)

    def window(self, key: str, total: int, room: int, selected: int | None,
               *, token=None, target: int | None = None) -> tuple[int, list[int]]:
        self.revision()
        room = max(1, room)
        maximum = max(0, total - room)
        lane = self.scrolls.get(key)
        fresh = lane is None or lane.token != token
        if target is None:
            target = 0 if fresh else lane.target
            if selected is not None:
                if selected < target:
                    target = selected
                elif selected >= target + room:
                    target = selected - room + 1
        target = max(0, min(maximum, target))
        if fresh:
            lane = Scroll(token, target, target, self.now)
            self.scrolls[key] = lane
        elif target != lane.target:
            origin = lane.value(self.now)
            # Very long Home/End jumps should arrive immediately, not tour every row.
            duration = SCROLL_SECONDS if self.enabled and abs(target - origin) <= room * 3 else 0.0
            lane = Scroll(token, origin, target, self.now, duration)
            self.scrolls[key] = lane
        if not self.enabled:
            lane.origin, lane.duration = target, 0.0
        start = max(0, min(maximum, round(lane.value(self.now))))
        indices = list(range(start, min(total, start + room)))
        if indices and selected is not None and 0 <= selected < total:
            if selected < start:
                indices[0] = selected
            elif selected >= start + room:
                indices[-1] = selected
        return start, indices

    def row(self, key: str, selected, index, *, token=None, focused=True,
            zebra=False, surface=CANVAS, animate=True) -> str | None:
        lane = self.highlights.get(key)
        if lane is None or lane.token != token:
            lane = Highlight(token, selected, self.now)
            self.highlights[key] = lane
        elif selected != lane.selected:
            lane = Highlight(token, selected, self.now, lane.weights(self.now),
                             FOCUS_SECONDS if self.enabled and animate else 0.0)
            self.highlights[key] = lane
        weights = lane.weights(self.now) if self.enabled else {selected: 1.0}
        weight = weights.get(index, 0.0)
        # The actual cursor remains legible from the first frame of a transition.
        if index == selected:
            weight = max(.3, weight)
        base = blend(surface, SURFACE, .24) if zebra and isinstance(index, int) and index % 2 else surface
        return blend(base, FOCUS_SURFACE if focused else SELECTION_SURFACE, weight) if weight > .01 else base if zebra else None

    def paint(self, box, key: str, selected, index, **options):
        box.background_color = self.row(key, selected, index, **options)
        self.paints.setdefault(key, {})[index] = (weakref.ref(box), options)
        return box


engine = Motion()
bind = engine.bind
context = engine.context
reset = engine.reset
forget = engine.forget


def _sync_context() -> None:
    from . import state
    renderer = engine._renderer_ref() if engine._renderer_ref else None
    if renderer is not None:
        engine.context((state.phase.peek(), renderer.width, renderer.height))


def window(*args, **kwargs):
    _sync_context()
    return engine.window(*args, **kwargs)


def row(*args, **kwargs):
    _sync_context()
    return engine.row(*args, **kwargs)


def paint(*args, **kwargs):
    _sync_context()
    return engine.paint(*args, **kwargs)
