"""Shape the terminal session OpenTUI drives: reads off-thread, resize settled.

Two Windows-specific defects in OpenTUI 0.1.2 are corrected here, both by
wrapping rather than patching: the renderer is given a configuration that asks
for what it only infers, and the event loop is given the resize debounce it
already implements for Unix.

**Input.** OpenTUI waits on the console handle and then calls ReadFile. The
handle also signals for key releases, focus and resize events that produce no
VT bytes. ReadFile then waits for the next key and stops every frame meanwhile.
The adapter buffers actual bytes on one reader thread; parsing and dispatch
remain on OpenTUI's thread.

**Resize.** ``EventLoop.run`` has two resize paths. On Unix a SIGWINCH sets a
flag and the loop applies the new size only after 100 ms of quiet. Windows has
no SIGWINCH, so it takes the polling fallback -- which calls ``_handle_resize``
the moment the polled size differs, with no settling time. Dragging a window
edge then reports every intermediate size, and each one reaches
``CliRenderer.resize``, which resizes the buffers and sets ``_force_next_render``
for a complete repaint: dozens of full-screen redraws per second, each one
starting while the last is still going out. That is the tearing. The debounce
that already exists in the library is reused here rather than invented.
"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
import threading
import time

from opentui.input.handler import InputHandler


ENABLE_QUICK_EDIT_MODE = 0x0040
ENABLE_EXTENDED_FLAGS = 0x0080


def _disable_console_selection(backend) -> None:
    """Keep mouse clicks in the TUI instead of pausing conhost for selection.

    WindowsBackend saves the original modes before this runs and restores them
    on stop. EXTENDED_FLAGS is required for clearing QUICK_EDIT to take effect.
    """
    kernel = getattr(backend, "_kernel32", None)
    handle = getattr(backend, "_stdin_handle", None)
    if kernel is None or handle is None:
        return
    mode = wintypes.DWORD()
    if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
        return
    interactive = (mode.value | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE
    if interactive != mode.value and not kernel.SetConsoleMode(handle, interactive):
        raise OSError("Не удалось отключить выделение текста в консоли")


class ResponsiveInputHandler(InputHandler):
    """Commit a bounded burst of navigation keys before giving rendering a turn."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._yield_pending = False
        self._pending_events = None
        self._dispatch_handlers = None

    def poll(self) -> bool:
        if self._yield_pending:
            self._yield_pending = False
            return False
        events = []
        processed = False
        started = time.monotonic()
        handlers = self._key_handlers
        self._pending_events, self._dispatch_handlers = events, handlers
        self._key_handlers = [events.append]
        try:
            for _ in range(4096):
                before = len(events)
                if not super().poll():
                    break
                processed = True
                if (not events or len(events) == before) and not self._in_bracketed_paste:
                    break
                if events and len(events) != before and events[-1].key not in {"up", "down", "pageup", "pagedown"}:
                    break
                if len(events) >= 32:
                    break
                if time.monotonic() - started >= .008:
                    break
        finally:
            self._key_handlers = handlers
            self._pending_events = self._dispatch_handlers = None
        self._dispatch_events(events, handlers)
        self._yield_pending = processed
        return processed

    def _dispatch_events(self, events, handlers):
        # Adjacent repeats carry their distance in one event. Direction changes,
        # modifiers and Enter remain in their original order.
        grouped = []
        for event in events:
            signature = (event.key, event.ctrl, event.alt, event.shift, event.meta, event.event_type)
            if grouped and signature == grouped[-1][0] and event.key in {"up", "down", "pageup", "pagedown"}:
                grouped[-1][1].repeat_count += 1
            else:
                event.repeat_count = 1
                grouped.append((signature, event))
        for _, event in grouped:
            for callback in list(handlers):
                callback(event)
                if event.propagation_stopped:
                    break

    def _flush_before_pointer_or_paste(self):
        if self._pending_events:
            events = self._pending_events[:]
            self._pending_events.clear()
            self._dispatch_events(events, self._dispatch_handlers)

    def _emit_mouse(self, event):
        self._flush_before_pointer_or_paste()
        super()._emit_mouse(event)

    def _emit_paste(self, text):
        self._flush_before_pointer_or_paste()
        super()._emit_paste(text)


class BufferedInputBackend:
    def __init__(self, backend):
        self._backend = backend
        self._bytes: deque[int] = deque()
        self._condition = threading.Condition()
        self._running = False
        self._thread: threading.Thread | None = None
        self._error: Exception | None = None
        self._packet_remaining = 0
        self._prefix_since = None

    def start(self) -> None:
        if self._running:
            return
        self._backend.start()
        try:
            _disable_console_selection(self._backend)
        except Exception:
            self._backend.stop()
            raise
        self._running = True
        self._error = None
        self._thread = threading.Thread(
            target=self._read, name="wifi-tool-console-input", daemon=True,
        )
        self._thread.start()

    def _read(self) -> None:
        try:
            while self._running:
                byte = self._backend.read_byte()
                with self._condition:
                    if not self._running or byte < 0:
                        break
                    self._bytes.append(byte)
                    self._condition.notify_all()
        except Exception as exc:
            with self._condition:
                self._error = exc
        finally:
            with self._condition:
                self._running = False
                self._condition.notify_all()

    def has_data(self, timeout: float = 0) -> bool:
        with self._condition:
            deadline = time.monotonic() + timeout
            while True:
                if self._error is not None:
                    raise RuntimeError("Не удалось прочитать ввод терминала") from self._error
                if self._packet_remaining:
                    return bool(self._bytes)
                size = self._ready_packet()
                if size:
                    self._packet_remaining = size
                    self._prefix_since = None
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._running:
                    return False
                self._condition.wait(min(remaining, .01))

    def _ready_packet(self) -> int:
        """Expose complete UTF-8/VT sequences to OpenTUI's synchronous parser.

        Its ESC/CSI checks use a zero timeout. Publishing bytes individually
        therefore turns a fragmented arrow into Escape (opening a dialog), or
        spins inside the CSI parser waiting for a final byte that isn't there.
        A real, lone Escape is delivered after a short ambiguity timeout.
        """
        if not self._bytes:
            return 0
        first = self._bytes[0]
        if first != 27:
            size = 4 if first >= 0xF0 else 3 if first >= 0xE0 else 2 if first >= 0xC0 else 1
            return size if len(self._bytes) >= size else 0
        if self._prefix_since is None:
            self._prefix_since = time.monotonic()
        if len(self._bytes) == 1:
            return 1 if time.monotonic() - self._prefix_since >= .035 else 0
        second = self._bytes[1]
        if second in (ord("["), ord("O")):
            for index, byte in enumerate(self._bytes):
                if index >= 2 and 0x40 <= byte <= 0x7e:
                    # Legacy X10 mouse needs its three trailing bytes too.
                    size = index + 4 if second == ord("[") and index == 2 and byte == ord("M") else index + 1
                    return size if len(self._bytes) >= size else 0
            if len(self._bytes) > 1024:
                self._bytes.clear()
                self._prefix_since = None
            return 0
        if second in (ord("P"), ord("_"), ord("]")):
            data = bytes(self._bytes)
            end = data.find(b"\x1b\\", 2)
            return end + 2 if end >= 0 else 0
        size = 4 if second >= 0xF0 else 3 if second >= 0xE0 else 2 if second >= 0xC0 else 1
        return size + 1 if len(self._bytes) >= size + 1 else 0

    def read_byte(self) -> int:
        with self._condition:
            self._packet_remaining = max(0, self._packet_remaining - 1)
            return self._bytes.popleft() if self._bytes else -1

    def unread(self, byte: int) -> None:
        with self._condition:
            self._bytes.appendleft(byte)
            self._packet_remaining += 1
            self._condition.notify_all()

    def stop(self) -> None:
        with self._condition:
            self._running = False
            self._condition.notify_all()
        reader = self._thread
        if reader is not None and reader.is_alive() and os.name == "nt":
            _cancel_console_read(reader)
        self._backend.stop()
        if reader is not None:
            reader.join(timeout=0.5)
        self._thread = None


def _cancel_console_read(reader: threading.Thread) -> None:
    """Cancel the reader's synchronous ReadFile without injecting fake keys."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.CancelSynchronousIo.argtypes = [wintypes.HANDLE]
    kernel.CancelSynchronousIo.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenThread(0x0001, False, reader.native_id)  # THREAD_TERMINATE
    if handle:
        try:
            kernel.CancelSynchronousIo(handle)
        finally:
            kernel.CloseHandle(handle)


#: How long the size has to hold still before the renderer is told. Matches
#: ``event_loop._RESIZE_DEBOUNCE``, which is what the Unix path uses.
RESIZE_SETTLE_SECONDS = 0.10


def _settled_resize() -> None:
    """Give ``EventLoop`` the resize settling its Unix path already has.

    The original handler is left doing the work -- it re-reads the terminal size
    when it finally runs, so a drag that ends somewhere new is still measured
    correctly. All this adds is the waiting, and the re-check that keeps the
    wait alive while the size is still moving.
    """
    import shutil

    from opentui.input import event_loop

    if os.name != "nt":
        return
    original = event_loop.EventLoop._handle_resize

    def _handle_resize(self) -> None:
        self._resize_pending = True
        self._last_resize_time = time.perf_counter()
        if getattr(self, "_settle_installed", False):
            return
        self._settle_installed = True

        def flush(_delta: float) -> None:
            if not self._resize_pending:
                return
            # Still moving: restart the wait instead of landing on a size the
            # user has already dragged past.
            if shutil.get_terminal_size() != self._last_term_size:
                self._last_resize_time = time.perf_counter()
                return
            if time.perf_counter() - self._last_resize_time < RESIZE_SETTLE_SECONDS:
                return
            self._resize_pending = False
            original(self)

        self.on_frame(flush)

    event_loop.EventLoop._handle_resize = _handle_resize


@contextmanager
def terminal_session():
    """Install the app-local terminal behaviour for this renderer session only.

    Wraps input reads, settles resize, and says plainly what the renderer was
    asked for. Every change is undone on the way out, so a second render in the
    same process starts from the library's own behaviour again.
    """
    from opentui.input import _backend
    from opentui.input import event_loop

    if os.name == "nt":
        from opentui.input._backend_windows import WindowsBackend

    original_create = _backend.create_backend
    original_handler = event_loop.InputHandler
    original_resize = event_loop.EventLoop._handle_resize

    def create_backend():
        backend = original_create()
        return BufferedInputBackend(backend) if isinstance(backend, WindowsBackend) else backend

    if os.name == "nt":
        _backend.create_backend = create_backend
        _settled_resize()
    event_loop.InputHandler = ResponsiveInputHandler
    try:
        yield
    finally:
        _backend.create_backend = original_create
        event_loop.InputHandler = original_handler
        event_loop.EventLoop._handle_resize = original_resize


#: The old name, kept because a test and a caller still spell it this way.
nonblocking_terminal_input = terminal_session


#: What the renderer is told to do, stated instead of inferred.
#:
#: ``use_mouse`` defaults to "enable when the tree has mouse handlers", which
#: is a guess made once, before a screen is necessarily mounted. Left to it, a
#: wheel event nobody handled scrolls the *terminal* -- the window moves under
#: the drawing and the drawing no longer lines up with anything. Asking for it
#: outright means the wheel belongs to the list. ``use_alternate_screen`` is
#: already the default and is spelled out for the same reason: it is what puts
#: the session on the alternate screen, so nothing the app draws can end up in
#: the terminal's scrollback.
def renderer_config() -> dict:
    return {"use_alternate_screen": True, "use_mouse": True}
