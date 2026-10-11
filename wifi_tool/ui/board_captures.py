"""Browse stored board captures without starting a capture or a password run."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from .. import bruce, hc22000
from ..options import ensure_captures_dir
from . import controller, dialogs, forms, state
from .actions import Action


@dataclass
class StoredCapture:
    name: str
    path: Path | None = None
    report: hc22000.ConversionReport | None = None
    error: str = ""

    @property
    def label(self) -> str:
        name = Path(self.name).stem
        if bruce.bssid_of(self.name) and len(name) > 16:
            name = name[16:]
        if self.error:
            return f"{name} · ошибка чтения"
        return f"{name} · EAPOL {len(self.report.eapol)} · PMKID {len(self.report.pmkid)}"


def read_stored_captures(board, destination: Path) -> list[StoredCapture]:
    """Read every saved file, refreshing local copies the board has changed."""
    destination.mkdir(parents=True, exist_ok=True)
    captures = []
    for entry in board.captures_present():
        capture = StoredCapture(entry.name)
        try:
            if Path(entry.name).name != entry.name or "\\" in entry.name:
                raise bruce.BoardError("плата вернула некорректное имя файла")
            data = board.read_file(entry.path, size=entry.size)
            if entry.size and len(data) != entry.size:
                raise bruce.BoardError(f"получено {len(data)} из {entry.size} байт")
            path = destination / entry.name
            if not path.exists() or path.read_bytes() != data:
                temporary = path.with_name(path.name + ".part")
                temporary.write_bytes(data)
                temporary.replace(path)
            capture.path = path
            capture.report = hc22000.convert(path)
        except (bruce.BoardError, hc22000.CaptureFormatError, OSError) as exc:
            capture.error = str(exc)
        captures.append(capture)
    return captures


def _show_error(message: str) -> None:
    from .widgets import wrap

    width = max(8, min(64, getattr(controller._renderer, "width", 72) - 8))
    dialogs.open_select("Ошибка чтения захвата", [
        *(Action(line, lambda: None, enabled=False) for line in wrap(message, width)),
        Action("Закрыть", lambda: None),
    ], searchable=False)


def _show_capture(capture: StoredCapture) -> None:
    if capture.error:
        _show_error(capture.error)
        return
    report = capture.report
    details = [
        capture.name,
        f"Кадров EAPOL: {report.eapol_frames}",
        f"Пар EAPOL: {len(report.eapol)} · PMKID: {len(report.pmkid)}",
    ]
    if report.truncated:
        details.append("Файл обрезан: " + report.detail)
    dialogs.open_select("Сохранённый захват", [
        *(Action(line, lambda: None, enabled=False) for line in details),
        Action("Открыть параметры", lambda: forms.open_form(capture=str(capture.path)), primary=True),
        Action("Назад к захватам", browse),
    ], searchable=False)


def browse() -> None:
    if controller._board_busy or state.phase.peek() == "crack":
        return
    controller._board_busy = True
    loading = Action("Читаю сохранённые захваты…", lambda: None, enabled=False)
    dialogs.open_select("Захваты с платы", [loading], searchable=False)
    try:
        controller._spawn(_load(loading))
    except Exception:
        controller._board_busy = False
        dialogs.close()
        raise


def _still_loading(loading: Action) -> bool:
    layers = dialogs.stack.peek()
    return bool(layers and any(item is loading for item in layers[-1].items))


async def _load(loading: Action) -> None:
    captures = []
    error = ""
    transfer = asyncio.create_task(asyncio.to_thread(_read_board))
    try:
        captures = await asyncio.shield(transfer)
    except asyncio.CancelledError:
        # The serial reader still owns the port until its blocking read ends.
        # Drain it before allowing another board operation to take the lease.
        await controller._drain(transfer)
        raise
    except Exception as exc:
        error = str(exc) or type(exc).__name__
    finally:
        controller._board_busy = False
    if not _still_loading(loading):
        return
    dialogs.close()
    if error:
        _show_error(error)
        return
    items = [Action(capture.label, lambda capture=capture: _show_capture(capture),
                    description=capture.name, category="Источники") for capture in captures]
    if not items:
        items.append(Action("На плате нет сохранённых файлов захвата", lambda: None, enabled=False))
    items.extend([
        Action("Обновить список", browse),
        Action("Закрыть", lambda: None),
    ])
    dialogs.open_select(f"Захваты с платы ({len(captures)})", items)


def _read_board() -> list[StoredCapture]:
    board = controller._open_board_blocking()
    try:
        if board is None:
            raise bruce.BoardError(controller._board_open_reason())
        return read_stored_captures(board, ensure_captures_dir())
    finally:
        controller._release_board(board)
