"""Conversion backends: capture file -> hashcat mode 22000.

Two backends, in priority order:

1. **wpawolf** (``https://github.com/StrongWind1/WPAWolf``) -- a pure-Rust
   rewrite of ``hcxpcapngtool`` that ships Windows binaries. Preferred when
   installed, because it is far more complete than the built-in fallback
   (A-MSDU walking, fragment reassembly, cross-file pairing, FCS recovery).
2. **builtin** -- :mod:`wifi_tool.hc22000`, the dependency-free Python
   converter. Always available, so the tool works with nothing installed.

``hcxpcapngtool`` from ZerBea/hcxtools is deliberately *not* used: its README
states "Unsupported: Windows OS", and it is the piece we need on Windows.

Note on wpawolf flags: ``--strict`` is documented upstream as dropping
thousands of crackable MICs, so we pass ``--smart`` instead (a reduction
option that never loses a hash) plus the ESSID list for diagnostics.
"""
from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from . import hc22000
from .options import normalize_bssid
from .processes import terminate

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"

# Candidate binary names across the MSVC and GNU Windows release assets.
WPAWOLF_NAMES = (
    "wpawolf.exe",
    "wpawolf-windows-x86_64.exe",
    "wpawolf-x86_64-pc-windows-msvc.exe",
)


class ConversionError(RuntimeError):
    """Raised when a capture could not be converted into hashes."""


class ConversionCancelled(ConversionError):
    """A requested stop must not fall back to another conversion backend."""


@dataclass
class Result:
    """Outcome of a conversion, independent of which backend produced it."""

    path: Path
    report: hc22000.ConversionReport
    backend: str


def find_wpawolf() -> Optional[Path]:
    """Locate wpawolf.exe in assets/ or on PATH."""
    for name in WPAWOLF_NAMES:
        local = ASSETS_DIR / name
        if local.exists():
            return local
    for name in WPAWOLF_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def preferred_backend() -> str:
    """``"wpawolf"`` when available, else ``"builtin"``."""
    return "wpawolf" if find_wpawolf() else "builtin"


async def convert(
    capture: str | Path,
    out_path: str | Path,
    bssid: str | None = None,
    *,
    prefer: str | None = None,
    essid_hint: str = "",
    essid: str | None = None,
    on_log=None,
    should_stop=None,
) -> Result:
    """Convert ``capture`` into an hc22000 file, using the best available backend."""
    capture = Path(capture)
    out_path = Path(out_path)
    if should_stop is not None and should_stop():
        raise ConversionCancelled("Конвертация отменена")
    if bssid:
        try:
            bssid = normalize_bssid(bssid)
        except ValueError as exc:
            raise ConversionError(str(exc)) from exc
    # Checked before any backend runs, but after the .22000 branch: a hash file
    # is text by design and would be rejected as unreadable, and a backend that
    # gives up mid-run only tells you so through the file it left behind.
    if capture.suffix.lower() in (".22000", ".hc22000"):
        report = await asyncio.to_thread(_report_from_file, capture, bssid, None, 0, essid)
        if should_stop is not None and should_stop():
            raise ConversionCancelled("Конвертация отменена")
        out_path.write_text("\n".join(report.pmkid + report.eapol) + "\n", encoding="utf-8")
        return Result(path=out_path, report=report, backend="hashfile")
    _reject_unreadable(capture)
    backend = prefer or preferred_backend()

    if backend == "wpawolf":
        exe = find_wpawolf()
        if exe:
            try:
                return await _wpawolf(exe, capture, out_path, bssid, on_log,
                                      should_stop=should_stop, essid=essid)
            except ConversionCancelled:
                raise
            except ConversionError:
                if prefer == "wpawolf":
                    raise  # explicit request: do not silently degrade
                if on_log:
                    on_log("wpawolf не справился, переключаюсь на встроенный конвертер")
        elif prefer == "wpawolf":
            raise ConversionError("wpawolf не найден (assets/wpawolf.exe)")

    if should_stop is not None and should_stop():
        raise ConversionCancelled("Конвертация отменена")
    try:
        report = await asyncio.to_thread(hc22000.convert, capture, out_path, bssid,
                                          should_stop=should_stop,
                                          essid_hint=essid_hint, essid_filter=essid)
    except InterruptedError as exc:
        raise ConversionCancelled("Конвертация отменена") from exc
    except hc22000.CaptureFormatError as exc:
        raise ConversionError(f"Файл не читается как захват: {exc}") from exc
    return Result(path=out_path, report=report, backend="builtin")


def _reject_unreadable(capture: Path) -> None:
    """Fail with the file's own explanation when it is not a capture.

    Capture backends that give up mid-run write their error message into the
    output file instead of packets, so what arrives here is often a small file
    of plain text. Run through either backend that reads as "no hashes found",
    and the user is told to wait longer for someone to reconnect -- advice that
    sends them away from the real fault, which is the file, not the network.
    """
    try:
        for _ in hc22000.iter_frames(capture):
            return  # the first frame parsed: the file is a capture
    except hc22000.CaptureFormatError as exc:
        raise ConversionError(f"Файл не читается как захват: {exc}") from exc
    except OSError as exc:
        raise ConversionError(f"не удалось прочитать {capture.name}: {exc}") from exc


async def _wpawolf(
    exe: Path,
    capture: Path,
    out_path: Path,
    bssid: str | None,
    on_log,
    *,
    should_stop=None,
    essid: str | None = None,
    timeout: float = 120.0,
) -> Result:
    """Run wpawolf, then read its output back into a ConversionReport."""
    essid_file = out_path.with_suffix(".essid.txt")
    cmd = [
        str(exe),
        "--smart",
        "--22000-out",
        str(out_path),
        "-E",
        str(essid_file),
        str(capture),
    ]
    if on_log:
        on_log("$ " + " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL,
        )
    except OSError as exc:
        raise ConversionError(f"не удалось запустить wpawolf: {exc}") from exc

    lines: List[str] = []
    assert proc.stdout is not None
    started = time.monotonic()
    try:
        while True:
            if should_stop is not None and should_stop():
                raise ConversionCancelled("Конвертация отменена")
            if time.monotonic() - started >= timeout:
                raise ConversionError("wpawolf превысил лимит времени конвертации")
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if not raw:
                if proc.returncode is not None:
                    break
                await asyncio.sleep(0.05)
                continue
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line:
                lines.append(line)
                del lines[:-200]
                if on_log:
                    on_log(line)
        rc = await proc.wait()
    finally:
        await terminate(proc)

    if rc != 0 or not out_path.exists():
        detail = lines[-1] if lines else f"код возврата {rc}"
        raise ConversionError(f"wpawolf не создал файл хэшей: {detail}")

    report = _report_from_file(out_path, bssid, essid_file, len(lines), essid)
    # Restrict the file itself too: otherwise hashcat still sees every AP even
    # when the UI's report describes just the selected one.
    if bssid or essid:
        out_path.write_text("\n".join(report.pmkid + report.eapol) + "\n", encoding="utf-8")
    return Result(path=out_path, report=report, backend="wpawolf")


def _report_from_file(
    hash_file: Path,
    bssid: str | None,
    essid_file: Optional[Path],
    _banner_lines: int,
    essid: str | None = None,
) -> hc22000.ConversionReport:
    """Summarise a wpawolf 22000 file without re-parsing frames.

    ``frames`` / ``dot11_frames`` / ``eapol_frames`` stay at zero: they are
    counters over frames *this* module read, and wpawolf read them. Reporting
    zero here would make the "no hashes in this file" message claim the capture
    held no 802.11 traffic at all, which is a different and wrong conclusion --
    ``external`` is what the summary keys off instead.

    ``essid`` widens the filter to any access point that announced this
    network's name: the WPA key comes from the SSID, so a handshake with the
    other band of the same router verifies the same passwords. A record whose
    own name field is empty never matches -- it says nothing about whose
    network it belongs to.
    """
    pmkid: List[str] = []
    eapol: List[str] = []
    try:
        text = hash_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConversionError(f"не удалось прочитать {hash_file}: {exc}") from exc

    want = normalize_bssid(bssid) if bssid else None
    want_name = essid.encode("utf-8").hex().lower() if essid else ""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("*")
        if len(parts) < 6:
            continue
        if want and parts[3].lower() == want:
            pass
        elif want_name and parts[5].lower() == want_name:
            pass
        elif want or want_name:
            continue
        if line.startswith("WPA*01"):
            pmkid.append(line)
        elif line.startswith("WPA*02"):
            eapol.append(line)

    essids = 0
    if essid_file and essid_file.exists():
        try:
            essids = sum(1 for ln in essid_file.read_text(encoding="utf-8").splitlines() if ln.strip())
        except OSError:
            essids = 0

    return hc22000.ConversionReport(
        pmkid=pmkid, eapol=eapol, essids=essids, external=True
    )


def setup_hint() -> str:
    """How to install the optional, more complete converter."""
    return (
        "Опционально: поставить wpawolf.exe в папку assets/.\n"
        "Windows-сборки лежат в репозитории StrongWind1/WPAWolf (Releases,\n"
        "Windows MSVC/GNU). Он заменяет hcxpcapngtool, который на Windows\n"
        "официально не поддерживается, и вытаскивает больше хэшей, чем\n"
        "встроенный конвертер. Без него всё равно работает встроенный."
    )
