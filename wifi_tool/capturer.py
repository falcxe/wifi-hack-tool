"""Handshake/PMKID capture backends.

No external capture tool can be assumed to be installed, so the backend is
pluggable and discovered at runtime:

* ``cap80211`` -- the NDIS monitor-mode driver tool (most capable on Windows).
* ``tshark``   -- Npcap in raw 802.11 monitor mode, if Wireshark is installed.

Command templates are overridable via ``assets/capture.json`` so a backend can
be corrected without touching code. Each backend can be probed with
``probe_help()`` to show the real usage text of the installed binary.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List

from . import hc22000
from .processes import terminate as _terminate

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
CONFIG_PATH = ASSETS_DIR / "capture.json"

# Defaults. Placeholders: {iface} {out} {duration} {bssid} {channel}
DEFAULT_BACKENDS: dict[str, dict] = {
    "cap80211": {
        "title": "cap80211 (драйвер монитора)",
        "probe": "netcap80211.exe",
        "args": ["-i", "{iface}", "-f", "{out}"],
        "captures_80211": True,
        "needs_channel": True,
    },
    # ``-a duration:{duration}`` is what makes this backend honest: tshark stops
    # on its own schedule, runs its exit path and closes the savefile. It was
    # missing, so the only way out was killing it -- and a killed tshark cannot
    # flush, so the last packets stayed in its buffer and vanished. A handshake
    # is a few kilobytes; that is the whole capture, not a tail of it.
    "tshark": {
        "title": "tshark (Npcap, raw 802.11)",
        "probe": "tshark.exe",
        "args": ["-i", "{iface}", "-I", "-a", "duration:{duration}", "-w", "{out}"],
        "captures_80211": True,
        "needs_channel": False,
        # tshark has no channel option: the radio is tuned by the driver, so the
        # capture loop does it through Npcap's helper instead -- but a backend
        # that *can* take ``{channel}`` is set here and left to do it itself.
    },
}


class CaptureError(RuntimeError):
    """Raised when capture cannot be started or failed."""


@dataclass
class Interface:
    index: int
    name: str
    description: str = ""
    capture_id: str = ""


@dataclass
class Backend:
    key: str
    title: str
    exe: Path | None
    args: List[str] = field(default_factory=list)
    captures_80211: bool = True
    needs_channel: bool = False

    @property
    def available(self) -> bool:
        return self.exe is not None and Path(self.exe).exists()


def _load_overrides() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CaptureError(f"не удалось прочитать {CONFIG_PATH}: {exc}") from exc
    if not isinstance(data, dict):
        raise CaptureError(f"{CONFIG_PATH}: ожидался JSON-объект")
    return data


def discover_backends() -> List[Backend]:
    """Return every known capture backend, marking which ones are installed."""
    overrides = _load_overrides()
    backends: List[Backend] = []
    for key, spec in DEFAULT_BACKENDS.items():
        merged = {**spec, **(overrides.get(key) or {})}
        probe = merged.get("probe") or ""
        exe = _find_exe(probe)
        backends.append(
            Backend(
                key=key,
                title=merged.get("title", key),
                exe=exe,
                args=list(merged.get("args", [])),
                captures_80211=bool(merged.get("captures_80211", True)),
                needs_channel=bool(merged.get("needs_channel", False)),
            )
        )
    return backends


def first_available_backend() -> Backend | None:
    for backend in discover_backends():
        if backend.available:
            return backend
    return None


def _find_exe(name: str) -> Path | None:
    """Look in assets/ first, then next to known install dirs, then on PATH."""
    if not name:
        return None
    local = ASSETS_DIR / name
    if local.exists():
        return local
    import shutil

    found = shutil.which(name) or shutil.which(Path(name).stem)
    if found:
        return Path(found)
    # common install locations not always on PATH
    guesses = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / name,
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Wireshark"
        / name,
    ]
    for g in guesses:
        if g.exists():
            return g
    return None


# ---------------------------------------------------------------------------
# interfaces
# ---------------------------------------------------------------------------

# ``netsh interface ipv4 show interfaces`` columns (labels are localized, the
# shape is not): index, metric, MTU, state, name. Both English and Russian
# states are single words, so a non-space token matches either.
_IFACE_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S.*?)\s*$")


def list_interfaces() -> List[Interface]:
    """List IPv4 interfaces with their netsh index, state and alias."""
    try:
        proc = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "interfaces"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    out: List[Interface] = []
    for line in (proc.stdout or "").splitlines():
        m = _IFACE_RE.match(line)
        if m:
            out.append(
                Interface(index=int(m.group(1)), name=m.group(5), description=m.group(4))
            )
    return out


def resolve_interface(backend: Backend, iface: Interface) -> Interface:
    """Map a Windows interface to tshark's stable Npcap device identifier.

    Windows interface indexes and tshark -D indexes are unrelated; passing a
    netsh index to tshark can select a different adapter or an extcap helper.

    Idempotent: an interface that already carries a device id has been through
    here, and asking Npcap again would cost another ``tshark -D`` for nothing.
    """
    if backend.key != "tshark" or iface.capture_id:
        return iface
    try:
        proc = subprocess.run([str(backend.exe), "-D"], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError(f"не удалось получить список интерфейсов tshark: {exc}") from exc
    if proc.returncode != 0:
        raise CaptureError((proc.stderr or "").strip() or "tshark не выдал список интерфейсов")
    suffix = f"({iface.name})".casefold()
    for line in (proc.stdout or "").splitlines():
        match = re.match(r"^\s*\d+\.\s+(\\Device\\NPF_\{[^}]+\})\s+", line, re.IGNORECASE)
        if match and line.rstrip().casefold().endswith(suffix):
            return Interface(iface.index, iface.name, iface.description, match.group(1))
    raise CaptureError(f"tshark не видит Wi-Fi интерфейс «{iface.name}». Проверь установку Npcap.")


def _npcap_dot11_enabled() -> bool | None:
    """Read the installed optional feature; never change the driver registry."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as key:
            value, _ = winreg.QueryValueEx(key, "Dot11Support")
        return bool(int(value))
    except (ImportError, OSError, ValueError, TypeError):
        return None


def _wlan_helper() -> Path:
    """Npcap's helper, the tool that switches an adapter into monitor mode."""
    return (Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap"
            / "WlanHelper.exe")


def _helper_run(guid: str, *args: str) -> subprocess.CompletedProcess | None:
    """Run WlanHelper for one interface, or None if it could not be run."""
    try:
        return subprocess.run([str(_wlan_helper()), guid, *args], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _iface_guid(iface: Interface) -> str | None:
    """The Npcap interface GUID behind an ``\\Device\\NPF_{...}`` id."""
    match = re.search(r"\{([^}]+)\}", iface.capture_id or "")
    return match.group(1) if match else None


def current_mode(iface: Interface) -> str:
    """The adapter's current 802.11 mode, or ``""`` if it cannot be read."""
    guid = _iface_guid(iface)
    if guid is None or not _wlan_helper().is_file():
        return ""
    proc = _helper_run(guid, "mode")
    if proc is None or proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip().splitlines()[0].strip().lower() if proc.stdout else ""


def set_monitor_channel(iface: Interface, channel: int) -> str:
    """Put the adapter on ``channel``; ``""`` when it took or there is no way to.

    Npcap's helper can only set a channel while the adapter is in monitor mode,
    which is the mode the capture runs in and not the one it is in beforehand --
    so the caller switches modes first and then asks for this.

    The value is read back instead of assumed. A card that quietly stayed on the
    channel it was left on is the whole difference between a capture that catches
    a handshake in ten seconds and one that catches nothing in five minutes, and
    from outside the two are the same silence. Anything other than the requested
    channel comes back as text naming both numbers, because "the adapter was on
    channel 1 while the network was on 6" is the single most useful thing this
    function can say.
    """
    guid = _iface_guid(iface)
    if guid is None or not _wlan_helper().is_file():
        return ""
    # WlanHelper's `channel` only goes up to 14, which is the whole 2.4 GHz
    # band; everything above is a 5 GHz channel and has to be asked for as a
    # frequency (ch 36 = 5180). Passing 36 to `channel` would be refused by the
    # driver, and a target on 5 GHz is exactly the target that gets missed.
    setting = ("channel", str(channel)) if 1 <= channel <= 14 else (
        "freq", str(5000 + 5 * channel))
    proc = _helper_run(guid, *setting)
    if proc is None or proc.returncode != 0:
        detail = ""
        if proc is not None:
            lines = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
            detail = lines[-1] if lines else f"код {proc.returncode}"
        return f"не удалось переключить адаптер на канал {channel}" + (f" ({detail})" if detail else "")
    check = _helper_run(guid, *setting[:1])
    if check is not None and check.returncode == 0:
        got = (check.stdout or "").strip().splitlines()
        if got and got[0].strip().isdigit():
            now = int(got[0].strip())
            if now != int(setting[1]):
                return (f"адаптер остался на {setting[0]}={now} вместо "
                        f"{setting[1]} — сеть на канале {channel}, "
                        f"рукопожатий здесь не будет")
    return ""


def _wireless_modes(iface: Interface) -> tuple[str, ...] | None:
    """Ask Npcap's helper for supported modes, without switching modes."""
    helper = _wlan_helper()
    guid = re.search(r"\{([^}]+)\}", iface.capture_id)
    if not helper.is_file() or guid is None:
        return None
    proc = _helper_run(guid.group(1), "modes")
    if proc is None:
        return None
    modes = tuple(part.strip().lower() for part in (proc.stdout or "").strip().split(","))
    known = {"managed", "monitor", "master", "wfd_device", "wfd_owner", "wfd_client"}
    return modes if proc.returncode == 0 and modes and set(modes) <= known else None


#: Netsh interface names that belong to a wireless adapter (RU + EN).
_WIRELESS_NEEDLES = ("wi-fi", "wifi", "wlan", "беспровод", "wireless")


def wireless_interface() -> Interface | None:
    """The first wireless adapter netsh reports, or None."""
    for iface in list_interfaces():
        if any(needle in iface.name.lower() for needle in _WIRELESS_NEEDLES):
            return iface
    return None


def restore_managed_mode(iface: Interface | None = None) -> str:
    """Put the adapter back into managed mode; ``""`` when there was nothing to do.

    A capture runs against an adapter switched into raw 802.11, and only the
    capture tool's own exit path switches it back. Two ways out of a capture skip
    that path -- a backend that was asked to stop by the user, and one stopped
    early because the handshake had already been read off the file -- and both
    leave the stick unable to do anything: ``netsh wlan show networks`` lists no
    networks at all, the interface looks merely "disconnected", and the adapter
    comes back only when it is unplugged and plugged in again, because that is
    the other event that resets the mode. To the user that reads as a dead
    adapter, and to the next run as "no networks found", with nothing in between
    to say a capture is what did it.

    So it is put back here, every time a capture ends, by whichever of the two
    tools is present: Npcap's WlanHelper, which is what switched the adapter,
    and netsh, which is all there is when the capture ran on another backend.
    A refusal comes back as text instead of being raised -- the capture itself
    succeeded, and failing to tidy up afterwards must not throw away the
    handshake that was just caught.
    """
    if iface is None:
        iface = wireless_interface()
    if iface is None:
        return ""

    guid = re.search(r"\{([^}]+)\}", iface.capture_id or "")
    helper = _wlan_helper()
    if guid is not None and helper.is_file():
        try:
            proc = subprocess.run([str(helper), guid.group(1), "mode", "managed"],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            proc = None
        if proc is not None and proc.returncode == 0:
            return ""

    # The quotes are part of the argument on purpose: netsh splits its own
    # command line on spaces, so an adapter called "Wi-Fi 2" would otherwise
    # arrive as the name "Wi-Fi" followed by a stray word.
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "set", "interface", f'name="{iface.name}"', "mode=managed"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (f"Не удалось вернуть адаптер «{iface.name}» в обычный режим: {exc}. "
                "Переподключи адаптер по USB.")
    if proc.returncode == 0:
        return ""

    detail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
    reason = detail[-1] if detail else f"код {proc.returncode}"
    return (
        f"Не удалось вернуть адаптер «{iface.name}» в обычный режим ({reason}). "
        "До переподключения адаптера по USB сканировать сети он не сможет."
    )


def monitor_capable(backend: Backend, iface: Interface) -> bool:
    """Whether this adapter can be captured on at all, as far as it can be told.

    ``True`` when nobody can say otherwise. An adapter whose modes Npcap will not
    report is not thereby disqualified -- that answer belongs to
    :func:`check_monitor_support`, which actually opens the radio, and the point
    of this function is only to keep the selection step from walking past a
    perfectly good adapter just because a query came back empty.
    """
    if backend.key != "tshark":
        return True
    modes = _wireless_modes(resolve_interface(backend, iface))
    return modes is None or "monitor" in modes


def check_monitor_support(backend: Backend, iface: Interface) -> None:
    """Check tshark's raw 802.11 link types without recording any packets."""
    if backend.key != "tshark":
        return
    if _npcap_dot11_enabled() is False:
        raise CaptureError(
            "Npcap: поддержка raw 802.11 выключена.\n"
            "Переустанови Npcap с галочкой «Support raw 802.11 traffic (and monitor mode)»."
        )
    modes = _wireless_modes(iface)
    if modes is not None and "monitor" not in modes:
        raise CaptureError(
            "Текущий драйвер Wi-Fi не поддерживает режим монитора "
            f"(доступно: {', '.join(modes)}).\n"
            "Выбери источник «Файл захвата» или используй адаптер/драйвер с поддержкой monitor."
        )
    try:
        proc = subprocess.run([str(backend.exe), "-i", iface.capture_id or str(iface.index), "-I", "-L"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError(f"не удалось проверить режим монитора: {exc}") from exc
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        detail = output.strip().splitlines()
        raise CaptureError("tshark не смог открыть режим монитора: " +
                           (detail[0] if detail else f"код {proc.returncode}"))
    if not re.search(r"\b(?:IEEE802_11\w*|RADIOTAP|PRISM_HEADER)\b", output, re.IGNORECASE):
        raise CaptureError("Драйвер не предоставил raw 802.11 в режиме монитора. Используй готовый файл захвата.")


def probe_help(backend: Backend, timeout: float = 10.0) -> str:
    """Return the backend binary's usage text (empty if it prints nothing)."""
    if not backend.available:
        return ""
    exe = Path(backend.exe)
    for flag in ("--help", "-h", "/?", "-?"):
        try:
            proc = subprocess.run(
                [str(exe), flag],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        text = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if text:
            return text
    return ""


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------


def build_command(
    backend: Backend,
    iface: Interface,
    out_path: Path,
    duration: int,
    bssid: str | None,
    channel: int | None,
) -> list[str]:
    subs = {
        "iface": iface.capture_id or str(iface.index),
        "ifname": iface.name,
        "out": str(out_path),
        "duration": str(duration),
        "bssid": bssid or "",
        "channel": str(channel or ""),
    }
    cmd = [str(backend.exe)]
    for arg in backend.args:
        try:
            cmd.append(arg.format(**subs))
        except (KeyError, IndexError):
            cmd.append(arg)
    return cmd


async def capture(
    backend: Backend,
    iface: Interface,
    out_path: str | Path,
    *,
    duration: int = 60,
    bssid: str | None = None,
    channel: int | None = None,
    on_log: Callable[[str], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    verify: Callable[[Path], bool] | None = None,
    scan_interval: float = 2.0,
    kick: Callable[[], None] | None = None,
) -> Path:
    """Run ``backend`` until it stops, the duration elapses, or we cancel.

    Async so output is consumed without blocking the UI's event loop.

    ``on_progress(seconds_left, bytes_written)`` is called about twice a second so
    a UI can show a countdown. Without it the capture is a silent 60 seconds --
    which reads as a hang, and is the reason people press Esc on a process that
    was working perfectly well.

    Whichever way the run ends, the backend is asked to stop the way a program
    stops rather than the way a process is killed, and the file it left behind is
    checked before it is called a capture. Both matter: an un-flushed file is
    read as a capture that saw no handshake, which is the one conclusion that
    sends the user off to wait for someone else to reconnect.

    ``duration`` is a ceiling, not a schedule: with ``verify`` supplied the run
    ends the moment the file holds a handshake worth having, so a patient limit
    costs nothing when the handshake is quick. That is the whole point of a
    long window -- nobody has to sit through five minutes of waiting when the
    answer arrived in the first ten seconds, and nobody has to guess whether
    five minutes is enough. Without ``verify`` the capture runs its full length.

    ``verify(path) -> bool`` is asked only after new EAPOL-Key traffic has
    actually appeared, never on a timer, and it is called off the event loop:
    the check is a full conversion of the capture so far, and "some EAPOL
    arrived" is a weaker statement than "hashcat now has a record to check
    passwords against" -- stopping on the first one can end the capture holding
    a lone message 1, which pairs with nothing and cracks nothing.

    ``kick()`` is called once, after the adapter is on the target's channel and
    before any progress is reported: it starts whatever makes the network send
    the handshake -- a deauthentication burst -- which is only worth doing once
    the radio is pointed at the right frequency.
    """
    if not backend.available:
        raise CaptureError(f"{backend.title}: исполняемый файл не найден")

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = build_command(backend, iface, out_path, duration, bssid, channel)

    def log(line: str) -> None:
        if on_log:
            on_log(line)

    log("$ " + " ".join(cmd))
    proc = await _spawn(cmd, backend.title)

    if channel and not any("{channel}" in arg for arg in backend.args):
        # The target's channel was asked for and no backend was given a way to
        # use it. This is the quiet failure behind "the stick almost never sees a
        # handshake": a monitor-mode adapter listens on whatever channel it was
        # left on, so a capture aimed at channel 6 while the card sits on 1
        # records five minutes of an empty band and reports no networks.
        await _retune(iface, channel, backend, log)

    if kick is not None:
        # Only now. A deauthentication sent before the retune went out on
        # whatever channel the adapter was left on, and a frame on an empty
        # channel knocks nobody over -- so the capture would have waited the
        # full window for a reaction that was never asked for.
        kick()

    started = time.monotonic()
    cancelled = False
    last_tick = 0.0
    # Where the last signature search stopped, so each one reads only what the
    # backend has appended since.
    scanned = 0
    next_scan = started + max(0.5, scan_interval)
    reminded = False
    assert proc.stdout is not None

    async def enough(check: Callable[[Path], bool]) -> bool:
        """Whether the capture on disk is already worth stopping for."""
        nonlocal scanned
        offset = hc22000.first_key_frame(out_path, scanned)
        if offset is None:
            size = out_path.stat().st_size if out_path.exists() else 0
            scanned = max(scanned, size)
            return False
        # New EAPOL since the last look. A file the backend is still writing can
        # be cut mid-frame, so a parse failure here is not a failure to judge:
        # it simply is not enough yet.
        if await asyncio.to_thread(check, out_path):
            return True
        scanned = offset + len(hc22000.EAPOL_KEY_SIGNATURE)
        return False

    try:
        while True:
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
            except asyncio.TimeoutError:
                raw = b""
            now = time.monotonic()
            if raw:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line:
                    log(line)
            elif proc.returncode is not None:
                break
            elif proc.stdout.at_eof():
                await asyncio.sleep(0.05)

            if on_progress is not None and now - last_tick >= 0.5:
                last_tick = now
                size = out_path.stat().st_size if out_path.exists() else 0
                on_progress(max(0, int(duration - (now - started))), size)

            if verify is not None and now >= next_scan:
                next_scan = now + max(0.5, scan_interval)
                if await enough(verify):
                    log("[рукопожатие получено — запись можно завершать]")
                    break

            if not reminded and duration >= 120 and now - started >= 15:
                # The single thing that most raises the odds during a long
                # window, said once instead of every tick: a handshake only
                # happens when a client associates, and the user usually has
                # such a client to hand.
                reminded = True
                log("[подсказка] переподключи телефон или ноутбук к этой сети — "
                    "обмен EAPOL пойдёт сам")

            if should_stop is not None and should_stop():
                cancelled = True
                log("[захват остановлен]")
                break
            if now - started > duration:
                log(f"[захват завершён по таймауту {duration} с]")
                # The backend was told the same limit up front, so it should be
                # on its way out and about to close the file. Give it that time
                # rather than cutting it off: whatever it has not written yet is
                # still in its buffer.
                if proc.returncode is None:
                    log("[ждём, пока инструмент допишет файл]")
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(proc.wait(), timeout=_FLUSH_GRACE)
                break
    finally:
        await _terminate(proc)

    # Every exit from here -- self-terminated backend, cancelled run, or a
    # handshake found early enough to stop on -- leaves the adapter in the mode
    # the backend asked for. Only the backend's own exit path gives it back, and
    # the two ways that skip that path are exactly the ones that leave a stick
    # that cannot scan until it is unplugged.
    problem = await asyncio.to_thread(restore_managed_mode, iface)
    if problem:
        log(f"[внимание] {problem}")

    if cancelled:
        raise CaptureError("захват отменён")
    await _verify_capture_file(out_path, backend)
    log(f"[захват сохранён: {out_path} ({out_path.stat().st_size} байт)]")
    return out_path


#: How long a capture tool is given to finish writing after the timer expires.
_FLUSH_GRACE = 5.0


async def _retune(iface: Interface, channel: int, backend: Backend,
                  log: Callable[[str], None]) -> None:
    """Move the adapter onto the target's channel, and say what happened.

    Two backends can do it without help: a tool whose command line carries
    ``{channel}`` handles it itself, and that is checked before this is called.
    For the rest the only lever is Npcap's helper, and it has one ordering
    requirement -- a channel can only be set while the adapter is in monitor mode
    -- so the capture is started first and the switch is waited for. Asking
    before tshark has finished switching would be refused by the driver, and
    asking once and never checking would leave the adapter on the wrong channel
    with nothing in the log to say so.
    """
    if backend.key != "tshark" and not _iface_guid(iface):
        log(f"[канал] {backend.title} не умеет переключать канал сам — "
            f"сеть на {channel}, адаптер останется на текущем")
        return
    mode = await asyncio.to_thread(current_mode, iface)
    deadline = time.monotonic() + _MONITOR_WAIT
    while mode and mode != "monitor" and time.monotonic() < deadline:
        await asyncio.sleep(0.25)
        mode = await asyncio.to_thread(current_mode, iface)
    if mode and mode != "monitor":
        log(f"[внимание] адаптер не перешёл в режим монитора (сейчас «{mode}») — "
            f"канал {channel} может не установиться")
    note = await asyncio.to_thread(set_monitor_channel, iface, channel)
    log(f"[внимание] {note}" if note else f"[канал] адаптер на канале {channel}")


#: How long to wait for a backend to switch the adapter into monitor mode before
#: asking for a channel the driver would only accept in that mode.
_MONITOR_WAIT = 6.0


async def _spawn(cmd: list[str], title: str) -> asyncio.subprocess.Process:
    """Start the backend, reporting a launch failure the way a launch fails."""
    try:
        return await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL,
        )
    except OSError as exc:
        raise CaptureError(f"не удалось запустить {title}: {exc}") from exc


async def _verify_capture_file(out_path: Path, backend: Backend) -> None:
    """Refuse to call it a capture unless it is one.

    Existence and a non-zero size are not enough. A backend that gives up
    mid-run can leave a small file of plain text where the packets should be
    (``ERR: File is too big``), which passes both checks and then converts to
    nothing at all -- reported moments later as a network where nobody
    reconnected. Checked here, where the backend's own name and usage text are
    still in hand.
    """
    if not out_path.exists() or out_path.stat().st_size == 0:
        help_text = await asyncio.to_thread(probe_help, backend)
        detail = help_text.splitlines()[0] if help_text else ""
        raise CaptureError(_no_capture_message(out_path, backend, detail))

    try:
        with out_path.open("rb") as fh:
            head = fh.read(64)
    except OSError as exc:
        raise CaptureError(_no_capture_message(out_path, backend, str(exc))) from exc

    text = hc22000.text_payload(head)
    if text:
        raise CaptureError(
            _no_capture_message(out_path, backend, f"вместо пакетов в файле текст: {text!r}")
        )


def _no_capture_message(out_path: Path, backend: Backend, detail: str) -> str:
    size = out_path.stat().st_size if out_path.exists() else 0
    message = f"{backend.title} не создал файл захвата."
    if detail:
        message += f" Причина: {detail}."
    message += (
        f"\nПроверен файл {out_path.name} ({size} байт). "
        "Если рукопожатие было в эфире, оно потеряно при записи — повтори захват."
    )
    return message


def setup_hint() -> str:
    """Human-readable instructions for installing a capture backend."""
    return (
        "Не найден ни один инструмент захвата.\n\n"
        "Вариант 1 -- cap80211 (надёжнее всего на Windows):\n"
        "  Скачай cap80211, распакуй и положи в папку assets рядом с wifi_tool:\n"
        "    assets\\netcap80211.exe\n\n"
        "Вариант 2 -- Wireshark с Npcap:\n"
        "  Установи Wireshark и при установке включи\n"
        "  \"Support raw 802.11 traffic (and monitor mode)\",\n"
        "  затем добавь папку Wireshark в PATH.\n\n"
        "Если команда запуска отличается, опиши её в assets\\capture.json:\n"
        '  { "cap80211": { "args": ["-i", "{iface}", "-f", "{out}"] } }'
    )
