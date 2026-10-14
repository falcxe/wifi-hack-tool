"""The one-key ladder: every recovery route, cheapest and most likely first.

WPA2-PBKDF2 cannot be "beaten" -- given a capture and a list of candidates the
answer is always "found" or "not in this list". What decides the odds is *which*
candidates get tested and *in what order*, and that is what this module owns:

1. ``saved``      -- the key Windows already stores for a network this machine has
   joined. Deterministic, no capture, no dictionary, no admin rights.
2. ``targeted``   -- candidates built from the network's own identity (SSID,
   BSSID) plus factory defaults. Home and ISP routers ship with passwords
   generated from exactly these, so a few thousand candidates settle most
   factory-default cases in seconds.
3. ``quick``      -- the 4800 most common Wi-Fi passwords.
4. ``rockyou``    -- 9.6M candidates (~14 s at 684 kH/s on an RTX 4060 Ti).
5. ``mutations``  -- the same list run through hashcat's ``best66`` rules, which
   catches ``Password1``-style variants of words the list already contains.
6. ``digits``     -- bounded brute force over all-digit passwords, the shape that
   dominates what is left in the real world.

The generated candidates are also run through those rules, right after the
generated list itself: a password derived from the network's own name is far
more often a *mutated* one (``MTS_GPON_A3E2!``, ``MyNetWiFi2024``), and those
strings are in neither the generated list nor in RockYou.

Every stage is a separate hashcat run over the same hash file, so a stage cut
short by its time slice costs only its own slice: the budget left over flows into
the next stage instead of being lost. The first success ends the ladder.

Stage weights are relative costs measured in candidates, used only to divide the
time budget -- hashcat does the actual work and reports what it covered.
"""
from __future__ import annotations

import inspect
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Sequence

#: WPA-PSK is 8..63 bytes; anything shorter or longer can never be the answer.
MIN_PSK_BYTES = 8
MAX_PSK_BYTES = 63

#: Upper bound on generated candidates. At ~700 kH/s a quarter million candidates
#: cost well under a second, so the cap costs nothing and keeps the stage's time
#: share meaningful.
MAX_TARGETED = 400_000

_SEPARATORS = re.compile(r"[\s_\-.]+")
_DIGITS_ONLY = re.compile(r"\d+")

#: Factory defaults and admin credentials that ship with consumer and ISP gear.
#: These are the passwords that actually turn up on home networks far more often
#: than anything a leaked-corpus wordlist contains.
_FACTORY_DEFAULTS: tuple[str, ...] = (
    "admin", "password", "12345678", "123456789", "1234567890", "1234567",
    "1234", "00000000", "11111111", "88888888", "87654321", "qwerty123",
    "abc12345", "iloveyou", "monkey", "dragon", "letmein", "shadow", "master",
    "sunshine", "princess", "football", "baseball", "superman", "batman",
    "trustno1", "welcome", "changeme", "default", "internet", "wireless",
    "wireless1", "test1234", "test12345", "test123456", "1q2w3e4r", "qazwsx",
    "zaq12wsx", "asdfghjk", "1qaz2wsx", "zxcvbnm", "password1", "passw0rd",
    "p@ssw0rd", "passwort", "wlan", "wlan1234", "wifi", "wifi1234", "wifi12345",
    "homewifi", "mynet", "mynet123", "internet123", "office", "office1234",
    "guest", "guest1234", "public", "public1234", "router", "router1234",
    "ubnt", "ubnt1234", "tplink", "tplink1234", "netgear", "netgear1234",
    "dlink", "dlink1234", "zyxel1234", "asus1234", "keenth", "meinsm", "hallo",
    "vodafone", "vodafone1", "o2wifi", "telekom", "unitymedia", "ewe1234",
)


def psk_usable(text: str) -> bool:
    """True when ``text`` could be a WPA-PSK at all (8..63 bytes, no padding)."""
    if not text or text != text.strip():
        return False
    raw = text.encode("utf-8", "ignore")
    return MIN_PSK_BYTES <= len(raw) <= MAX_PSK_BYTES


def _bases(network) -> list[str]:
    """Strings the router's own password is plausibly derived from."""
    out: list[str] = []
    ssid = (network.ssid or "").strip()
    if ssid:
        compact = _SEPARATORS.sub("", ssid)
        for form in (compact, compact.lower(), compact.upper()):
            if form and form not in out:
                out.append(form)
    bssid = (network.bssid or "").replace(":", "").replace("-", "").lower()
    if len(bssid) == 12:
        # Sticker passwords are routinely the tail of the MAC, or the whole
        # thing in either case. The 6-char tail is included even though it is
        # too short to be a PSK on its own: combined with digits below it is a
        # very common sticker format.
        for form in (
            bssid[-10:],
            bssid[-8:],
            bssid[-6:],
            bssid,
            bssid.upper(),
            bssid[-6:].upper(),
        ):
            if form not in out:
                out.append(form)
    return out


def _with_numbers(base: str) -> Iterable[str]:
    """``base`` alone, then with 0..9999 appended, then with common years."""
    if not base:
        return ()
    yield base
    yield from (f"{base}{n:04d}" for n in range(10_000))
    yield from (f"{base}{year}" for year in range(2010, 2031))


def candidates_for(network) -> list[str]:
    """Every candidate worth testing first for ``network``, best guess first.

    Ordered by how likely each group is to be the actual password: the SSID
    itself, factory defaults, then SSID/MAC plus digits. The caller feeds the
    result to hashcat, which stops the moment one of them verifies.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value not in seen and psk_usable(value):
            seen.add(value)
            out.append(value)

    bases = _bases(network)
    ssid = (network.ssid or "").strip()
    bssid = (network.bssid or "").replace(":", "").replace("-", "").lower()

    # 1. The name of the network and its stripped forms are the single most
    #    common home-router password.
    for base in bases[:3]:
        add(base)
        add(base + "123")
        add(base + "1234")
    if ssid:
        add(ssid)
        add(ssid.lower())
        add(ssid.upper())
        add(_SEPARATORS.sub("", ssid))

    # 2. Factory defaults and admin credentials.
    for value in _FACTORY_DEFAULTS:
        add(value)

    # 3. Anything built from the SSID or the MAC plus digits.
    for base in bases:
        for value in _with_numbers(base):
            add(value)
            if len(out) >= MAX_TARGETED:
                return out

    # 4. Serial-looking runs of digits and the MAC's own numeric tail, which is
    #    how a lot of ISP labelling machines derive the sticker password.
    if len(bssid) == 12:
        add(str(int(bssid[-8:], 16)))
        add(str(int(bssid[-6:], 16)))
    for match in _DIGITS_ONLY.findall(ssid)[:2]:
        add(match)
        add(match + match)
    return out


def write_candidates(network, path: str | Path) -> tuple[Path, int]:
    """Write :func:`candidates_for` to ``path``; returns the path and count."""
    values = candidates_for(network)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "".join(f"{value}\n" for value in values), encoding="utf-8"
    )
    return target, len(values)


#: Rule files are a few hundred bytes; reading them whole is cheaper than
#: guessing how many mutations best66 performs.
_RULE_CACHE: dict[Path, int] = {}


def _rule_count(rules: Path) -> int:
    """Number of mutation rules, counting ``:`` continuations as their own rule."""
    cached = _RULE_CACHE.get(rules)
    if cached is not None:
        return cached
    try:
        text = rules.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    count = sum(
        1
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and not line.startswith(":")
    )
    _RULE_CACHE[rules] = max(1, count)
    return _RULE_CACHE[rules]


@dataclass(frozen=True)
class Stage:
    """One hashcat run: a wordlist (optionally mutated) or a mask."""

    key: str
    title: str
    wordlist: Path | None = None
    rules: Path | None = None
    mask: str | None = None
    #: Exact candidate count when known; otherwise estimated from the file size.
    count: int | None = None

    def candidates(self) -> float:
        """How many passwords this stage tries, to the best available estimate."""
        if self.count is not None:
            return float(self.count)
        if self.mask is not None:
            return 10.0 ** self.mask.count("?d")
        if self.wordlist is None:
            return 0.0
        try:
            size = self.wordlist.stat().st_size
        except OSError:
            return 0.0
        lines = size / MEAN_CANDIDATE_BYTES
        if self.rules is not None:
            lines *= max(1, _rule_count(self.rules))
        return lines

    def seconds(self, rate: "Rate") -> float:
        """Wall-clock this stage needs at the given throughput."""
        return self.candidates() / max(1.0, rate.hps)


#: Measured on the developer's RTX 4060 Ti: hashcat 7.1.2, mode 22000, pure
#: kernel, no optimised m22000 kernel available -- 684.5 kH/s. Only used to slice
#: the time budget; a wrong guess costs a badly sized slice, never a wrong answer.
DEFAULT_HPS = 684_500.0

#: Mean bytes per candidate line, from the shipped dictionaries: rockyou-wpa.txt
#: is 104 401 920 bytes over 9 609 471 lines = 10.9, probable-wpa.txt 9.4.
MEAN_CANDIDATE_BYTES = 10.9


class Rate:
    """Measured hashcat throughput in candidates per second.

    Mutable on purpose: the pipeline refits ``hps`` from the ``Speed.#01`` line
    of the first stage that reports one, so the remaining stages are sliced
    against *this* machine rather than against the developer's GPU.
    """

    __slots__ = ("hps",)

    def __init__(self, hps: float = DEFAULT_HPS) -> None:
        self.hps = hps if hps > 0 else DEFAULT_HPS


#: hashcat prints its throughput in its session header, e.g.
#: ``Speed.#*........:  684.5 kH/s (94.88ms) @ Accel:30 Loops:1024 Thr:256``
_SPEED_RE = re.compile(r"Speed\.#\d+\.*\s*:\s*([\d.]+)\s*([kMG])?H/s", re.IGNORECASE)
_UNIT = {"k": 1e3, "m": 1e6, "g": 1e9}


def parse_speed(line: str) -> float | None:
    """Candidates per second from a hashcat ``Speed.#`` line, or None."""
    match = _SPEED_RE.search(line)
    if not match:
        return None
    value = float(match.group(1)) * _UNIT.get((match.group(2) or "").lower(), 1.0)
    return value if value > 0 else None


#: All-digit passwords, 8 then 9 characters: the remaining real-world shapes.
#: 10 digits is ~4 GPU-hours and is left out of the default ladder on purpose.
DIGIT_MASKS = ("?d?d?d?d?d?d?d?d", "?d?d?d?d?d?d?d?d?d")


def build_ladder(
    *,
    targeted: str | Path | None = None,
    targeted_count: int | None = None,
    quick: str | Path | None = None,
    rockyou: str | Path | None = None,
    rules: str | Path | None = None,
    extra: str | Path | None = None,
    digit_masks: Sequence[str] = DIGIT_MASKS,
    masks: Sequence[str] = (),
) -> List[Stage]:
    """Assemble the stages to run, in order, skipping anything not on disk.

    ``masks`` are the caller's own masks (from the settings screen). They run
    before the generic digit stages: a mask is a statement about what the
    password looks like, which beats a guess that the password is all digits,
    and the default digit masks would otherwise run first and spend the budget
    the user's own format needed.

    ``extra`` is a prepared list of passwords that no shipped dictionary has.
    It runs right before the digit masks, for the same reason it is worth
    anything at all: the masks brute-force all-digit passwords blind, and this
    list already knows 66k of the ones that exist in the wild -- the nine-digit
    mask is a billion candidates and a quarter of an hour, and this file covers
    the realistic part of that ground in about a second.
    """
    stages: List[Stage] = []

    def path(value: str | Path | None) -> Path | None:
        return Path(value) if value and Path(value).is_file() else None

    if (targeted_path := path(targeted)) is not None:
        stages.append(
            Stage(
                "targeted",
                "кандидаты по имени и MAC сети",
                targeted_path,
                count=targeted_count,
            )
        )
        if (rules_path := path(rules)) is not None:
            # The same words, mutated: ``MTS_GPON_A3E2!``, ``MTSGPONA3E2024``,
            # ``mynetwifi`` are what people actually type, and they are in
            # neither the generated list nor RockYou. ~5M candidates for the
            # typical 80k list -- seconds, not minutes, which is what makes it
            # worth a rung of its own instead of an afterthought.
            stages.append(
                Stage(
                    "targeted_rules",
                    f"кандидаты сети + мутации ({rules_path.name})",
                    targeted_path,
                    rules_path,
                )
            )
    if (quick_path := path(quick)) is not None:
        stages.append(Stage("quick", "частые пароли (4800)", quick_path))
    if (rockyou_path := path(rockyou)) is not None:
        stages.append(Stage("rockyou", "RockYou WPA", rockyou_path))
    # Ahead of the mutation stage, not after it. That stage is ~620M candidates
    # and about fifteen minutes; this one is 672k and about a second. Paying
    # stages in order of likelihood means a password this list can answer is
    # found in a second instead of after a quarter of an hour spent mutating
    # words that were never going to match.
    if (extra_path := path(extra)) is not None:
        stages.append(
            Stage(
                "extra",
                f"словари без RockYou ({extra_path.name})",
                extra_path,
            )
        )
    # A mask the user described outranks every dictionary and runs before the
    # mutation stage: best66 over RockYou is ~620M candidates, about ten minutes
    # of the budget, and it is the one stage a specific format can beat.
    for mask in masks:
        stages.append(Stage("mask", f"маска: {mask}", mask=mask))
    if (rockyou_path := path(rockyou)) is not None:
        if (rules_path := path(rules)) is not None:
            stages.append(
                Stage(
                    "mutations",
                    f"RockYou + мутации ({rules_path.name})",
                    rockyou_path,
                    rules_path,
                )
            )
    # Last, and only because the masks are exhaustive: they will find every
    # all-digit password of this length whether or not anybody has ever typed
    # it. The extra list above already tried the ones that are real.
    for mask in digit_masks:
        stages.append(Stage("digits", f"цифры: {mask}", mask=mask))
    return stages


#: Where the "passwords no shipped dictionary has" list is looked for. Kept out
#: of ``WORDLIST_NAMES`` on purpose: that tuple answers "is there a dictionary to
#: work with", and this file is an addition to it, not a replacement. A user
#: with only rockyou-wpa.txt must not be told a dictionary is missing.
#: The names themselves live in ``options`` with the other asset lookups.


#: hashcat needs ~2.5 s of session start-up (loading OpenCL, reading the potfile)
#: before it tests a single candidate, so a slice shorter than this would be
#: spent entirely on start-up and check nothing at all.
MIN_STAGE_SECONDS = 8.0


async def run_ladder(
    stages: Sequence[Stage],
    run_stage: Callable[[Stage, float], object],
    *,
    total_runtime: float = 1800.0,
    rate: Rate | None = None,
    on_stage: Callable[[int, Stage, float], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> tuple[object | None, Stage | None]:
    """Run ``stages`` until one succeeds; returns (outcome, winning stage).

    ``run_stage`` is called as ``run_stage(stage, timeout)`` and may be a plain
    function or a coroutine function; it must return something with a truthy
    ``cracked`` attribute on success. Each stage is given what it still needs at
    ``rate``, in order, so a stage that finishes early hands its unused time to
    the next one -- and the first stage's measured speed refits the rest of the
    slices, because the plan is recomputed from the weights and the wall clock
    before every stage starts.

    The slices are deliberately *not* proportional to the stages' sizes. The
    order of the ladder is a ranking of how likely each stage is to contain the
    password, and dividing a fixed budget proportionally to size ignores exactly
    that: it hands the biggest stage -- nine random digits, a billion candidates,
    a day and a half of GPU -- half the budget it cannot spend anyway, while the
    stage that is one minute short of covering RockYou through best66 gets cut
    off at 70%. Paying stages off in order is the same rule the ladder is sorted
    by, and it is what turns "71% of the two stages that matter" into "all of
    them, and whatever is left over for the last one".
    """
    rate = rate or Rate()
    # Not clamped to a minimum: a zero budget must run nothing at all, which is
    # what a caller asking for a dry run of the plan expects.
    deadline = time.monotonic() + max(0.0, float(total_runtime))
    left = [stage.seconds(rate) for stage in stages]
    outcome: object | None = None

    for index, stage in enumerate(stages):
        if should_stop is not None and should_stop():
            return None, None
        now = time.monotonic()
        available = deadline - now
        if available <= 0:
            break
        plan = _plan_slices(available, left)
        share = plan[index]
        if on_stage is not None:
            on_stage(index, stage, share)
        outcome = run_stage(stage, share)
        if inspect.isawaitable(outcome):
            outcome = await outcome
        if getattr(outcome, "cracked", False):
            return outcome, stage
        # This stage is done: it must not claim any of what is left.
        left[index] = 0.0
    return None, None


def _plan_slices(available: float, weights: Sequence[float]) -> List[float]:
    """The slice each stage gets from ``available``, in ladder order.

    One pass of water-filling: every stage is paid what it needs, and whatever
    the budget cannot cover is left to the stages after it, where the last one
    absorbs the remainder. A stage is never given more than it needs -- an
    over-served stage is time taken away from a stage that is not finished --
    but never less than :data:`MIN_STAGE_SECONDS`, because a slice shorter than
    hashcat's start-up tests nothing at all.

    ``weights[i]`` is what stage ``i`` still needs in seconds; zero for stages
    that have already run, so they claim nothing.
    """
    out: List[float] = []
    left = max(0.0, float(available))
    for need in weights:
        if left <= 0:
            out.append(0.0)
            continue
        share = min(max(float(need), 0.0), left)
        share = max(share, min(MIN_STAGE_SECONDS, left))
        out.append(share)
        left -= share
    return out


def budget_shares(
    stages: Sequence[Stage], total_runtime: float, rate: Rate | None = None
) -> List[float]:
    """The slice each stage would get -- exposed so the UI can show the plan.

    Mirrors :func:`run_ladder` on the assumption that no stage finishes early:
    the shares sum to at most ``total_runtime``, and every stage before the last
    is shown with exactly the time it needs, so the plan on screen is the plan
    that runs.
    """
    rate = rate or Rate()
    return _plan_slices(
        max(0.0, float(total_runtime)), [stage.seconds(rate) for stage in stages]
    )


def fmt_budget(seconds: float) -> str:
    """``95`` -> ``1м 35с``, for the plan line in the log."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} с"
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}м {rest:02d}с"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}ч {minutes:02d}м"


def fmt_count(value: float) -> str:
    """``9_609_471`` -> ``9.6 млн`` -- for stage sizes in the log."""
    if value >= 1e9:
        return f"{value / 1e9:.1f} млрд"
    if value >= 1e6:
        return f"{value / 1e6:.1f} млн"
    if value >= 1e3:
        return f"{value / 1e3:.1f} тыс"
    return f"{int(value)}"