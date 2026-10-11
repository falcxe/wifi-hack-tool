"""Tests for the one-key ladder: candidates, budgeting, and a real hashcat run.

The last test is the important one: it drives the *whole* automatic path --
stored-key check, conversion, ladder -- against the bundled fixture with the real
hashcat binary, and requires the documented password to come out of the first
stage. Nothing is mocked, so a candidate generator that stops producing the
password, or a ladder that skips its first rung, fails here.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wifi_tool import auto, converter, cracker, pipeline, profiles  # noqa: E402
from wifi_tool.models import CrackResult, Network  # noqa: E402

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "tests" / "fixtures" / "wpa2_psk_12345678.pcapng"
ASSETS = ROOT / "assets"
EXPECTED_PSK = "12345678"
#: Decoded from the fixture's hc22000 record; the AP it belongs to.
FIXTURE_SSID = "test-wnm-rsn"
FIXTURE_BSSID = "02:00:00:03:00:00"

OWN = Network("MyHomeWiFi_5G", "aa:bb:cc:d0:12:34", 6, 80, "WPA2-Personal", "CCMP")


class FakeOutcome:
    """The duck type :func:`auto.run_ladder` expects back from a stage."""

    def __init__(self, cracked: bool = False, password: str = "") -> None:
        self.cracked = cracked
        self.password = password


class CandidateTests(unittest.TestCase):
    def test_only_psk_length_values_are_emitted(self):
        values = auto.candidates_for(OWN)
        self.assertTrue(values)
        for value in values:
            self.assertTrue(8 <= len(value.encode("utf-8")) <= 63, value)
            self.assertEqual(value, value.strip(), value)

    def test_ssid_and_mac_forms_come_first(self):
        values = auto.candidates_for(OWN)
        head = values[:12]
        self.assertIn("MyHomeWiFi5G", head)
        self.assertIn("myhomewifi5g", head)
        # The raw SSID is tried too, before any generated combination.
        self.assertIn("MyHomeWiFi_5G", values[:40])

    def test_factory_defaults_are_present(self):
        values = set(auto.candidates_for(OWN))
        for expected in ("12345678", "password1", "changeme", "internet", "wireless1"):
            self.assertIn(expected, values, expected)

    def test_mac_tails_and_digit_runs(self):
        values = set(auto.candidates_for(OWN))
        # The BSSID is aa:bb:cc:d0:12:34, so every suffix of it is a candidate.
        self.assertIn("aabbccd01234", values)  # the whole MAC, 12 chars
        self.assertIn("ccd01234", values)  # last 8 chars
        self.assertIn("aabbccd012342024", values)  # whole MAC + a year
        self.assertIn("d012342024", values)  # last 6 chars + a year
        # A 6-char suffix alone is too short to be a PSK, so it is filtered out --
        # the length floor is what stops the list filling with dead candidates.
        self.assertNotIn("d01234", values)

    def test_no_duplicates_and_bounded(self):
        values = auto.candidates_for(OWN)
        self.assertEqual(len(values), len(set(values)), "duplicate candidates")
        self.assertLessEqual(len(values), auto.MAX_TARGETED)

    def test_empty_ssid_and_bssid_still_yield_defaults(self):
        values = auto.candidates_for(Network("", ""))
        self.assertIn("12345678", values)
        self.assertTrue(all(auto.psk_usable(v) for v in values))

    def test_psk_usable_rejects_padding_and_length(self):
        for bad in ("", " pass ", "short", "x" * 64):
            self.assertFalse(auto.psk_usable(bad), bad)
        self.assertTrue(auto.psk_usable("12345678"))
        self.assertTrue(auto.psk_usable("x" * 63))


class CostingTests(unittest.TestCase):
    def test_mask_cost_is_exact(self):
        eight = auto.Stage("digits", "8", mask="?d?d?d?d?d?d?d?d")
        nine = auto.Stage("digits", "9", mask="?d?d?d?d?d?d?d?d?d")
        self.assertEqual(eight.candidates(), 1e8)
        self.assertEqual(nine.candidates(), 1e9)

    def test_wordlist_cost_comes_from_the_file_size(self):
        stage = auto.Stage("quick", "quick", ROOT / "assets" / "probable-wpa.txt")
        # 45 276 bytes / 10.9 ~= 4153, against 4800 real lines: close enough for
        # slicing a budget, which is all this number is used for.
        self.assertAlmostEqual(stage.candidates(), 4800, delta=800)

    def test_explicit_count_wins_over_the_size_estimate(self):
        stage = auto.Stage("targeted", "t", ROOT / "assets" / "wordlist.txt", count=42)
        self.assertEqual(stage.candidates(), 42)

    def test_seconds_scale_with_measured_rate(self):
        stage = auto.Stage("digits", "8", mask="?d?d?d?d?d?d?d?d")
        slow = auto.Rate(100_000)
        fast = auto.Rate(1_000_000)
        self.assertAlmostEqual(stage.seconds(slow), 1000.0)
        self.assertAlmostEqual(stage.seconds(fast), 100.0)

    def test_rule_multiplies_the_wordlist(self):
        wordlist = ROOT / "assets" / "wordlist.txt"
        rules = ROOT / "assets" / "hashcat-7.1.2" / "rules" / "best66.rule"
        plain = auto.Stage("w", "w", wordlist)
        mutated = auto.Stage("m", "m", wordlist, rules)
        self.assertGreater(mutated.candidates(), plain.candidates() * 50)

    def test_budget_shares_never_exceed_the_total(self):
        stages = auto.build_ladder(
            targeted=ASSETS / "wordlist.txt",
            quick=ASSETS / "probable-wpa.txt",
            rockyou=ASSETS / "rockyou-wpa.txt",
            rules=ROOT / "assets" / "hashcat-7.1.2" / "rules" / "best66.rule",
        )
        for total in (30.0, 180.0, 1800.0):
            shares = auto.budget_shares(stages, total)
            self.assertEqual(len(shares), len(stages))
            self.assertLessEqual(sum(shares), total + 1e-6, total)

    def test_missing_files_are_skipped(self):
        stages = auto.build_ladder(targeted="nope.txt", quick=None, rockyou=None)
        self.assertEqual([s.key for s in stages], ["digits", "digits"])

    def test_the_generated_candidates_are_mutated_too(self):
        """``SSID!`` and ``SSID2024`` are typed far more often than ``SSID``."""
        rules = ROOT / "assets" / "hashcat-7.1.2" / "rules" / "best66.rule"
        stages = auto.build_ladder(targeted=ASSETS / "wordlist.txt", rules=rules)
        keys = [s.key for s in stages]
        self.assertEqual(keys[:2], ["targeted", "targeted_rules"])
        mutated = stages[1]
        self.assertEqual(mutated.rules, rules)
        self.assertGreater(mutated.candidates(), stages[0].candidates() * 50)

    def test_speed_parsing(self):
        self.assertEqual(
            auto.parse_speed("Speed.#01........:   684.5 kH/s (94.88ms) @ Accel:30"),
            684500.0,
        )
        self.assertEqual(auto.parse_speed("Speed.#2........:   1.2 MH/s"), 1_200_000.0)
        self.assertEqual(auto.parse_speed("Speed.#1........:  900.0 H/s"), 900.0)
        self.assertIsNone(auto.parse_speed("Session: 12345"))
        self.assertIsNone(auto.parse_speed("Speed.#1: 0 H/s"))


class LadderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.calls: list[tuple[str, float]] = []

    def _runner(self, cracked_on: str | None):
        def run(stage, timeout):
            self.calls.append((stage.key, timeout))
            return FakeOutcome(cracked=stage.key == cracked_on,
                               password="found" if stage.key == cracked_on else "")

        return run

    async def test_stops_at_the_first_success(self):
        stages = [
            auto.Stage("a", "a", ASSETS / "wordlist.txt"),
            auto.Stage("b", "b", ASSETS / "wordlist.txt"),
            auto.Stage("c", "c", ASSETS / "wordlist.txt"),
        ]
        outcome, winner = await auto.run_ladder(
            stages, self._runner("b"), total_runtime=600
        )
        self.assertTrue(outcome.cracked)
        self.assertEqual(outcome.password, "found")
        self.assertIs(winner, stages[1])
        self.assertEqual([k for k, _ in self.calls], ["a", "b"])

    async def test_runs_every_stage_when_nothing_matches(self):
        stages = [auto.Stage(k, k, ASSETS / "wordlist.txt") for k in "abcd"]
        outcome, winner = await auto.run_ladder(
            stages, self._runner(None), total_runtime=600
        )
        self.assertIsNone(outcome)
        self.assertIsNone(winner)
        self.assertEqual([k for k, _ in self.calls], ["a", "b", "c", "d"])

    async def test_a_stage_that_finishes_early_hands_its_time_on(self):
        """The whole point of the budget: unused time is not thrown away."""
        stages = [auto.Stage("a", "a", ASSETS / "wordlist.txt", count=1),
                  auto.Stage("b", "b", ASSETS / "wordlist.txt", count=10**10)]
        self.calls.clear()
        await auto.run_ladder(stages, self._runner(None), total_runtime=600)
        # Stage "a" is given the start-up floor and returns instantly, so almost
        # the whole budget is still there for "b".
        self.assertGreater(self.calls[1][1], self.calls[0][1] * 10,
                           "the second stage did not inherit the first stage's slack")
        self.assertGreater(self.calls[1][1], 500.0)

    async def test_startup_floor_protects_the_cheapest_stage(self):
        """A proportional slice below hashcat's start-up cost would test nothing."""
        stages = [auto.Stage("tiny", "tiny", ASSETS / "wordlist.txt", count=1),
                  auto.Stage("huge", "huge", mask="?d?d?d?d?d?d?d?d?d?d")]
        self.calls.clear()
        await auto.run_ladder(stages, self._runner(None), total_runtime=600)
        self.assertGreaterEqual(
            self.calls[0][1], auto.MIN_STAGE_SECONDS,
            "the first stage was given less than hashcat needs to start",
        )

    async def test_should_stop_aborts_before_the_next_stage(self):
        stages = [auto.Stage(k, k, ASSETS / "wordlist.txt") for k in "abc"]
        stop = {"now": False}

        def run(stage, timeout):
            self.calls.append((stage.key, timeout))
            stop["now"] = True
            return FakeOutcome()

        await auto.run_ladder(stages, run, total_runtime=600, should_stop=lambda: stop["now"])
        self.assertEqual([k for k, _ in self.calls], ["a"])

    async def test_zero_budget_runs_nothing(self):
        stages = [auto.Stage("a", "a", ASSETS / "wordlist.txt")]
        outcome, winner = await auto.run_ladder(stages, self._runner("a"), total_runtime=0)
        self.assertEqual(self.calls, [])
        self.assertIsNone(outcome)
        self.assertIsNone(winner)

    async def test_wall_clock_never_exceeds_the_budget(self):
        """The start-up floor may overshoot the *grants*, never the deadline."""
        stages = [auto.Stage(k, k, ASSETS / "wordlist.txt", count=1) for k in "abc"]
        self.calls.clear()
        started = time.monotonic()
        await auto.run_ladder(stages, self._runner(None), total_runtime=0.5)
        self.assertLessEqual(time.monotonic() - started, 0.5 + 0.2)
        for _, grant in self.calls:
            self.assertLessEqual(grant, 0.5, "a stage was granted more than the budget")

    async def test_async_run_stage_is_awaited(self):
        stages = [auto.Stage("a", "a", ASSETS / "wordlist.txt")]
        seen: list[float] = []

        async def run(stage, timeout):
            seen.append(timeout)
            return FakeOutcome(cracked=True, password="ok")

        outcome, _ = await auto.run_ladder(stages, run, total_runtime=60)
        self.assertTrue(outcome.cracked)
        self.assertEqual(len(seen), 1)

    async def test_measured_speed_refits_the_later_stages(self):
        """hashcat's reported throughput re-slices what is left, so a 4x slower GPU
        does not hand the later stages slices sized for a fast one."""
        rate = auto.Rate()
        stages = [auto.Stage("a", "a", ASSETS / "wordlist.txt", count=1),
                  auto.Stage("b", "b", mask="?d?d?d?d?d?d?d?d?d?d")]
        self.calls.clear()

        async def run(stage, timeout):
            self.calls.append((stage.key, timeout))
            # Stage "a" reports a GPU four times slower than the default.
            if stage.key == "a":
                rate.hps = auto.DEFAULT_HPS / 4
            return FakeOutcome()

        await auto.run_ladder(stages, run, total_runtime=1200, rate=rate)
        self.assertEqual([k for k, _ in self.calls], ["a", "b"])
        # At 1/4 the speed the 10^10 mask costs four times more, so it takes a
        # proportionally larger share of what is left -- not the 1200 s the
        # default rate would have justified.
        self.assertGreater(self.calls[1][1], 900.0)
        self.assertLessEqual(self.calls[1][1], 1200.0)


class BudgetAllocationTests(unittest.IsolatedAsyncioTestCase):
    """The budget is spent in ladder order, not in proportion to stage size.

    Proportional slicing hands the largest stage a share it cannot use -- nine
    random digits are a day and a half of GPU -- and takes that share away from
    the stage that was one minute short of covering RockYou through best66.
    """

    def ladder(self) -> list[auto.Stage]:
        return [
            auto.Stage("targeted", "targeted", ASSETS / "wordlist.txt", count=100_000),
            auto.Stage("mutations", "mutations", ASSETS / "rockyou-wpa.txt",
                       ASSETS / "hashcat-7.1.2" / "rules" / "best66.rule"),
            auto.Stage("digits", "digits", mask="?d" * 9),
        ]

    def test_every_stage_before_the_last_is_paid_in_full(self):
        stages = self.ladder()
        rate = auto.Rate()
        needs = [s.seconds(rate) for s in stages]
        # A budget that cannot finish even the last stage: everything but the
        # tail must still be covered completely.
        budget = needs[0] + needs[1] + 60
        shares = auto.budget_shares(stages, budget, rate)
        self.assertGreaterEqual(shares[0], needs[0])
        self.assertGreaterEqual(shares[1], needs[1])
        # What is left goes to the stage that cannot be finished -- minus the
        # start-up floor the cheap stages still cost, which is the price of
        # letting them run at all.
        self.assertAlmostEqual(shares[2], 60 - (auto.MIN_STAGE_SECONDS - needs[0]),
                               delta=1.0)
        self.assertAlmostEqual(sum(shares), budget, delta=1e-6)

    def test_a_stage_is_never_given_more_than_it_needs(self):
        stages = self.ladder()
        rate = auto.Rate()
        shares = auto.budget_shares(stages, 10 * 3600, rate)
        for stage, share in zip(stages, shares):
            # The floor is the one exception: a stage needs ~2.5 s of hashcat
            # start-up, so a 0.15 s stage is still given the floor.
            self.assertLessEqual(
                share, max(stage.seconds(rate), auto.MIN_STAGE_SECONDS) + 1e-6,
                stage.key,
            )

    def test_shares_add_up_to_the_budget_for_any_size(self):
        stages = self.ladder()
        for total in (0.0, 5.0, 30.0, 1800.0, 36000.0):
            shares = auto.budget_shares(stages, total)
            self.assertEqual(len(shares), len(stages))
            self.assertLessEqual(sum(shares), total + 1e-6, total)
            self.assertTrue(all(s >= 0 for s in shares), shares)

    async def test_the_first_stage_is_granted_exactly_what_the_plan_shows(self):
        """``budget_shares`` is not a decoration: it is what the first stage gets.

        The plan on screen is computed before the run from estimated sizes, and
        the run recomputes from the wall clock on every stage -- which it can
        only do honestly because the two call the same function. A plan that
        disagreed with the run would promise coverage the ladder never reaches.
        """
        stages = self.ladder()
        rate = auto.Rate()
        needs = [s.seconds(rate) for s in stages]
        shown = auto.budget_shares(stages, needs[0] + needs[1] + 60, rate)
        grants: list[float] = []

        async def run(stage, timeout):
            grants.append(timeout)
            return FakeOutcome()

        await auto.run_ladder(stages, run, total_runtime=needs[0] + needs[1] + 60, rate=rate)
        self.assertAlmostEqual(grants[0], shown[0], delta=1e-6)
        # Later stages inherit what the earlier ones did not use, which is the
        # whole point of measuring against the clock rather than the estimate.
        self.assertGreater(grants[2], shown[2])


class SavedKeyTests(unittest.TestCase):
    #: netsh repeats the label on every profile line, not just the first.
    LISTING = (
        "Профили пользователей\n"
        "---------------------------\n"
        "    Все профили пользователей     : BruceNet\n"
        "    Все профили пользователей     : Speedometer-Setup\n"
    )

    def test_find_key_reads_only_the_matching_profile(self):
        calls: list[list[str]] = []

        def fake_netsh(args, timeout=25.0):
            calls.append(args)
            if args == ["show", "profiles"]:
                return self.LISTING
            return (
                "    Имя SSID                   : Speedometer-Setup\n"
                "    Проверка подлинности      : WPA2-Personal\n"
                "    Шифр                       : CCMP\n"
                "    Содержимое ключа           : 12345678\n"
            )

        with patch.object(profiles, "_netsh", side_effect=fake_netsh):
            self.assertEqual(profiles.find_key("Speedometer-Setup"), "12345678")
        # The list once, then the single matching profile -- not every profile.
        self.assertEqual(len(calls), 2, calls)
        self.assertIn("name=Speedometer-Setup", calls[1])

    def test_find_key_is_empty_for_an_unknown_ssid(self):
        with patch.object(profiles, "_netsh", return_value=self.LISTING):
            self.assertEqual(profiles.find_key("Nope"), "")
            self.assertEqual(profiles.find_key(""), "")

    def test_find_key_is_empty_when_the_profile_is_locked(self):
        def fake_netsh(args, timeout=25.0):
            if args == ["show", "profiles"]:
                return "All User Profile\n    Locked\n"
            return (
                "    Name                       : Locked\n"
                "    Authentication             : WPA2-Personal\n"
                "    Encryption                 : CCMP\n"
                "    Профиль применен ко всем пользователям\n"
            )

        with patch.object(profiles, "_netsh", side_effect=fake_netsh):
            self.assertEqual(profiles.find_key("Locked"), "")

    def test_find_key_survives_a_netsh_failure(self):
        with patch.object(profiles, "_netsh", side_effect=profiles.ProfileError("нет")):
            self.assertEqual(profiles.find_key("BruceNet"), "")


class TargetTests(unittest.TestCase):
    def test_wpa3_only_is_not_an_offline_target(self):
        sae = Network("Modern", "aa:bb:cc:dd:ee:01", auth="WPA3-Personal")
        self.assertTrue(sae.is_psk)
        self.assertTrue(sae.is_wpa3_only)
        self.assertFalse(sae.crackable)

    def test_wpa3_transition_still_counts(self):
        transition = Network("Both", "aa:bb:cc:dd:ee:02", auth="WPA2-Personal WPA3-Personal")
        self.assertFalse(transition.is_wpa3_only)
        self.assertTrue(transition.crackable)

    def test_wpa2_and_open_and_enterprise(self):
        self.assertTrue(Network("n", "b", auth="WPA2-Personal").crackable)
        self.assertFalse(Network("n", "b", auth="Открытая").crackable)
        self.assertFalse(Network("n", "b", auth="WPA2-Enterprise").crackable)


class AutoAttackTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.report = None

    def _isolated_crack(self):
        original = cracker.crack

        async def run(*args, **kwargs):
            kwargs["potfile"] = self.root / "fixture.potfile"
            return await original(*args, **kwargs)

        return patch.object(cracker, "crack", side_effect=run)

    def _readiness(self):
        return pipeline.Readiness(
            admin=False,
            hashcat=cracker.find_hashcat(),
            wordlist=ASSETS / "rockyou-wpa.txt",
            rules=ROOT / "assets" / "hashcat-7.1.2" / "rules" / "best66.rule",
        )

    async def _convert(self):
        out = self.root / "fixture.22000"
        result = await converter.convert(FIXTURE, out, None, prefer="builtin")
        self.assertTrue(result.report.ok, "the fixture produced no hashes")
        return out, result.report

    async def test_stored_key_wins_before_anything_else_runs(self):
        with patch.object(pipeline, "saved_key_for", AsyncMock(return_value="SolvedIt")), \
                patch.object(pipeline, "obtain_hashes", AsyncMock()) as capture, \
                patch.object(cracker, "find_hashcat", return_value=None):
            result = await pipeline.auto_attack(OWN, readiness=self._readiness())
        self.assertTrue(result.success)
        self.assertEqual(result.password, "SolvedIt")
        self.assertEqual(result.method, "ключ Windows")
        # No capture, no hashcat, no ladder: the stored key is the whole answer.
        capture.assert_not_awaited()

    async def test_missing_hashcat_is_only_fatal_once_the_stored_key_misses(self):
        ready = pipeline.Readiness(admin=False, hashcat=None, wordlist=ASSETS / "rockyou-wpa.txt")
        with patch.object(pipeline, "saved_key_for", AsyncMock(return_value="")):
            with self.assertRaises(pipeline.PipelineError) as caught:
                await pipeline.auto_attack(OWN, readiness=ready)
        self.assertIn("hashcat", str(caught.exception))

    async def test_exhausted_ladder_is_a_result_not_an_exception(self):
        hash_path, report = await self._convert()
        with patch.object(pipeline, "saved_key_for", AsyncMock(return_value="")), \
                patch.object(cracker, "crack", AsyncMock(
                    return_value=cracker.CrackOutcome(exhausted=True))):
            result = await pipeline.auto_attack(
                OWN,
                readiness=self._readiness(),
                hash_path=hash_path,
                report=report,
                total_runtime=30,
            )
        self.assertFalse(result.success)
        self.assertEqual(result.password, "")
        self.assertIn("не подошёл", result.error)
        # An exhausted ladder is a result, so it must still carry a way forward.
        self.assertTrue(result.remedy, "a miss arrived with no advice attached")
        self.assertIn("маска", result.remedy)

    async def test_cancellation_is_reported_as_cancelled(self):
        hash_path, report = await self._convert()
        stop = {"now": False}
        stop_holder = pipeline.Callbacks(should_stop=lambda: stop["now"])

        with patch.object(pipeline, "saved_key_for", AsyncMock(return_value="")), \
                patch.object(auto, "run_ladder", AsyncMock(return_value=(None, None))):
            stop["now"] = True
            result = await pipeline.auto_attack(
                OWN,
                readiness=self._readiness(),
                hash_path=hash_path,
                report=report,
                total_runtime=30,
                cb=stop_holder,
            )
        self.assertFalse(result.success)
        self.assertIn("остановлен", result.error)

    async def test_plan_is_logged_before_anything_runs(self):
        hash_path, report = await self._convert()
        lines: list[str] = []
        stages: list[str] = []

        def announce(index, total, title):
            stages.append(f"{index + 1}/{total}")

        with patch.object(pipeline, "saved_key_for", AsyncMock(return_value="")), \
                patch.object(cracker, "crack", AsyncMock(
                    return_value=cracker.CrackOutcome())):
            await pipeline.auto_attack(
                OWN,
                readiness=self._readiness(),
                hash_path=hash_path,
                report=report,
                total_runtime=45,
                cb=pipeline.Callbacks(on_log=lines.append, on_stage=announce),
            )
        plan = [line for line in lines if line.startswith("  1.")]
        self.assertTrue(plan, f"no plan was logged:\n{chr(10).join(lines)}")
        self.assertIn("кандидаты по имени и MAC сети", plan[0])
        self.assertTrue(any("Этап 1/" in line for line in lines), lines)
        self.assertEqual(stages[0], "1/7")

    @unittest.skipUnless(FIXTURE.is_file(), "фикстура отсутствует")
    async def test_real_hashcat_recovers_the_password_from_the_first_stage(self):
        """The whole automatic path, with nothing mocked but the stored key.

        ``12345678`` is in the generated candidate list, so the ladder must find
        it in stage 1 -- which is what proves the generator and the stage order
        are both right, not just that hashcat can be called.
        """
        hashcat = cracker.find_hashcat()
        if hashcat is None:
            self.skipTest("hashcat не найден")
        hash_path, report = await self._convert()
        target = Network(FIXTURE_SSID, FIXTURE_BSSID, 6, 80, "WPA2-Personal", "CCMP")
        lines: list[str] = []
        stages: list[str] = []

        with self._isolated_crack(), \
                patch.object(pipeline, "saved_key_for", AsyncMock(return_value="")), \
                patch.object(cracker, "find_hashcat", return_value=hashcat):
            result = await pipeline.auto_attack(
                target,
                readiness=self._readiness(),
                hash_path=hash_path,
                report=report,
                hashcat_path=hashcat,
                total_runtime=300,
                cb=pipeline.Callbacks(on_log=lines.append),
            )

        self.assertTrue(result.success, f"ladder found nothing:\n{chr(10).join(lines[-25:])}")
        self.assertEqual(result.password, EXPECTED_PSK)
        self.assertIn("кандидаты по имени и MAC сети", result.method)
        print(f"  real ladder: {result.password!r} via {result.method} "
              f"in {result.elapsed:.1f}s")

    @unittest.skipUnless(FIXTURE.is_file(), "фикстура отсутствует")
    async def test_real_hashcat_still_reports_a_miss_honestly(self):
        """A password outside every stage must come back as 'not found'.

        Each test uses its own empty potfile: an earlier recovered answer must
        not turn a wrong dictionary into a false success or touch real results.
        """
        hashcat = cracker.find_hashcat()
        if hashcat is None:
            self.skipTest("hashcat не найден")
        hash_path, report = await self._convert()
        target = Network(FIXTURE_SSID, FIXTURE_BSSID, 6, 80, "WPA2-Personal", "CCMP")
        # One dictionary that cannot contain the answer, and no masks.
        wrong = self.root / "wrong.txt"
        wrong.write_text("qqqqqqqq\nwwwwwwww\n", encoding="utf-8")
        with self._isolated_crack(), \
                patch.object(pipeline, "saved_key_for", AsyncMock(return_value="")), \
                patch.object(auto, "build_ladder", side_effect=lambda **kw: [
                    auto.Stage("wrong", "подставной список", wrong)
                ]), \
                patch.object(cracker, "find_hashcat", return_value=hashcat):
            result = await pipeline.auto_attack(
                target,
                readiness=self._readiness(),
                hash_path=hash_path,
                report=report,
                hashcat_path=hashcat,
                total_runtime=120,
            )
        self.assertFalse(result.success, f"a wrong dictionary reported {result.password!r}")
        self.assertEqual(result.password, "")
        self.assertTrue(result.error)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
