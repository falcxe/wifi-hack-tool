"""Smoke test: the real flow on this machine, no mocks anywhere.

Renders the actual TUI, feeds real keys through the real terminal input handler,
and lets the whole background pipeline run: Enter to the audit screen, then -> to
start, then the Windows saved-profile check, the capture stage and -- if it gets
that far -- the ladder. Whatever the outcome, it has to be a coherent result
screen and a coherent log, not a hang and not a silent failure.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from opentui.testing import test_render
from opentui.input.event_loop import TestInputHandler
from opentui.renderer._session import bind_event_loop

from wifi_tool.ui import controller, state
from wifi_tool.ui.app import App


async def main() -> int:
    state.reset()
    controller.bind(None)
    setup = await test_render(App, {"width": 100, "height": 30})
    setup.render_frame()
    native = TestInputHandler()
    native.start()
    bind_event_loop(setup.renderer,
                    __import__("types").SimpleNamespace(input_handler=native,
                                                        on_frame=lambda cb: None))
    try:
        controller.boot()
        # Let the real scan finish.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            await asyncio.sleep(0.2)
            setup.render_frame()
            if not state.scanning() and (state.networks() or state.scan_error()):
                break
        nets = state.networks()
        print(f"scan      : {len(nets)} network(s), error={state.scan_error()!r}")
        if not nets:
            print("SMOKE: the scan produced nothing -- nothing to auto-attack")
            return 1

        target = next((n for n in nets if n.crackable), None)
        if target is None:
            print("SMOKE: nothing in the live scan is an offline target")
            print(setup.capture_char_frame())
            return 1
        state.selected.set(nets.index(target))
        setup.render_frame()
        print(f"target    : {target.label!r} {target.bssid} "
              f"crackable={target.crackable} auth={target.auth!r}")

        # Enter on the list opens the audit; the run starts from there. Both are
        # the keys a user would actually press.
        started = time.monotonic()
        native.feed("\r")
        for _ in range(50):
            await asyncio.sleep(0.1)
            setup.render_frame()
            if state.phase() == "audit":
                break
        if state.phase() != "audit":
            print(f"SMOKE: Enter did not reach the audit screen (phase={state.phase()})")
            print(setup.capture_char_frame())
            return 1
        audit_frame = setup.capture_char_frame()
        print(f"audit     : reached in {time.monotonic() - started:.1f}s")
        assert ("Поймаю рукопожатие" in audit_frame
                or "Нужен файл" in audit_frame
                or "Открытая" in audit_frame), (
            f"audit screen has no run action at all\n{audit_frame}"
        )
        # On a machine whose adapter cannot do monitor mode the button is
        # deliberately disabled and says so -- that is a correct outcome, not a
        # missing action.
        from wifi_tool.ui.screens.audit import _blocker, _disabled_reason, _auto_enabled
        blocked = (not _auto_enabled(target)
                   or bool(_blocker(target, state.readiness.peek())))
        print(f"blocked   : {blocked}"
              + (f" ({_disabled_reason(target)})" if blocked else ""))
        # The screen states what starting it will do, and why it may be limited.
        assert ("Поймаю рукопожатие" in audit_frame
                or "Нужен файл" in audit_frame
                or "Открытая" in audit_frame
                or "Ключ сохран" in audit_frame), (
            f"audit screen does not say what starting it will do\n{audit_frame}"
        )
        native.feed("\r")  # audit -> run
        started = time.monotonic()
        while time.monotonic() - started < 90 and state.phase() != "result":
            await asyncio.sleep(0.2)
            setup.render_frame()
        setup.render_frame()

        print(f"phase     : {state.phase()} after {time.monotonic() - started:.1f}s")
        print(f"stage     : {state.stage()!r}")
        result = state.result.peek()
        if result is None:
            print("SMOKE: no result was produced")
            print(setup.capture_char_frame())
            return 1
        print(f"success   : {result.success}")
        print(f"method    : {result.method!r}")
        print(f"error     : {(result.error or '')[:200]}")
        print("log:")
        for line in (result.log or state.log())[-12:]:
            print(f"   | {line[:110]}")
        print("frame:")
        for line in setup.capture_char_frame().splitlines():
            print(f"   {line}")
        ok = state.phase() == "result" and (
            result.success or bool(result.error)
        )
        # A failure has to say what to change, not just that it failed.
        if not result.success:
            assert result.remedy, "a failure arrived with no advice attached"
        print("\nSMOKE OK" if ok else "\nSMOKE FAIL")
        return 0 if ok else 1
    finally:
        native.stop()
        setup.destroy()
        controller.stop_pending()


async def stored_key_check() -> int:
    """One key on a network this machine has already joined.

    This is the one path that can actually succeed here, so it is the one worth
    watching end to end: real profile, real netsh, real Enter. No capture and no
    hashcat are involved -- if either one starts running, something regressed.
    """
    from wifi_tool import profiles

    found = [p for p in profiles.read_all() if p.has_key]
    print(f"profiles  : {len(found)} with a readable key")
    if not found:
        print("SKIP: no saved profile with a readable key on this machine")
        return 0
    profile = found[0]
    print(f"target    : {profile.name!r} auth={profile.auth!r}")

    state.reset()
    controller.bind(None)
    setup = await test_render(App, {"width": 100, "height": 30})
    setup.render_frame()
    native = TestInputHandler()
    native.start()
    bind_event_loop(setup.renderer,
                    __import__("types").SimpleNamespace(input_handler=native,
                                                        on_frame=lambda cb: None))
    try:
        # Put the network in the list by hand: this check is about the stored-key
        # path, not about whether the scan finds it right now.
        from wifi_tool.models import Network

        net = Network(profile.name, "00:11:22:33:44:55", 6, 70, "WPA2-Personal", "CCMP")
        state.networks.set([net])
        state.selected.set(0)
        state.phase.set("scan")
        setup.render_frame()

        started = time.monotonic()
        native.feed("\r")  # scan -> audit
        for _ in range(50):
            await asyncio.sleep(0.1)
            setup.render_frame()
            if state.phase() == "audit":
                break
        assert state.phase() == "audit", "scan: Enter did not open the audit"
        frame = setup.capture_char_frame()
        assert "Поймаю рукопожатие" in frame or "Нужен файл" in frame, (
            f"audit: no run action\n{frame}")
        state.readiness.set(None)  # no blocker: the run must actually start
        native.feed("\r")  # audit -> run
        while time.monotonic() - started < 30 and state.phase() != "result":
            await asyncio.sleep(0.1)
            setup.render_frame()
        setup.render_frame()

        result = state.result.peek()
        if result is None:
            print("SMOKE: no result")
            print(setup.capture_char_frame())
            return 1
        print(f"success   : {result.success}")
        print(f"password  : {result.password!r}")
        print(f"method    : {result.method!r}")
        print(f"elapsed   : {result.elapsed:.2f}s")
        ok = result.success and result.password == profile.key
        ok = ok and result.method == "ключ Windows"
        print(setup.capture_char_frame())
        print("STORED KEY OK" if ok else "STORED KEY FAIL")
        return 0 if ok else 1
    finally:
        native.stop()
        setup.destroy()
        controller.stop_pending()


if __name__ == "__main__":
    # Both have to run: ``a or b`` would skip the second one whenever the first
    # succeeded, which is precisely the case that matters.
    codes = [asyncio.run(main()), asyncio.run(stored_key_check())]
    raise SystemExit(max(codes))