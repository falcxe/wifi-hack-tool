"""Stop and reap external tools on completion, failure, and cancellation."""
from __future__ import annotations

import asyncio
import contextlib


async def terminate(proc, timeout: float = 3.0) -> None:
    """Stop ``proc``, hard, and reap it.

    On Windows ``Popen.terminate()`` is ``TerminateProcess``: the child dies on
    the spot and never runs its own exit path, so whatever was still sitting in
    a write buffer is gone. That is why the capture backends are built to finish
    on their own -- ``tshark -a duration:<n>`` -- and why the capture stage gives
    a backend time to close its file once the timer expires. A signal that
    would let it shut down gracefully is deliberately not used: ``CTRL_BREAK``
    only reaches a process that leads its own console group, and when one does
    not, Windows applies it to *our* group instead -- measured here as the test
    runner being killed by its own cleanup. Stopping the child a little later,
    having already told it when to stop, costs nothing and cannot do that.
    """
    if proc.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.wait()