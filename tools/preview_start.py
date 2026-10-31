"""Ad-hoc: render the welcome screen at a few sizes and print the frames."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["WIFI_TOOL_NO_BOARD"] = "1"

from opentui.testing import test_render  # noqa: E402

from wifi_tool.ui import state  # noqa: E402
from wifi_tool.ui.app import App  # noqa: E402
from wifi_tool.pipeline import Readiness  # noqa: E402
from wifi_tool.scanner import AdapterInfo  # noqa: E402


def ready_ok():
    return Readiness(admin=True, adapter=AdapterInfo("Wi-Fi", "Intel(R) Wi-Fi 6E AX211", "b0:47:e9:6c:2f:64", "connected"),
                     hashcat=Path("assets/hashcat-7.1.2/hashcat.exe"), wordlist=Path("assets/rockyou-wpa.txt"),
                     backend=type("B", (), {"exe": "assets/tshark.exe"})(), iface="\\Device\\NPF_{ABC}")


def ready_bad():
    r = Readiness(admin=False, adapter=AdapterInfo("Wi-Fi", "Intel(R) Wi-Fi 6E AX211", "b0:47", "connected"))
    r.capture_problem = "драйвер не поддерживает режим монитора"
    return r


async def shot(ready, width, height, details=False, index=0):
    state.reset()
    state.phase.set("start")
    state.readiness.set(ready)
    state.scenario_index.set(index)
    state.start_details.set(details)
    obj = await test_render(App, {"width": width, "height": height})
    frame = obj.capture_char_frame()
    obj.destroy()
    return frame


def main() -> None:
    for label, ready in (("ok", ready_ok()), ("bad", ready_bad())):
        for width, height in ((100, 30), (60, 20)):
            frame = asyncio.run(shot(ready, width, height))
            print(f"=== {label} {width}x{height} ===")
            print(frame)
            print(f"--- rows: {len(frame.splitlines())} ---")
    frame = asyncio.run(shot(ready_bad(), 100, 30, details=True, index=1))
    print("=== bad 100x30 details, scenario=file ===")
    print(frame)


if __name__ == "__main__":
    main()