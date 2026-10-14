"""Entry point for a bare clone: ``python main.py``.

All the work is in :mod:`wifi_tool.cli`, so that the same code serves both this
file and the installed ``wifi-tool`` console script. Run it directly rather
than importing it -- the UAC re-launch restarts ``sys.argv[0]``.
"""
from __future__ import annotations

from wifi_tool.cli import main

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)