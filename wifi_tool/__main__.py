"""``python -m wifi_tool`` -- same entry point as the ``wifi-tool`` script."""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)