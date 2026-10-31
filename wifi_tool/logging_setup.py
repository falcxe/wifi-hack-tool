"""File logging for support and bug reports."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from .bootstrap import log_path


def setup(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("wifi_tool")
    if logger.handlers:
        return logger
    logger.setLevel(level)
    path = log_path()
    try:
        handler = logging.FileHandler(path, encoding="utf-8", mode="w")
    except OSError:
        return logger
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    return logger