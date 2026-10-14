"""Корень репозитория в ``sys.path``.

С ``uv sync`` пакет и так установлен, и это не нужно. Но тесты должны
запускаться и на голом клоне без установки -- ``python tests/test_parser.py``
из README не должен падать на ``ModuleNotFoundError: wifi_tool`` раньше, чем
покажет свою настоящую ошибку.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))