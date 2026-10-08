"""Defensive YARA rule set for CyberShield.

``load_rules`` and :class:`YaraEngine` are re-exported here so callers can simply
``from detection_engine.yara import get_engine``.
"""

from __future__ import annotations

from .engine import (
    DEFAULT_RULES_DIR,
    RuleLoadResult,
    YaraEngine,
    YaraMatch,
    get_engine,
    load_rules,
)

__all__ = [
    "DEFAULT_RULES_DIR",
    "RuleLoadResult",
    "YaraEngine",
    "YaraMatch",
    "get_engine",
    "load_rules",
]