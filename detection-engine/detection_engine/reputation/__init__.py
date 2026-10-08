"""Threat-intelligence abstraction, offline store and aggregation."""

from __future__ import annotations

from .aggregator import CacheEntry, ReputationAggregator, TTLCache
from .base import (
    IndicatorType,
    IndicatorVerdict,
    ProviderResult,
    ProviderStatus,
    ThreatIntelProvider,
)
from .local import LocalIndicator, LocalIndicatorProvider, LocalIndicatorStore

__all__ = [
    "CacheEntry",
    "ReputationAggregator",
    "TTLCache",
    "IndicatorType",
    "IndicatorVerdict",
    "ProviderResult",
    "ProviderStatus",
    "ThreatIntelProvider",
    "LocalIndicator",
    "LocalIndicatorProvider",
    "LocalIndicatorStore",
]