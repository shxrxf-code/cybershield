"""Request rate limiting.

Two backends
------------
* **Redis** - correct for multi-replica deployments, where an in-process counter
  would let an attacker multiply their budget by the replica count.
* **In-process** - used when Redis is unavailable (tests, single-container
  development). It is explicitly *per process*, and :attr:`LimiterState.degraded`
  reports that so health checks and logs can say so rather than implying the
  limit is global.

Algorithm
---------
Sliding-window counter implemented as two fixed buckets (current and previous)
weighted by how much of each window has elapsed. This avoids the burst
admission a fixed window permits at a boundary while needing only one Redis
round trip via a Lua script, which keeps the check atomic.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Final

from app.core.config import get_settings
from app.core.exceptions import RateLimitError

#: Lua keeps the read-modify-write atomic. Doing it in Python would allow two
#: concurrent requests to both observe "under the limit" and both be admitted.
_SLIDING_WINDOW_LUA: Final[str] = """
local current = redis.call('GET', KEYS[1])
local previous = redis.call('GET', KEYS[2])
current = tonumber(current) or 0
previous = tonumber(previous) or 0
local weight = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local effective = current + previous * weight
if effective >= limit then
  redis.call('PEXPIRE', KEYS[1], math.ceil(window * 2000))
  redis.call('PEXPIRE', KEYS[2], math.ceil(window * 2000))
  return {0, effective}
end
local used = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], math.ceil(window * 2000))
redis.call('PEXPIRE', KEYS[2], math.ceil(window * 2000))
return {1, effective + 1}
"""


@dataclass(frozen=True, slots=True)
class RateLimit:
    """A limit definition: how many requests per rolling window."""

    requests: int
    window_seconds: float = 60.0

    def key(self, bucket: str, identifier: str) -> str:
        return f"rl:{bucket}:{identifier}"


@dataclass(slots=True)
class LimitResult:
    """Outcome of a limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_after: float
    degraded: bool = False


@dataclass
class _LocalWindow:
    count: int = 0
    started: float = field(default_factory=time.monotonic)


class LimiterState:
    """Holds the in-process fallback counters."""

    def __init__(self) -> None:
        self._windows: dict[str, _LocalWindow] = {}
        self._lock = asyncio.Lock()
        self.degraded = False

    async def hit(self, key: str, limit: int, window: float) -> LimitResult:
        now = time.monotonic()
        async with self._lock:
            bucket = self._windows.get(key)
            if bucket is None or now - bucket.started >= window:
                bucket = _LocalWindow(count=0, started=now)
                self._windows[key] = bucket
            bucket.count += 1
            allowed = bucket.count <= limit
            reset = window - (now - bucket.started)
            # Opportunistic cleanup keeps the dict from growing without bound
            # when identifiers churn (unique client IPs, API key ids).
            if len(self._windows) > 10_000:
                self._windows = {
                    k: v for k, v in self._windows.items() if now - v.started < window
                }
        return LimitResult(
            allowed=allowed,
            limit=limit,
            remaining=max(0, limit - bucket.count),
            reset_after=max(0.0, reset),
            degraded=True,
        )


_state = LimiterState()


class RateLimiter:
    """Sliding-window rate limiter with Redis and local backends."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self._settings = get_settings()
        self._redis = redis_client
        self._rules: dict[str, RateLimit] = {
            "default": RateLimit(
                self._settings.rate_limit_default_per_minute, 60.0
            ),
            "auth": RateLimit(self._settings.rate_limit_auth_per_minute, 60.0),
            "scan": RateLimit(self._settings.rate_limit_scan_per_minute, 60.0),
            "file_scan": RateLimit(self._settings.rate_limit_file_scan_per_minute, 60.0),
        }
        self._script_sha: str | None = None

    @property
    def rules(self) -> dict[str, RateLimit]:
        return dict(self._rules)

    def rule_for(self, bucket: str) -> RateLimit:
        return self._rules.get(bucket, self._rules["default"])

    async def check(self, bucket: str, identifier: str) -> LimitResult:
        """Record a hit and report whether it is allowed.

        Returns a result rather than raising so callers can attach
        ``X-RateLimit-*`` headers on success as well as failure.
        """
        rule = self.rule_for(bucket)
        if not self._settings.rate_limit_enabled:
            return LimitResult(True, rule.requests, rule.requests, 0.0)

        client = await self._get_redis()
        if client is None:
            return await _state.hit(rule.key(bucket, identifier), rule.requests, rule.window_seconds)

        window_ms = int(rule.window_seconds * 1000)
        current_bucket = int(time.time() // rule.window_seconds)
        current_key = f"{rule.key(bucket, identifier)}:{current_bucket}"
        previous_key = f"{rule.key(bucket, identifier)}:{current_bucket - 1}"

        # Fraction of the previous window still "in play" at this instant.
        elapsed = (time.time() % rule.window_seconds) / rule.window_seconds
        weight = 1.0 - elapsed

        try:
            allowed, effective = await self._execute(
                client, current_key, previous_key, weight, rule.requests, window_ms
            )
        except Exception:  # noqa: BLE001 - availability must not become an outage
            _state.degraded = True
            return await _state.hit(rule.key(bucket, identifier), rule.requests, rule.window_seconds)

        _state.degraded = False
        return LimitResult(
            allowed=bool(allowed),
            limit=rule.requests,
            remaining=max(0, int(rule.requests - effective)),
            reset_after=rule.window_seconds * (1 - elapsed),
        )

    async def enforce(self, bucket: str, identifier: str) -> LimitResult:
        """Like :meth:`check` but raises :class:`RateLimitError` when limited.

        Raises:
            RateLimitError: With a ``Retry-After`` value derived from the window.
        """
        result = await self.check(bucket, identifier)
        if not result.allowed:
            raise RateLimitError(retry_after=max(1, int(result.reset_after)))
        return result

    async def peek(self, bucket: str, identifier: str) -> int:
        """Current usage without incrementing. Best effort."""
        rule = self.rule_for(bucket)
        client = await self._get_redis()
        if client is None:
            window = _state._windows.get(rule.key(bucket, identifier))  # noqa: SLF001
            return window.count if window else 0
        try:
            key = f"{rule.key(bucket, identifier)}:{int(time.time() // rule.window_seconds)}"
            value = await client.get(key)
            return int(value) if value else 0
        except Exception:  # noqa: BLE001
            return 0

    async def reset(self, bucket: str, identifier: str) -> None:
        """Clear an identifier's counter, e.g. after a successful login."""
        rule = self.rule_for(bucket)
        client = await self._get_redis()
        if client is None:
            _state._windows.pop(rule.key(bucket, identifier), None)
            return
        try:
            pattern = rule.key(bucket, identifier)
            keys = [key async for key in client.scan_iter(match=f"{pattern}:*", count=100)]
            if keys:
                await client.delete(*keys)
        except Exception:  # noqa: BLE001
            return

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _get_redis(self) -> Any | None:
        if self._redis is not None:
            return self._redis
        if not self._settings.use_redis_queue:
            return None
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(
                self._settings.redis_url, decode_responses=True, socket_timeout=1.0
            )
            await client.ping()
        except Exception:  # noqa: BLE001 - availability must not become an outage
            _state.degraded = True
            return None
        self._redis = client
        _state.degraded = False
        return client

    async def _execute(
        self,
        client: Any,
        current_key: str,
        previous_key: str,
        weight: float,
        limit: int,
        window_ms: int,
    ) -> tuple[int, float]:
        """Run the atomic sliding-window script, with a client-side fallback."""
        try:
            result = await client.eval(
                _SLIDING_WINDOW_LUA,
                2,
                current_key,
                previous_key,
                weight,
                limit,
                window_ms,
            )
            return int(result[0]), float(result[1])
        except AttributeError:
            # A fake/mocked client in tests may not implement eval().
            return await self._execute_pipelined(
                client, current_key, previous_key, weight, limit, window_ms
            )

    async def _execute_pipelined(
        self,
        client: Any,
        current_key: str,
        previous_key: str,
        weight: float,
        limit: int,
        window_ms: int,
    ) -> tuple[int, float]:
        pipe = client.pipeline(transaction=True)
        pipe.incr(current_key)
        pipe.pexpire(current_key, window_ms * 2)
        previous = await client.get(previous_key)
        counts = await pipe.execute()
        used = int(counts[0]) + int(previous or 0) * weight
        return (1 if used <= limit else 0), float(used)


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the process-wide rate limiter."""
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


def set_rate_limiter(limiter: RateLimiter | None) -> None:
    """Replace the limiter, for tests and worker configuration."""
    global _limiter
    _limiter = limiter


def get_limiter_state() -> LimiterState:
    """Return the process-wide limiter state.

    Health checks use ``degraded`` to report that the in-process fallback is in
    use because Redis is unreachable, so an operator sees the truth rather than
    an implied global limit.
    """
    return _state


__all__ = [
    "LimitResult",
    "LimiterState",
    "RateLimit",
    "RateLimiter",
    "get_limiter_state",
    "get_rate_limiter",
    "set_rate_limiter",
]