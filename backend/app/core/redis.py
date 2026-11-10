from typing import Optional
import json
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

# Fallback in-memory cache if Redis server is unreachable in local offline test mode
_local_cache = {}


class RedisService:
    def __init__(self):
        self._client = None
        self._connected = False

    async def connect(self):
        try:
            import redis.asyncio as aioredis
            self._client = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
            await self._client.ping()
            self._connected = True
            logger.info("Connected to Redis successfully.")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}), using thread-safe in-memory cache fallback.")
            self._connected = False

    async def get(self, key: str) -> Optional[str]:
        if self._connected and self._client:
            try:
                return await self._client.get(key)
            except Exception:
                pass
        return _local_cache.get(key)

    async def set(self, key: str, value: str, expire: int = 3600):
        if self._connected and self._client:
            try:
                await self._client.set(key, value, ex=expire)
                return
            except Exception:
                pass
        _local_cache[key] = value

    async def get_json(self, key: str) -> Optional[dict]:
        data = await self.get(key)
        if data:
            try:
                return json.loads(data)
            except Exception:
                return None
        return None

    async def set_json(self, key: str, value: dict, expire: int = 3600):
        await self.set(key, json.dumps(value), expire=expire)

    async def close(self):
        if self._connected and self._client:
            await self._client.close()


redis_client = RedisService()
