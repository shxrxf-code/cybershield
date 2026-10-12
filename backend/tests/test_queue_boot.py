"""Boot lifecycle: the in-process scan worker starts regardless of config.

Setting ``USE_REDIS_QUEUE=true`` enables the shared Redis rate-limit store but
does **not** provide a distributed scan consumer. The in-process asyncio worker
must therefore always start, so an async scan submitted with that flag set can
never be enqueued and then silently never executed.
"""

from __future__ import annotations

from app.core.config import get_settings


async def test_worker_running_after_boot_with_redis_flag_enabled():
    from app.main import create_app
    from app.workers.queue import get_scan_queue, set_scan_queue

    set_scan_queue(None)
    try:
        cfg = get_settings().model_copy(update={"use_redis_queue": True})
        app = create_app(cfg)
        async with app.router.lifespan_context(app):
            assert get_scan_queue().running is True
    finally:
        set_scan_queue(None)


async def test_worker_running_after_boot_by_default():
    from app.main import create_app
    from app.workers.queue import get_scan_queue, set_scan_queue

    set_scan_queue(None)
    try:
        app = create_app(get_settings())
        async with app.router.lifespan_context(app):
            assert get_scan_queue().running is True
    finally:
        set_scan_queue(None)
