"""API router assembly.

Every functional route lives under ``/api/v1``. The router is kept dependency
free (pure registrations) so that importing this module never triggers
settings/database side effects; ``app.main.create_app`` wires it into a
FastAPI instance with middleware and exception handling.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import api_keys, auth, health, intel, quarantine, scans, users

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(api_keys.router)
api_router.include_router(scans.router)
api_router.include_router(intel.router)
api_router.include_router(quarantine.router)

__all__ = ["api_router"]