"""Shared fixtures and test-environment bootstrap.

The environment is pinned **at import time**, before any application module is
imported, because ``app.core.config.get_settings()`` constructs a fresh
``Settings`` from the process environment on every call (no caching). A single
shared SQLite database is used for the whole session; tests create their own
users and rows with unique identifiers so they stay independent even though the
schema is shared.

Third-party threat-intel keys that happen to be present in the developer's
shell are removed so no test can accidentally make a live outbound lookup.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

import pytest

_session_root = Path(tempfile.mkdtemp(prefix="cybershield-test-"))

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_session_root}/test.db"
os.environ["STORAGE_ROOT"] = str(_session_root / "storage")
os.environ["SECRET_KEY"] = "test-secret-key-0123456789abcdef"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "1"
os.environ["RATE_LIMIT_ENABLED"] = "true"
os.environ["RATE_LIMIT_DEFAULT_PER_MINUTE"] = "1000"
os.environ["RATE_LIMIT_AUTH_PER_MINUTE"] = "1000"
os.environ["RATE_LIMIT_SCAN_PER_MINUTE"] = "1000"
os.environ["RATE_LIMIT_FILE_SCAN_PER_MINUTE"] = "1000"
os.environ["MAX_FAILED_LOGINS"] = "5"
os.environ["LOCKOUT_MINUTES"] = "15"
os.environ["QUARANTINE_ENABLED"] = "true"
os.environ["QUARANTINE_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["TRUST_PROXY_HEADERS"] = "false"

# No third-party lookups from the test suite, ever.
for _var in ("VIRUSTOTAL_API_KEY", "OTX_API_KEY", "IPQUALITYSCORE_API_KEY"):
    os.environ.pop(_var, None)


TEST_PASSWORD = "Test-Pass-1234!"


@pytest.fixture(autouse=True)
async def _fresh_schema() -> None:
    """Re-point the engine at the test database and (re)create tables.

    ``create_all`` is idempotent, but disposing the engine first guarantees a
    test never reuses a connection pool created in a closed event loop.
    """
    from app.db.session import dispose_engine, init_models

    await dispose_engine()
    await init_models()
    yield
    await dispose_engine()


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    """Drop process-level service singletons so tests start clean."""
    yield
    from app.services.quarantine import set_quarantine_service
    from app.services.scan_service import set_scan_service
    from app.workers.queue import set_scan_queue

    set_scan_service(None)
    set_scan_queue(None)
    set_quarantine_service(None)


@pytest.fixture
async def db():
    """One async session with auto-commit/rollback semantics (worker-style)."""
    from app.db.session import session_scope

    async with session_scope() as session:
        yield session


@pytest.fixture
def make_user():
    """Create a user directly (no HTTP) and return its credentials."""

    async def _make(*, admin: bool = False, active: bool = True, email: str | None = None) -> dict:
        from sqlalchemy import select

        from app.models.base import utcnow
        from app.models.user import User
        from app.security.passwords import get_password_hasher

        from app.db.session import session_scope

        resolved_email = email or f"user-{uuid.uuid4().hex[:12]}@test.dev"
        async with session_scope() as s:
            existing = (
                await s.execute(select(User).where(User.email == resolved_email))
            ).scalar_one_or_none()
            if existing is not None:
                return {"id": existing.id, "email": resolved_email, "password": TEST_PASSWORD}
            user = User(
                email=resolved_email,
                password_hash=get_password_hasher().hash(TEST_PASSWORD),
                full_name="Test Person",
                is_active=active,
                is_admin=admin,
                is_verified=True,
                password_changed_at=utcnow(),
            )
            s.add(user)
            await s.flush()
            return {"id": user.id, "email": resolved_email, "password": TEST_PASSWORD}

    return _make


@pytest.fixture
def token_headers():
    """Sign an access token for a user (no HTTP round-trip)."""

    async def _headers(user_id, email: str, *, admin: bool = False) -> dict[str, str]:
        from app.api.deps import ADMIN_SCOPE, USER_SCOPES
        from app.security.tokens import get_token_service

        scopes = sorted(USER_SCOPES)
        if admin:
            scopes.append(ADMIN_SCOPE)
        access, _refresh = get_token_service().create_token_pair(
            subject=str(user_id), email=email, scopes=scopes
        )
        return {"Authorization": f"Bearer {access}"}

    return _headers


@pytest.fixture
async def user(make_user):
    """A standard account with ready-to-use headers."""
    info = await make_user(admin=False)
    return info


@pytest.fixture
async def user_headers(user, token_headers):
    return await token_headers(user["id"], user["email"])


@pytest.fixture
async def admin_headers(make_user, token_headers):
    info = await make_user(admin=True)
    return await token_headers(info["id"], info["email"], admin=True)


@pytest.fixture
async def client():
    """HTTP client against a live ASGI app with lifespan (queue worker up)."""
    import httpx

    from app.main import create_app

    app = create_app()
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            yield http


@pytest.fixture
def api_key_login(client):
    """Factory that creates an API key over HTTP and returns its plaintext."""

    async def _make(user_headers: dict[str, str]) -> tuple[str, dict]:
        response = await client.post(
            "/api/v1/api-keys",
            headers=user_headers,
            json={"name": "ci-key", "scopes": ["scan:read", "scan:write"]},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        return body["plaintext"], {"X-API-Key": body["plaintext"]}

    return _make