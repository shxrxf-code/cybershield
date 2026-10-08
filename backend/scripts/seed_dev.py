#!/usr/bin/env python
"""Seed local-development accounts for a first run of the API.

Creates two accounts behind fixed, clearly-marked dev-only credentials:

* ``admin@cybershield.dev`` / ``CyberShield!dev2026-Admin`` (administrator)
* ``analyst@cybershield.dev`` / ``CyberShield!dev2026-Analyst``

Passwords are hashed with the application's own Argon2id pipeline and stored in
PHC form, so the rows this script writes are verified by exactly the same code
the login route uses. The script is idempotent: an existing account is left
untouched, never re-created or re-hashed.

.. warning::

   These are development-only credentials. The account rows are created in the
   configured database whatever its environment, so only run this against a
   database you own.

Usage, from the ``backend`` directory::

    python -m scripts.seed_dev
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from app.db.session import init_models, session_scope  # noqa: E402
from app.models.base import utcnow  # noqa: E402
from app.models.user import User  # noqa: E402
from app.security import get_password_hasher  # noqa: E402

DEV_ACCOUNTS = (
    {
        "email": "admin@cybershield.dev",
        "password": "CyberShield!dev2026-Admin",
        "full_name": "CyberShield Dev Administrator",
        "is_admin": True,
    },
    {
        "email": "analyst@cybershield.dev",
        "password": "CyberShield!dev2026-Analyst",
        "full_name": "CyberShield Dev Analyst",
        "is_admin": False,
    },
)


async def seed() -> int:
    """Create the dev accounts, returning how many were inserted."""
    await init_models()
    hasher = get_password_hasher()
    created = 0
    async with session_scope() as session:
        for account in DEV_ACCOUNTS:
            existing = await session.scalar(
                select(User).where(User.email == account["email"])
            )
            if existing is not None:
                continue
            session.add(
                User(
                    email=account["email"],
                    password_hash=hasher.hash(account["password"]),
                    full_name=account["full_name"],
                    is_active=True,
                    is_admin=account["is_admin"],
                    is_verified=True,
                    password_changed_at=utcnow(),
                )
            )
            created += 1
            print(f"created {account['email']} (is_admin={account['is_admin']})")
    return created


def main() -> None:
    import asyncio

    created = asyncio.run(seed())
    print("done;", created, "account(s) created, existing accounts left untouched")


if __name__ == "__main__":
    main()