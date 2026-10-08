"""User, API-key and session models.

Password material is never stored in reversible form: only an Argon2id hash and
the parameters used to produce it are persisted, so a database compromise does
not yield credentials and hashes remain verifiable after the cost parameters are
raised.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.scan import Scan


class User(BaseModel):
    """An account that can authenticate against the API.

    ``is_active`` is checked on every request in addition to token validity, so
    disabling an account takes effect immediately rather than when the access
    token happens to expire.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    #: Argon2id PHC string (``$argon2id$v=19$m=...,t=...,p=...$salt$hash``).
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

    def is_locked(self, now: datetime | None = None) -> bool:
        """Whether the account is inside its failed-login lockout window."""
        if self.locked_until is None:
            return False
        from app.models.base import utcnow

        reference = now or utcnow()
        lock_until = self.locked_until
        if lock_until.tzinfo is None:
            lock_until = lock_until.replace(tzinfo=reference.tzinfo)
        return lock_until > reference

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User id={self.id} email={self.email!r} active={self.is_active}>"


class ApiKey(BaseModel):
    """A long-lived machine credential for CLI and CI use.

    Only a **hash** of the key is stored. The plaintext exists exactly once, in
    the response to the creation request, because an operator who cannot recover
    it cannot use it - and a recoverable key in a database is a liability. The
    optional ``prefix`` is a non-secret short handle (``cs_live_ab12``) that lets
    a human identify a key without being able to replay it.
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_user_active", "user_id", "is_active"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: Non-secret display handle.
    prefix: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    #: SHA-256 of the full key. Lookup keys are high-entropy random values, so a
    #: fast hash is appropriate here - Argon2 would only slow down the lookup.
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_prefix_pepper: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scopes: Mapped[str] = mapped_column(String(255), default="scan:read,scan:write", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="api_keys")

    @property
    def scope_list(self) -> list[str]:
        return [scope for scope in self.scopes.split(",") if scope]

    def is_usable(self, now: datetime | None = None) -> bool:
        """Whether the key may currently authenticate a request."""
        from app.models.base import utcnow

        if not self.is_active or self.revoked_at is not None:
            return False
        if self.expires_at is None:
            return True
        expires = self.expires_at
        reference = now or utcnow()
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=reference.tzinfo)
        return expires > reference

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ApiKey id={self.id} name={self.name!r} prefix={self.prefix!r}>"


__all__ = ["ApiKey", "User"]