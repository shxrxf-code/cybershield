"""Authentication request and response schemas."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.config import get_settings

#: Practical ceiling; bcrypt-free but still blocks a "password" that is really a
#: pasted document.
MAX_PASSWORD_LENGTH = 256


def _validate_password_length(value: str) -> str:
    if len(value) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
    return value


class LoginRequest(BaseModel):
    """Credentials for the token endpoint."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(description="Registered account email address.")
    password: Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
    #: Optional client fingerprint, echoed back in the audit log.
    client: str | None = Field(default=None, max_length=64)

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(BaseModel):
    """Issued access and refresh tokens."""

    model_config = ConfigDict(extra="forbid")

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds.")
    refresh_expires_in: int = Field(description="Refresh token lifetime in seconds.")

    @classmethod
    def build(
        cls, access_token: str, refresh_token: str, access_ttl: int, refresh_ttl: int
    ) -> "TokenResponse":
        return cls(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=access_ttl,
            refresh_expires_in=refresh_ttl,
        )


class RefreshRequest(BaseModel):
    """Exchange a refresh token for a new pair."""

    model_config = ConfigDict(extra="forbid")

    refresh_token: Annotated[str, Field(min_length=10, max_length=4096)]


class PasswordChangeRequest(BaseModel):
    """Change the caller's own password."""

    model_config = ConfigDict(extra="forbid")

    current_password: Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
    new_password: Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]

    @field_validator("new_password")
    @classmethod
    def _check_new(cls, value: str) -> str:
        return _validate_password_length(value)


class PasswordStrengthRequest(BaseModel):
    """Ask the server for a strength readout. Never grants access."""

    model_config = ConfigDict(extra="forbid")

    password: Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]


class PasswordStrengthResponse(BaseModel):
    """Heuristic strength assessment. Advisory only."""

    score: float = Field(ge=0.0, le=1.0)
    length: int
    character_classes: int
    problems: list[str] = Field(default_factory=list)


class UserCreateRequest(BaseModel):
    """Registration payload."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
    full_name: str | None = Field(default=None, max_length=255)

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("full_name")
    @classmethod
    def _strip_name(cls, value: str | None) -> str | None:
        return value.strip() if value else None


class UserUpdateRequest(BaseModel):
    """Profile edit. Password changes go through the dedicated endpoint."""

    model_config = ConfigDict(extra="forbid")

    full_name: str | None = Field(default=None, max_length=255)


class UserResponse(BaseModel):
    """Public projection of a user.

    Deliberately contains no password hash, no lockout counters and no internal
    timestamps: ``model_dump()`` on this object is safe to log or return
    verbatim, which removes the temptation to hand-roll a response and
    accidentally leak a column.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    full_name: str | None
    is_active: bool
    is_admin: bool
    is_verified: bool
    created_at: datetime
    last_login_at: datetime | None


class ApiKeyCreateRequest(BaseModel):
    """Create a machine credential."""

    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=120)]
    scopes: list[str] = Field(default_factory=lambda: ["scan:read"])
    expires_in_days: int | None = Field(default=None, ge=1, le=365)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"[\w .\-]{1,120}", cleaned, flags=re.UNICODE):
            raise ValueError("Key name may contain only letters, digits, spaces, '.', '-' and '_'.")
        return cleaned


class ApiKeyResponse(BaseModel):
    """API key metadata. ``plaintext`` is populated only at creation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    prefix: str
    scopes: list[str]
    is_active: bool
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    #: Present exactly once, in the creation response.
    plaintext: str | None = Field(
        default=None,
        description="Shown once. It cannot be recovered later, by anyone.",
    )


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=255)


def default_password_min_length() -> int:
    """Configured minimum password length, for client-side validation hints."""
    return get_settings().password_min_length


__all__ = [
    "ApiKeyCreateRequest",
    "ApiKeyResponse",
    "LoginRequest",
    "PasswordChangeRequest",
    "PasswordStrengthRequest",
    "PasswordStrengthResponse",
    "RefreshRequest",
    "RevokeRequest",
    "TokenResponse",
    "UserCreateRequest",
    "UserResponse",
    "UserUpdateRequest",
]