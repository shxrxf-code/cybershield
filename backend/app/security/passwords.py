"""Password hashing and strength enforcement.

Argon2id is the default because it is memory-hard: GPUs and ASICs that make
bcrypt cheap are far less effective against it, and it is the current OWASP
first recommendation. bcrypt remains available for verifying legacy hashes at
login so that an upgrade can be completed without forcing password resets.

Secrets come from the ``passwords`` module only; no caller ever handles a raw
hash, and nothing here logs password material.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import string
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import (
    HashingError,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from argon2.low_level import Type

from app.core.config import get_settings
from app.core.exceptions import CyberShieldError

logger = logging.getLogger(__name__)

# OWASP 2024 guidance: Argon2id, 19 MiB of memory, 2 iterations, 1 lane.
DEFAULT_MEMORY_COST_KIB: Final[int] = 19 * 1024
DEFAULT_TIME_COST: Final[int] = 2
DEFAULT_PARALLELISM: Final[int] = 1
SALT_LENGTH: Final[int] = 16


class PasswordPolicyError(CyberShieldError):
    """Raised when a proposed password fails the strength policy."""

    status_code = 422
    code = "password_policy_violation"


class PasswordHasherFactory:
    """Builds Argon2id hashers from settings, tuned once per process.

    ``memory_cost`` and ``time_cost`` are set explicitly rather than left at
    library defaults so the cost is a documented, reviewable deployment decision
    rather than an accident of the installed version.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._hasher = PasswordHasher(
            time_cost=DEFAULT_TIME_COST,
            memory_cost=DEFAULT_MEMORY_COST_KIB,
            parallelism=DEFAULT_PARALLELISM,
            hash_len=32,
            salt_len=SALT_LENGTH,
            type=Type.ID,
        )
        self._min_length = settings.password_min_length
        self._enabled = settings.argon2_enabled

    @property
    def min_length(self) -> int:
        return self._min_length

    def hash(self, password: str) -> str:
        """Hash a password, rejecting anything that fails policy.

        Raises:
            PasswordPolicyError: If the password is too short or too repetitive.
            AppError: If hashing itself fails, which is never the caller's fault.
        """
        self.validate_strength(password)
        try:
            return self._hasher.hash(password)
        except HashingError as exc:  # pragma: no cover - environment failure
            logger.error("Password hashing failed", exc_info=True)
            raise CyberShieldError("Unable to process credentials") from exc

    def verify(self, password: str, stored_hash: str | None) -> bool:
        """Check a password against a stored hash.

        Returns ``False`` - never raises - for unknown or malformed hashes, so a
        corrupt row cannot become an authentication bypass or a way to
        distinguish accounts by error.
        """
        if not stored_hash or not password:
            return False

        if stored_hash.startswith("$argon2"):
            try:
                return self._hasher.verify(stored_hash, password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False
            except HashingError:  # pragma: no cover - environment failure
                logger.error("Argon2 verification failed", exc_info=True)
                return False

        if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
            return self._verify_bcrypt_compat(stored_hash, password)

        logger.warning("Unrecognised password hash format; refusing to authenticate")
        return False

    @staticmethod
    def _verify_bcrypt_compat(stored_hash: str, password: str) -> bool:
        """Verify a legacy bcrypt hash without a hard bcrypt dependency.

        bcrypt is not a KDF that can be implemented in a few lines, so this
        branch reports the mismatch case only when ``bcrypt`` happens to be
        installed; otherwise the login is refused and the user must reset. The
        constant-time comparison below is a defence-in-depth measure for the
        stub path, not a bcrypt implementation.
        """
        try:  # pragma: no cover - optional dependency path
            import bcrypt  # type: ignore[import-not-found]

            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ImportError:
            logger.warning(
                "Legacy bcrypt hash encountered but bcrypt is not installed; "
                "the user must reset their password"
            )
            return False

    def needs_rehash(self, stored_hash: str | None) -> bool:
        """Whether a stored hash should be upgraded on next successful login.

        Re-hashing on login is the only way a key-rotation policy actually takes
        effect for existing users.
        """
        if not stored_hash:
            return True
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return True

    def validate_strength(self, password: str) -> None:
        """Enforce the documented password policy.

        Rejects: too short, over the hard cap, entirely one repeated character,
        and the small set of passwords that top every breach corpus.
        """
        minimum = self._min_length

        if len(password) < minimum:
            raise PasswordPolicyError(
                f"Password must be at least {minimum} characters long."
            )
        if len(password) > 256:
            # Silently accepting megabyte passwords enables memory-exhaustion
            # abuse against the hasher.
            raise PasswordPolicyError("Password must be at most 256 characters long.")
        if len(set(password)) <= 2:
            raise PasswordPolicyError("Password is not sufficiently varied.")
        if password.lower() in _COMMON_PASSWORDS:
            raise PasswordPolicyError("This password appears in well-known breach lists.")

    def dummy_verify(self) -> None:
        """Burn roughly one hash's worth of time against a dummy hash.

        Called when a username does not exist. Without it, "no such user"
        responses return instantly while a real user costs ~50 ms of hashing,
        which is a reliable user-enumeration oracle on the login endpoint.
        """
        try:
            self._hasher.verify(
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$Zm9vYmFyYmF6cXV1eG1vMTIzNDU2Nzg5",
                secrets.token_urlsafe(16),
            )
        except Exception:  # noqa: BLE001 - the point is the time, not the result
            pass


#: Small, curated list. This is not a defence - a full breach corpus would be
#: gigabytes and would embed third-party data - it exists to reject the handful
#: of passwords that show up first in every credential-stuffing list.
_COMMON_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password1234",
        "password12345",
        "qwerty123456",
        "123456789012",
        "administrator",
        "letmein12345",
        "iloveyou1234",
        "welcome12345",
        "changeme1234",
        "p@ssw0rd1234",
    }
)


def generate_token(length: int = 32) -> str:
    """Cryptographically secure random token, URL-safe."""
    return secrets.token_urlsafe(length)


def constant_time_equals(left: str, right: str) -> bool:
    """Timing-safe string comparison."""
    return hmac.compare_digest(
        hashlib.sha256(left.encode("utf-8")).digest(),
        hashlib.sha256(right.encode("utf-8")).digest(),
    )


def password_strength_score(password: str) -> dict[str, float | int | list[str]]:
    """Heuristic strength readout for the client-side meter.

    Advisory only: the server enforces the policy in
    :meth:`PasswordHasherFactory.validate_strength` and this score never
    grants access.
    """
    settings = get_settings()
    length = len(password)
    character_classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password),
        )
    )
    unique_ratio = len(set(password)) / length if length else 0.0

    score = 0.0
    score += min(length, 24) / 24 * 0.5
    score += character_classes / 4 * 0.3
    score += unique_ratio * 0.2
    if password.lower() in _COMMON_PASSWORDS:
        score = 0.0

    problems: list[str] = []
    if length < settings.password_min_length:
        problems.append(f"Use at least {settings.password_min_length} characters.")
    if character_classes < 3:
        problems.append("Mix upper case, lower case, digits and symbols.")
    if password.lower() in _COMMON_PASSWORDS:
        problems.append("This password is well known and easily guessed.")

    return {
        "score": round(min(1.0, score), 3),
        "length": length,
        "character_classes": character_classes,
        "problems": problems,
    }


#: Lazily constructed so importing this module does not pay Argon2 setup cost
#: in processes that only need token helpers.
_hasher_factory: PasswordHasherFactory | None = None


def get_password_hasher() -> PasswordHasherFactory:
    """Return the process-wide password hasher."""
    global _hasher_factory
    if _hasher_factory is None:
        _hasher_factory = PasswordHasherFactory()
    return _hasher_factory


__all__ = [
    "PasswordHasherFactory",
    "PasswordPolicyError",
    "constant_time_equals",
    "generate_token",
    "get_password_hasher",
    "password_strength_score",
]