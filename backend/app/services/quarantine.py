"""Quarantine storage: encrypted-at-rest blobs tied to a retention deadline.

Responsibilities
----------------
* **Write**: an opaque storage key, a possibly AES-GCM-encrypted blob under the
  quarantine directory with a path-containment check, and a
  :class:`~app.models.quarantine.QuarantineItem` row.
* **Read**: integrity-verified, decrypted bytes. A blob whose SHA-256 no longer
  matches the record is refused, because it was altered outside this service.
* **Release/delete/reap**: every action is audited in
  :class:`~app.models.quarantine.QuarantineAccessLog`.

Hard guarantees
---------------
* The client-supplied filename is *never* used to build a path.
* Blobs are never executed, mounted, opened as media, or otherwise interpreted.
* When ``quarantine_encryption_key`` is configured the blob is encrypted before
  it touches disk; if the key is set but the ``cryptography`` package is missing,
  quarantine fails closed rather than degrading to plaintext.
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.exceptions import QuarantineError
from app.models.base import utcnow
from app.models.quarantine import (
    DEFAULT_QUARANTINE_RETENTION_DAYS,
    QuarantineAccessLog,
    QuarantineItem,
)
from app.security.sanitize import safe_join
from app.services.audit import log_audit

logger = logging.getLogger(__name__)

#: Magic prefix of the at-rest envelope, so corruption and version skew are
#: detected on read rather than surfacing as a decrypt error.
_ENVELOPE_MAGIC: bytes = b"CBSQ1"
#: Associated data binds the envelope to this service's purpose.
_AAD: bytes = b"cybershield-quarantine-v1"


class _Crypto:
    """Lazily imported AES-GCM helper. ``available`` is False without ``cryptography``."""

    available: bool = bool(importlib.util.find_spec("cryptography"))

    @staticmethod
    def derive_key(secret: str) -> bytes:
        """SHA-256 of the configured secret.

        The secret is a high-entropy environment value, so a plain SHA-256 wrap
        (rather than a KDF) is appropriate: there is no guessable entropy to
        slow down.
        """
        return hashlib.sha256(secret.encode("utf-8")).digest()

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = secrets.token_bytes(12)
        aessiv = AESGCM(key)
        sealed = aessiv.encrypt(nonce, plaintext, _AAD)
        return _ENVELOPE_MAGIC + nonce + sealed

    @staticmethod
    def decrypt(key: bytes, blob: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not blob.startswith(_ENVELOPE_MAGIC) or len(blob) < len(_ENVELOPE_MAGIC) + 12 + 16:
            raise QuarantineError("Quarantined blob is not a valid CyberShield envelope.")
        offset = len(_ENVELOPE_MAGIC)
        nonce = blob[offset : offset + 12]
        sealed = blob[offset + 12 :]
        try:
            return AESGCM(key).decrypt(nonce, sealed, _AAD)
        except Exception as exc:  # noqa: BLE001 - cryptography raises several types
            raise QuarantineError("Quarantined blob failed authenticity verification.") from exc


@dataclass(slots=True)
class StoredQuarantine:
    """What a read returns: the item record plus its verified bytes."""

    item: QuarantineItem
    data: bytes


class QuarantineService:
    """Owns byte-level quarantine operations; DB rows are managed here too."""

    def __init__(self, settings: Settings | None = None, crypto: type[_Crypto] | None = None) -> None:
        self._settings = settings or get_settings()
        self._crypto = crypto or _Crypto
        if self._settings.quarantine_encryption_key and not self._crypto.available:
            raise QuarantineError(
                "QUARANTINE_ENCRYPTION_KEY is set but the cryptography package is not "
                "installed. Quarantine refuses to store plaintext; install cryptography "
                "or remove the key."
            )

    @property
    def enabled(self) -> bool:
        return self._settings.quarantine_enabled

    @property
    def retention_days(self) -> int:
        return self._settings.quarantine_retention_days

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    async def store_blob(
        self,
        db: AsyncSession,
        *,
        data: bytes,
        scan_id: Any,
        user_id: Any | None,
        original_filename: str,
        size_bytes: int,
        sha256: str,
        sha1: str | None,
        md5: str | None,
        detected_type: str | None,
        verdict: str | None,
        score: float | None,
        reason: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> QuarantineItem:
        """Encrypt (when configured), store, and record the item."""
        if not self.enabled:
            raise QuarantineError("Quarantine is disabled by configuration.")
        if not data:
            raise QuarantineError("Cannot quarantine an empty blob.")

        storage_key = secrets.token_hex(24)
        target = safe_join(self._settings.quarantine_dir, storage_key)
        target.parent.mkdir(parents=True, exist_ok=True)

        encrypting = self._settings.quarantine_encryption_key is not None
        key = self._crypto.derive_key(self._settings.quarantine_encryption_key) if encrypting else None
        stored = self._crypto.encrypt(key, data) if encrypting else data
        integrity_hash = hashlib.sha256(stored).hexdigest()

        try:
            with target.open("wb") as handle:
                handle.write(stored)
        except OSError as exc:
            raise QuarantineError(f"Could not write quarantined copy: {exc.strerror or exc}") from exc

        item = QuarantineItem(
            scan_id=scan_id,
            user_id=user_id,
            storage_key=storage_key,
            original_filename=original_filename[:255],
            size_bytes=size_bytes,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            detected_type=detected_type,
            verdict=verdict,
            score=score,
            reason=reason,
            stored_integrity_hash=integrity_hash,
            is_encrypted=encrypting,
            encryption_algorithm="AES-256-GCM" if encrypting else None,
            metadata_json=metadata,
            expires_at=self._deadline(),
        )
        db.add(item)
        await db.flush()
        logger.info(
            "quarantine_store",
            extra={"storage_key": storage_key[:12], "size_bytes": size_bytes, "encrypted": encrypting},
        )
        return item

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    async def read_blob(
        self,
        db: AsyncSession,
        item: QuarantineItem,
        *,
        actor_id: Any | None = None,
    ) -> StoredQuarantine:
        """Return verified, decrypted bytes, auditing the read."""
        path = safe_join(self._settings.quarantine_dir, item.storage_key)
        try:
            stored = path.read_bytes()
        except OSError as exc:
            raise QuarantineError(f"Cannot read quarantined copy: {exc.strerror or exc}") from exc

        if item.stored_integrity_hash is None:
            raise QuarantineError("Quarantined record is missing its integrity hash.")
        if hashlib.sha256(stored).hexdigest() != item.stored_integrity_hash:
            raise QuarantineError(
                "Quarantined blob failed integrity verification and was refused. "
                "It was modified outside this service."
            )

        if item.is_encrypted:
            if not self._settings.quarantine_encryption_key:
                raise QuarantineError(
                    "The quarantined blob is encrypted but QUARANTINE_ENCRYPTION_KEY is no longer set."
                )
            key = self._crypto.derive_key(self._settings.quarantine_encryption_key)
            data = self._crypto.decrypt(key, stored)
        else:
            data = stored

        db.add(
            QuarantineAccessLog(
                quarantine_id=item.id,
                user_id=actor_id,
                action="read",
            )
        )
        return StoredQuarantine(item=item, data=data)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def delete(
        self,
        db: AsyncSession,
        item: QuarantineItem,
        *,
        actor_id: Any | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Delete the blob and the row, auditing the deletion."""
        path = safe_join(self._settings.quarantine_dir, item.storage_key)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:  # pragma: no cover - unlink rarely fails
            raise QuarantineError(f"Could not delete quarantined copy: {exc.strerror or exc}") from exc
        db.add(
            QuarantineAccessLog(
                quarantine_id=item.id,
                user_id=actor_id,
                action="delete",
                source_ip=source_ip,
                user_agent=user_agent,
            )
        )
        await db.delete(item)
        await log_audit(
            db,
            action="quarantine.delete",
            actor_id=actor_id,
            target_type="quarantine_item",
            target_id=str(item.id),
            source_ip=source_ip,
            user_agent=user_agent,
            message=f"Quarantined file {item.original_filename!r} deleted.",
        )

    async def release(
        self,
        db: AsyncSession,
        item: QuarantineItem,
        *,
        actor_id: Any | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> StoredQuarantine:
        """Return verified bytes for a release, marking the item released."""
        read = await self.read_blob(db, item, actor_id=actor_id)
        item.is_released = True
        item.released_at = utcnow()
        db.add(
            QuarantineAccessLog(
                quarantine_id=item.id,
                user_id=actor_id,
                action="release",
                source_ip=source_ip,
                user_agent=user_agent,
            )
        )
        await log_audit(
            db,
            action="quarantine.release",
            actor_id=actor_id,
            target_type="quarantine_item",
            target_id=str(item.id),
            source_ip=source_ip,
            user_agent=user_agent,
            message=f"Quarantined file {item.original_filename!r} released.",
        )
        return read

    async def reap_expired(self, db: AsyncSession) -> int:
        """Delete every item past its retention window. Returns the count."""
        now = utcnow()
        rows = (
            await db.execute(select(QuarantineItem).where(QuarantineItem.expires_at.is_not(None)))
        ).scalars().all()
        removed = 0
        for item in rows:
            if item.is_expired(now):
                path = safe_join(self._settings.quarantine_dir, item.storage_key)
                try:
                    path.unlink(missing_ok=True)
                except OSError:  # pragma: no cover - best effort
                    logger.warning("quarantine_reap_unlink_failed", extra={"key": item.storage_key})
                    continue
                db.add(
                    QuarantineAccessLog(
                        quarantine_id=item.id, action="reap"
                    )
                )
                await db.delete(item)
                removed += 1
        if removed:
            logger.info("quarantine_reaped", extra={"count": removed})
        return removed

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _deadline(self) -> datetime:
        return utcnow() + timedelta(days=self.retention_days)


_quarantine: QuarantineService | None = None


def get_quarantine_service(settings: Settings | None = None) -> QuarantineService:
    """Return the process-wide quarantine service."""
    global _quarantine
    if _quarantine is None:
        _quarantine = QuarantineService(settings)
    return _quarantine


def set_quarantine_service(service: QuarantineService | None) -> None:
    """Replace the service, for tests."""
    global _quarantine
    _quarantine = service


__all__ = [
    "QuarantineService",
    "StoredQuarantine",
    "get_quarantine_service",
    "set_quarantine_service",
]