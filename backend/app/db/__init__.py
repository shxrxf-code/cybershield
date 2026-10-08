"""Async SQLAlchemy persistence layer.

Importing this package registers every table on ``Base.metadata``, which is what
``create_all`` and Alembic autogeneration rely on.
"""

from app.db.session import (
    create_engine,
    dispose_engine,
    get_db,
    get_engine,
    get_sessionmaker,
    init_models,
    session_scope,
)
from app.models.audit import AuditEvent, RateLimitEvent
from app.models.base import Base
from app.models.intel import ThreatIntelCache
from app.models.quarantine import QuarantineAccessLog, QuarantineItem
from app.models.scan import Scan, ScanFeedback
from app.models.user import ApiKey, User

__all__ = [
    "ApiKey",
    "AuditEvent",
    "Base",
    "QuarantineAccessLog",
    "QuarantineItem",
    "RateLimitEvent",
    "Scan",
    "ScanFeedback",
    "ThreatIntelCache",
    "User",
    "create_engine",
    "dispose_engine",
    "get_db",
    "get_engine",
    "get_sessionmaker",
    "init_models",
    "session_scope",
]