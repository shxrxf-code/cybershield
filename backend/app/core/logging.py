"""Structured logging with request correlation and secret redaction.

Logs are emitted as one JSON object per line in non-development environments so
that a log shipper can index them. Sensitive values (tokens, passwords, API keys,
raw email content) are redacted before serialisation.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from typing import Any, Final

from app.core.config import Settings

# Correlation ID for the current task; set by middleware, inherited by workers.
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
user_id_ctx: ContextVar[str | None] = ContextVar("user_id", default=None)

_REDACTED: Final = "***REDACTED***"

# Keys whose values must never reach a log sink, matched case-insensitively.
_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "new_password",
        "current_password",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "cookie",
        "set_cookie",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "client_secret",
        "private_key",
        "quarantine_encryption_key",
        "virustotal_api_key",
        "abuseipdb_api_key",
        "google_safebrowsing_api_key",
        "virustotal",
        "otp",
        "mfa_code",
    }
)

# Substrings that mark a key as sensitive even when not explicitly listed.
_SENSITIVE_SUBSTRINGS: Final[tuple[str, ...]] = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
)

_LOG_RECORD_BUILTINS: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively redact sensitive values from a structure destined for logs."""
    if _depth > 6:
        return "<truncated>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _SENSITIVE_KEYS or any(s in lowered for s in _SENSITIVE_SUBSTRINGS):
                result[str(key)] = _REDACTED
            else:
                result[str(key)] = redact(item, _depth + 1)
        return result
    if isinstance(value, (list, tuple, set)):
        return [redact(item, _depth + 1) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return f"<{type(value).__name__}>"


class ContextFilter(logging.Filter):
    """Attach the current request/user correlation IDs to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get() or "-"
        record.user_id = user_id_ctx.get() or "-"
        return True


class JsonFormatter(logging.Formatter):
    """Render a log record as a single redacted JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
            "user_id": getattr(record, "user_id", "-"),
        }

        # Promote structured ``extra={...}`` fields to top-level keys.
        for key, value in record.__dict__.items():
            if key in _LOG_RECORD_BUILTINS or key in payload or key.startswith("_"):
                continue
            payload[key] = redact(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human-readable formatter used during local development."""

    def format(self, record: logging.LogRecord) -> str:
        base = (
            f"{self.formatTime(record, '%H:%M:%S')} "
            f"{record.levelname:<8} "
            f"{record.name} "
            f"[{getattr(record, 'request_id', '-')}] "
            f"{record.getMessage()}"
        )
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _LOG_RECORD_BUILTINS
            and k not in {"request_id", "user_id"}
            and not k.startswith("_")
        }
        if extras:
            base += " | " + json.dumps(redact(extras), default=str)
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def configure_logging(settings: Settings) -> None:
    """Install the CyberShield logging configuration (idempotent)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if settings.log_json else TextFormatter())
    handler.addFilter(ContextFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    if settings.log_file is not None:
        from logging.handlers import RotatingFileHandler

        settings.log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            settings.log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(JsonFormatter())
        file_handler.addFilter(ContextFilter())
        root.addHandler(file_handler)

    # Uvicorn ships its own handlers; route them through ours for consistency.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True

    # Third-party loggers are noisy at INFO and can leak request URLs.
    for name in ("httpx", "httpcore", "urllib3", "asyncio", "sqlalchemy.engine"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger."""
    return logging.getLogger(name)