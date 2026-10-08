"""Centralised exception hierarchy and API error translation.

Every error surfaced to a client passes through :class:`CyberShieldError` so that
responses share one stable envelope::

    {
      "error": {
        "code": "scan_failed",
        "message": "Human readable summary.",
        "status_code": 500,
        "correlation_id": "...",
        "details": {...}
      }
    }

Internal exception text (stack traces, file paths, provider payloads) is never
placed in ``message``; it is logged and returned only as a correlation ID.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, request_id_ctx

logger = get_logger(__name__)


class ErrorCode:
    """Canonical machine-readable error codes."""

    AUTH_REQUIRED = "auth_required"
    AUTH_INVALID = "auth_invalid"
    AUTH_EXPIRED = "auth_expired"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    VALIDATION_ERROR = "validation_error"
    RATE_LIMITED = "rate_limited"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_TYPE = "unsupported_type"
    SCAN_FAILED = "scan_failed"
    SCAN_TIMEOUT = "scan_timeout"
    SCANNER_ERROR = "scanner_error"
    QUARANTINE_ERROR = "quarantine_error"
    SSRF_BLOCKED = "ssrf_blocked"
    INTERNAL_ERROR = "internal_error"
    SERVICE_UNAVAILABLE = "service_unavailable"


class CyberShieldError(Exception):
    """Base class for all expected application errors."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    code: str = ErrorCode.INTERNAL_ERROR
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.status_code = status_code or self.status_code
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(CyberShieldError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = ErrorCode.AUTH_INVALID
    message = "Invalid or missing authentication credentials."


class AuthorizationError(CyberShieldError):
    status_code = status.HTTP_403_FORBIDDEN
    code = ErrorCode.FORBIDDEN
    message = "You are not allowed to access this resource."


class NotFoundError(CyberShieldError):
    status_code = status.HTTP_404_NOT_FOUND
    code = ErrorCode.NOT_FOUND
    message = "The requested resource was not found."


class ConflictError(CyberShieldError):
    """Raised when a request is valid but conflicts with current state."""

    status_code = status.HTTP_409_CONFLICT
    code = ErrorCode.CONFLICT
    message = "The resource is in a conflicting state."


class ValidationError(CyberShieldError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = ErrorCode.VALIDATION_ERROR
    message = "The request payload failed validation."


class RateLimitError(CyberShieldError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = ErrorCode.RATE_LIMITED
    message = "Too many requests. Please slow down and try again shortly."

    def __init__(self, message: str | None = None, *, retry_after: int = 60, **kwargs: Any) -> None:
        details = kwargs.pop("details", {}) or {}
        details["retry_after_seconds"] = retry_after
        super().__init__(message, details=details, **kwargs)
        self.retry_after = retry_after


class PayloadTooLargeError(CyberShieldError):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    code = ErrorCode.PAYLOAD_TOO_LARGE
    message = "The uploaded content exceeds the permitted size limit."


class UnsupportedFileTypeError(CyberShieldError):
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    code = ErrorCode.UNSUPPORTED_TYPE
    message = "This file type is not supported for analysis."


class ScanFailedError(CyberShieldError):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    code = ErrorCode.SCAN_FAILED
    message = "The security scan could not be completed."


class ScannerUnavailableError(CyberShieldError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = ErrorCode.SERVICE_UNAVAILABLE
    message = "A required analysis service is currently unavailable."


class SSRFBlockedError(CyberShieldError):
    """Raised when a URL resolves to a forbidden destination."""

    status_code = status.HTTP_400_BAD_REQUEST
    code = ErrorCode.SSRF_BLOCKED
    message = "The URL was blocked because it targets a restricted network destination."


class QuarantineError(CyberShieldError):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    code = ErrorCode.QUARANTINE_ERROR
    message = "The quarantine operation failed."


def error_response(
    *,
    code: str,
    message: str,
    status_code: int,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build the canonical error envelope."""
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "status_code": status_code,
            "correlation_id": request_id_ctx.get(),
        }
    }
    if details:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload, headers=headers)


def register_exception_handlers(app: FastAPI) -> None:
    """Install handlers that translate every exception into the error envelope."""

    @app.exception_handler(CyberShieldError)
    async def _handle_known(request: Request, exc: CyberShieldError) -> JSONResponse:
        headers = {}
        if isinstance(exc, RateLimitError):
            headers["Retry-After"] = str(exc.retry_after)
        log = logger.warning if exc.status_code < 500 else logger.error
        log(
            "request_failed",
            extra={
                "error_code": exc.code,
                "status_code": exc.status_code,
                "path": request.url.path,
                "method": request.method,
                "details": exc.details,
            },
        )
        return error_response(
            code=exc.code,
            message=exc.message,
            status_code=exc.status_code,
            details=exc.details,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # ``exc.errors()`` can embed the submitted value; report the field path only.
        fields = [
            {"field": ".".join(str(p) for p in err.get("loc", [])), "reason": err.get("type", "invalid")}
            for err in exc.errors()
        ]
        logger.info(
            "request_validation_failed",
            extra={"path": request.url.path, "fields": fields, "status_code": 422},
        )
        return error_response(
            code=ErrorCode.VALIDATION_ERROR,
            message="The request payload failed validation.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details={"fields": fields},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        mapping = {
            401: ErrorCode.AUTH_REQUIRED,
            403: ErrorCode.FORBIDDEN,
            404: ErrorCode.NOT_FOUND,
            429: ErrorCode.RATE_LIMITED,
        }
        logger.info(
            "http_error",
            extra={"path": request.url.path, "status_code": exc.status_code},
        )
        return error_response(
            code=mapping.get(exc.status_code, "http_error"),
            message=str(exc.detail),
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = request_id_ctx.get()
        logger.exception(
            "unhandled_exception",
            extra={
                "path": request.url.path,
                "method": request.method,
                "exception_type": type(exc).__name__,
                "correlation_id": correlation_id,
            },
        )
        return error_response(
            code=ErrorCode.INTERNAL_ERROR,
            message=(
                "An unexpected internal error occurred. "
                f"Quote correlation ID {correlation_id} when reporting this issue."
                if correlation_id
                else "An unexpected internal error occurred."
            ),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )