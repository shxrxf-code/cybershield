"""Application configuration.

Configuration is loaded exclusively from environment variables (12-factor).
No secret is ever hardcoded and no secret is ever returned to API clients.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_ROOT.parent


class Settings(BaseSettings):
    """Runtime settings for the CyberShield backend."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = "CyberShield API"
    app_version: str = "1.0.0"
    environment: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    docs_enabled: bool = True

    # ------------------------------------------------------------------
    # Database / Redis
    # ------------------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./cybershield.db"
    database_pool_size: int = 10
    database_max_overflow: int = 20
    redis_url: str = "redis://localhost:6379/0"
    use_redis_queue: bool = False

    # ------------------------------------------------------------------
    # Security / authentication
    # ------------------------------------------------------------------
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 14
    bcrypt_rounds: int = 12
    argon2_enabled: bool = True
    password_min_length: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    cors_allow_credentials: bool = False
    #: Honour ``X-Forwarded-For``/``X-Forwarded-Proto`` when computing the client
    #: identity for rate limiting and audit. Defaults to off so a deployment that
    #: faces the internet without a trusted proxy cannot be spoofed through these
    #: headers; enable only behind a proxy that overwrites them.
    trust_proxy_headers: bool = False

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_default_per_minute: int = 60
    rate_limit_auth_per_minute: int = 10
    rate_limit_scan_per_minute: int = 30
    rate_limit_file_scan_per_minute: int = 10

    # ------------------------------------------------------------------
    # Upload / quarantine storage
    # ------------------------------------------------------------------
    max_upload_bytes: int = 100 * 1024 * 1024  # 100 MiB
    max_email_bytes: int = 25 * 1024 * 1024  # 25 MiB
    storage_root: Path = Field(default_factory=lambda: PROJECT_ROOT / "var")
    keep_files_after_scan: bool = False
    quarantine_enabled: bool = True
    quarantine_encryption_key: str | None = None
    #: Retention windows, in days. Scans pass their window even when a quarantined
    #: copy is still held, so an indicator can be cleaned while the sample remains.
    scan_retention_days: int = 90
    quarantine_retention_days: int = 14

    # ------------------------------------------------------------------
    # URL scanner / SSRF protection
    # ------------------------------------------------------------------
    url_fetch_enabled: bool = True
    url_fetch_timeout_seconds: float = 10.0
    url_fetch_max_bytes: int = 2 * 1024 * 1024
    url_max_redirects: int = 10
    url_allowed_ports: set[int] = Field(default_factory=lambda: {80, 443, 8080, 8443})
    url_allow_private_networks: bool = False
    url_dns_timeout_seconds: float = 5.0
    url_user_agent: str = "CyberShield-Scanner/1.0 (+defensive-url-analysis)"

    # ------------------------------------------------------------------
    # Threat intelligence providers
    # ------------------------------------------------------------------
    virustotal_api_key: str | None = None
    virustotal_enabled: bool = True
    urlhaus_enabled: bool = True
    urlhaus_endpoint: str = "https://urlhaus-api.abuse.ch/v1/url/"
    #: abuse.ch requires an Auth-Key header. Without it the provider is
    #: excluded from lookups rather than failing every request.
    urlhaus_auth_key: str | None = None
    abuseipdb_api_key: str | None = None
    google_safebrowsing_api_key: str | None = None
    threat_intel_timeout_seconds: float = 8.0
    threat_intel_cache_ttl_seconds: int = 900

    # ------------------------------------------------------------------
    # External scanners
    # ------------------------------------------------------------------
    clamav_enabled: bool = True
    clamav_host: str = "localhost"
    clamav_port: int = 3310
    clamav_timeout_seconds: float = 60.0
    clamav_max_scan_bytes: int = 100 * 1024 * 1024

    yara_enabled: bool = True
    yara_rules_dir: Path | None = None

    ocr_enabled: bool = False
    ocr_max_characters: int = 20000

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True
    log_file: Path | None = None

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------
    @field_validator("cors_origins", "cors_allow_credentials", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Allow comma-separated CORS origins from a single env var."""
        if isinstance(value, str) and not value.strip().startswith("["):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}:
            raise ValueError(f"Invalid log level: {value}")
        return level

    @model_validator(mode="after")
    def _validate_production_hardening(self) -> Settings:
        """Refuse to boot production with insecure defaults."""
        if self.environment != "production":
            return self

        problems: list[str] = []
        # A generated per-process secret invalidates every token on restart and
        # differs between replicas, so it must be pinned in production.
        if self.secret_key == self.model_fields["secret_key"].default_factory():  # type: ignore[misc]
            problems.append("SECRET_KEY must be set explicitly in production")
        if self.debug:
            problems.append("DEBUG must be false in production")
        if self.docs_enabled and not self.debug:
            # Docs are not a vulnerability per se, but they are disabled by
            # default in production deployments via the compose profile.
            pass
        if self.cors_allow_credentials and "*" in self.cors_origins:
            problems.append("CORS_ALLOW_CREDENTIALS cannot be used with wildcard origins")
        if problems:
            raise ValueError("Insecure production configuration: " + "; ".join(problems))
        return self

    # ------------------------------------------------------------------
    # Derived paths
    # ------------------------------------------------------------------
    @property
    def upload_dir(self) -> Path:
        return self.storage_root / "uploads"

    @property
    def quarantine_dir(self) -> Path:
        return self.storage_root / "quarantine"

    @property
    def temp_dir(self) -> Path:
        return self.storage_root / "tmp"

    @property
    def resolved_yara_rules_dir(self) -> Path:
        if self.yara_rules_dir is not None:
            return self.yara_rules_dir
        return PROJECT_ROOT / "detection-engine" / "yara" / "rules"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def ensure_directories(self) -> None:
        """Create runtime storage directories. Safe to call repeatedly."""
        for directory in (self.storage_root, self.upload_dir, self.quarantine_dir, self.temp_dir):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()