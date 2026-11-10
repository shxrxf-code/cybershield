from typing import List, Optional
import os
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_NAME: str = "ShieldGuard AI - Cybersecurity Engine"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-shieldguard-key-change-in-production-32bytes!")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # Database & Cache
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/shieldguard")
    DATABASE_URL_SYNC: str = os.getenv("DATABASE_URL_SYNC", "sqlite:///./shieldguard_dev.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_OTX_KEY: Optional[str] = os.getenv("ALIENVAULT_OTX_KEY", "")
    PHISHTANK_API_KEY: Optional[str] = os.getenv("PHISHTANK_API_KEY", "")

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    # Security Thresholds
    RISK_SCORE_THRESHOLD_MALICIOUS: int = 75
    RISK_SCORE_THRESHOLD_SUSPICIOUS: int = 40

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
