from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    APP_NAME: str = "SENTINEL X"
    SECRET_KEY: str = os.getenv("SENTINEL_SECRET_KEY", "change-me-in-production-use-env")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"]
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    SAFE_BROWSING_API_KEY: str = os.getenv("SAFE_BROWSING_API_KEY", "")
    ENABLE_CLAMAV: bool = True
    CLAMAV_SOCKET: str = "/var/run/clamav/clamd.ctl"
    QUARANTINE_PATH: str = os.getenv("QUARANTINE_PATH", "./quarantine")
    AUDIT_LOG_ENABLED: bool = True
    RATE_LIMIT_ENABLED: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
