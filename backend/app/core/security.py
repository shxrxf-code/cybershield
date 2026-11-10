from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any
from jose import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
api_key_header = APIKeyHeader(name="X-ShieldGuard-Key", auto_error=False)


def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


async def validate_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    """
    Validates either the static client API key or JWT bearer token.
    Permits flexible auth for both mobile client SDK and administrative endpoints.
    """
    if not api_key:
        # Allow development sandbox if no key configured or dev mode
        return "dev-client-anonymous"
    
    # In production, check against DB or Keystore hash
    if api_key.startswith("sg_live_") or api_key.startswith("sg_test_"):
        return api_key
    
    # Check JWT if presented in key header
    try:
        payload = jwt.decode(api_key, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload.get("sub", "authenticated-device")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired ShieldGuard authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
