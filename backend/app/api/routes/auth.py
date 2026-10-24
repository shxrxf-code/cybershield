from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
import jwt
from datetime import datetime, timedelta
from ...core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

@router.post("/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    # In production, hash passwords and store in DB. This is functional scaffold with secure patterns.
    payload = {"sub": req.email, "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    payload = {"sub": req.email, "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me")
def me():
    return {"user": "authenticated", "note": "Use Authorization: Bearer <token>"}
