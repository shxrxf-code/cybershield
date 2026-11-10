from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.core.database import init_db
from app.core.redis import redis_client
from app.api.v1.router import api_router
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ShieldGuard")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Add OWASP Security Headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Response-Time"] = f"{process_time:.4f}s"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing ShieldGuard AI Security Engine...")
    try:
        await init_db()
    except Exception as e:
        logger.warning(f"Database init warning: {e}")
    await redis_client.connect()
    yield
    logger.info("Shutting down ShieldGuard AI Engine...")
    await redis_client.close()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Multi-Vector Cybersecurity Defense API for Android & Endpoint Protection.",
    version="2.0.0",
    lifespan=lifespan
)

# Apply middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "ShieldGuard AI Core",
        "version": "2.0.0",
        "engines": {
            "url_phishing": "ONLINE",
            "apk_malware": "ONLINE",
            "sms_smishing": "ONLINE",
            "document_exploit": "ONLINE",
            "threat_intelligence": "CONNECTED"
        }
    }


@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to ShieldGuard AI Security API Gateway",
        "documentation": "/docs",
        "openapi_spec": "/openapi.json"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
