from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import router
from .core.config import settings

app = FastAPI(
    title="CyberShield API",
    description="Universal AI-Powered Cross-Platform Cybersecurity & Device Protection Platform API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")

@app.get("/health")
def health():
    return {"status": "ok", "service": "cybershield-api", "version": "1.0.0"}

@app.get("/")
def root():
    return {"name": "CyberShield", "docs": "/docs", "health": "/health"}
