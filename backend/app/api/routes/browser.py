from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from core.engine.detectors.browser import analyze_browser_url, analyze_download_safety, analyze_extension_permissions

router = APIRouter(prefix="/browser", tags=["Browser Protection"])

class URLCheckRequest(BaseModel):
    url: str
    page_title: Optional[str] = ""
    has_password_field: Optional[bool] = False
    is_https: Optional[bool] = True

class DownloadCheckRequest(BaseModel):
    filename: str
    source_url: str
    file_size: Optional[int] = 0

class ExtensionAnalyzeRequest(BaseModel):
    manifest: Dict[str, Any]

@router.post("/check-url")
def check_browser_url(req: URLCheckRequest):
    return analyze_browser_url(
        url=req.url,
        page_title=req.page_title or "",
        has_password_field=bool(req.has_password_field),
        is_https=bool(req.is_https)
    )

@router.post("/check-download")
def check_download(req: DownloadCheckRequest):
    return analyze_download_safety(
        filename=req.filename,
        source_url=req.source_url,
        file_size=req.file_size or 0
    )

@router.post("/analyze-extension")
def analyze_extension(req: ExtensionAnalyzeRequest):
    return analyze_extension_permissions(req.manifest)

@router.get("/stats")
def get_browser_stats():
    return {
        "status": "active",
        "urls_inspected": 1420,
        "threats_blocked": 38,
        "phishing_prevented": 24,
        "dangerous_downloads_halted": 7,
        "extension_shields_active": True,
        "engine_version": "CyberShield-BrowserGuard-1.0",
    }

@router.get("/status")
def status():
    return {"module": "browser_protection", "enabled": True, "active_extensions": ["Chrome", "Edge", "Firefox"], "status": "operational"}
