from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from core.engine.detectors.url import analyze_url
from core.engine.scoring import compute_risk_score
from core.schemas.threat import URLAnalysisResult, RiskScore

router = APIRouter(prefix="/url", tags=["URL Protection"])

class URLScanRequest(BaseModel):
    url: HttpUrl

@router.post("/scan", response_model=URLAnalysisResult)
def scan_url(req: URLScanRequest):
    url_str = str(req.url)
    det = analyze_url(url_str)
    risk = compute_risk_score(det.get("features", {}))
    is_mal = risk["score"] >= 40
    is_phish = risk["score"] >= 50 or det.get("features", {}).get("phishing_indicators")
    action = "block" if risk["score"] >= 70 else "warn" if risk["score"] >= 40 else "allow"
    return URLAnalysisResult(
        url=url_str,
        is_malicious=is_mal,
        is_phishing=bool(is_phish),
        risk=RiskScore(**risk),
        categories=det.get("reasons", []),
        reasons=det.get("reasons", []),
        blocked=(action == "block"),
        action=action,
    )

@router.get("/status")
def status():
    return {"module": "url", "enabled": True, "status": "operational", "engine": "core.detectors.url+scoring"}
