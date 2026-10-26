from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from core.engine.detectors.email import analyze_email
from core.engine.scoring import compute_risk_score
from core.schemas.threat import RiskScore

router = APIRouter(prefix="/email", tags=["Email Security"])

class EmailScanRequest(BaseModel):
    sender: str
    subject: str = ""
    body: str = ""
    urls: List[str] = []

@router.post("/scan")
def scan_email(req: EmailScanRequest):
    det = analyze_email(req.sender, req.subject, req.body, req.urls)
    risk = compute_risk_score(det.get("features", {}))
    is_phish = risk["score"] >= 50
    action = "block" if risk["score"] >= 70 else "warn" if risk["score"] >= 50 else "allow"
    return {
        "is_phishing": is_phish,
        "risk": risk,
        "reasons": det.get("reasons", []),
        "action": action,
        "spoof_detected": "spoof" in str(det.get("reasons", [])).lower()
    }

@router.get("/status")
def status():
    return {"module": "email", "enabled": True, "oauth_configured": False, "status": "operational", "note": "OAuth requires user consent configuration"}
