from fastapi import APIRouter, UploadFile, File
from pathlib import Path
import sys, hashlib
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from core.engine.detectors.apk import analyze_apk_permissions
from core.engine.scoring import compute_risk_score

router = APIRouter(prefix="/apk", tags=["APK Scanner"])

@router.post("/scan")
async def scan_apk(file: UploadFile = File(...)):
    content = await file.read()
    fhash = hashlib.sha256(content).hexdigest()
    # Basic analysis without full unzip/manifest parsing in this env; provide structure
    # Heuristic based on filename
    features = {}
    reasons = []
    name = (file.filename or "").lower()
    if "mod" in name or "crack" in name or "hack" in name:
        features["malware_signatures"] = True
        reasons.append("Suspicious filename indicator")
    risk = compute_risk_score(features)
    action = "quarantine" if risk["score"] >= 70 else "warn" if risk["score"] >= 40 else "allow"
    return {
        "filename": file.filename,
        "apk_hash": fhash,
        "size_bytes": len(content),
        "permissions": [],
        "dangerous_permissions": [],
        "is_malicious": risk["score"] >= 40,
        "threat_score": risk["score"],
        "risk": risk,
        "action": action,
        "analysis": {
            "static_analysis": "partial",
            "manifest_analysis": "pending",
            "certificate_analysis": "pending",
            "note": "Full Android APK parsing requires androguard/aapt; structure provided"
        },
        "reasons": reasons
    }

@router.get("/status")
def status():
    return {"module": "apk", "enabled": True, "platform": "android", "status": "operational", "full_analysis": "scaffold"}
