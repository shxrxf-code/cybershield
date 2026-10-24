from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
import hashlib
import os
import subprocess
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from core.engine.scoring import compute_risk_score
from core.schemas.threat import FileScanResult, RiskScore

router = APIRouter(prefix="/scan", tags=["File Scanning"])

QUARANTINE = Path(os.getenv("QUARANTINE_PATH", "./quarantine"))
QUARANTINE.mkdir(parents=True, exist_ok=True)

class HashScanRequest(BaseModel):
    file_hash: str
    filename: str = "unknown"

@router.post("/hash", response_model=FileScanResult)
def scan_hash(req: HashScanRequest):
    # Check ClamAV signatures via clamscan if available? For hash-only, do heuristic
    features = {}
    reasons = []
    # Known test hash EICAR not in plain text; treat generic
    risk = compute_risk_score(features)
    return FileScanResult(
        file_hash=req.file_hash,
        filename=req.filename,
        is_malicious=False,
        detections=[],
        risk=RiskScore(**risk),
        action="allow",
        quarantined=False,
    )

@router.post("/file", response_model=FileScanResult)
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    fhash = hashlib.sha256(content).hexdigest()
    detections = []
    features = {}
    reasons = []
    # Try clamscan on temp file if available
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename or "tmp").suffix) as tf:
            tf.write(content)
            tmp = tf.name
        try:
            res = subprocess.run(["clamscan", "--no-summary", tmp], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            out = res.stdout.decode(errors="ignore")
            if "FOUND" in out:
                detections.append({"engine": "clamav", "output": out.strip()})
                features["malware_signatures"] = True
                reasons.append("ClamAV detection")
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
    except FileNotFoundError:
        reasons.append("ClamAV not installed or not in PATH")
    except subprocess.TimeoutExpired:
        reasons.append("ClamAV scan timeout")
    except Exception as e:
        reasons.append(f"ClamAV error: {e}")
    # EICAR test string detection
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
        detections.append({"engine": "eicar", "output": "EICAR Test File"})
        features["malware_signatures"] = True
        reasons.append("EICAR test signature detected")
    risk = compute_risk_score(features)
    is_mal = len(detections) > 0 or risk["score"] >= 40
    action = "quarantine" if is_mal and risk["score"] >= 40 else "warn" if is_mal else "allow"
    quarantined = False
    if action == "quarantine":
        try:
            qpath = QUARANTINE / f"{fhash}_{Path(file.filename or 'file').name}"
            with open(qpath, "wb") as f:
                f.write(content)
            quarantined = True
        except Exception:
            quarantined = False
    return FileScanResult(
        file_hash=fhash,
        filename=file.filename or "unknown",
        is_malicious=is_mal,
        detections=detections,
        risk=RiskScore(**risk),
        action=action,
        quarantined=quarantined,
    )

@router.get("/status")
def status():
    return {"module": "scan", "enabled": True, "clamav_available": os.system("which clamscan >/dev/null 2>&1") == 0, "status": "operational"}
