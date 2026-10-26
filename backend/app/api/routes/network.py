from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from core.engine.detectors.network import analyze_connection
from core.engine.scoring import compute_risk_score

router = APIRouter(prefix="/network", tags=["Network Shield"])

class ConnRequest(BaseModel):
    src_ip: str = "192.168.1.100"
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"

@router.post("/analyze")
def analyze(req: ConnRequest):
    det = analyze_connection(req.src_ip, req.dst_ip, req.dst_port, req.protocol)
    risk = compute_risk_score(det.get("features", {}))
    action = "block" if risk["score"] >= 60 else "warn" if risk["score"] >= 40 else "allow"
    return {
        "suspicious": det.get("suspicious", False),
        "risk": risk,
        "reasons": det.get("reasons", []),
        "action": action,
        "block": action == "block"
    }

@router.get("/status")
def status():
    return {"module": "network", "enabled": True, "suricata_available": True, "dns_protection": True, "status": "operational"}
