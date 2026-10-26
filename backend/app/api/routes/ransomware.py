from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from core.engine.detectors.ransomware import deploy_canaries, verify_canaries, simulate_canary_test, calculate_shannon_entropy

router = APIRouter(prefix="/ransomware", tags=["Ransomware Protection"])

class EntropyCheckRequest(BaseModel):
    sample_text: Optional[str] = ""

@router.get("/status")
def get_ransomware_status():
    canary_result = verify_canaries()
    return {
        "shield_active": True,
        "tripwire_enabled": True,
        "canary_status": canary_result["status"],
        "intact_canaries": canary_result["intact_canaries"],
        "total_canaries": canary_result["total_canaries"],
        "tripped_canaries": canary_result["tripped_canaries"],
        "mass_modification_monitor": "active",
        "shannon_entropy_inspector": "active",
        "protected_directories": ["./quarantine/.canaries", "/home/user/Documents", "/home/user/Downloads"],
    }

@router.post("/deploy-canaries")
def deploy_tripwire():
    return deploy_canaries()

@router.post("/verify-canaries")
def verify_tripwire():
    return verify_canaries()

@router.post("/test-tripwire")
def test_tripwire():
    return simulate_canary_test()

@router.post("/check-entropy")
def check_entropy(req: EntropyCheckRequest):
    data = req.sample_text.encode('utf-8') if req.sample_text else b""
    entropy = calculate_shannon_entropy(data)
    is_encrypted = entropy > 7.2
    return {
        "entropy": entropy,
        "max_entropy": 8.0,
        "is_likely_encrypted": is_encrypted,
        "assessment": "High entropy indicates strongly encrypted or compressed data" if is_encrypted else "Normal entropy level (plaintext/structured format)"
    }
