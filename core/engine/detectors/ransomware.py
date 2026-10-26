import os
import math
import time
from typing import Dict, Any, List

CANARY_DIR = "./quarantine/.canaries"
CANARY_FILES = [
    "important_financial_records.docx.canary",
    "payroll_summary_2026.xlsx.canary",
    "private_keys_backup.pem.canary",
]
CANARY_SIGNATURE = b"CYBERSHIELD_CANARY_TRIPWIRE_TOKEN_V1_DO_NOT_MODIFY"

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte data (0.0 to 8.0). High entropy (>7.5) indicates encryption or compression."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def deploy_canaries() -> Dict[str, Any]:
    """Deploys honeypot canary files in monitored directory to detect ransomware encryption."""
    os.makedirs(CANARY_DIR, exist_ok=True)
    deployed = []
    for canary_name in CANARY_FILES:
        path = os.path.join(CANARY_DIR, canary_name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(CANARY_SIGNATURE + b"\n" + (b"CANARY_DATA_PAYLOAD_" * 50))
        deployed.append({
            "filename": canary_name,
            "path": path,
            "status": "intact",
            "last_verified": time.time(),
        })
    return {"deployed_count": len(deployed), "canaries": deployed}

def verify_canaries() -> Dict[str, Any]:
    """Verifies that honeypot canary files have not been modified, deleted, or encrypted."""
    os.makedirs(CANARY_DIR, exist_ok=True)
    intact = 0
    tripped = []
    
    for canary_name in CANARY_FILES:
        path = os.path.join(CANARY_DIR, canary_name)
        if not os.path.exists(path):
            tripped.append({"filename": canary_name, "reason": "Canary file deleted or moved by unauthorized process"})
        else:
            try:
                with open(path, "rb") as f:
                    content = f.read()
                if not content.startswith(CANARY_SIGNATURE):
                    entropy = calculate_shannon_entropy(content)
                    tripped.append({
                        "filename": canary_name,
                        "reason": f"Canary file content modified or encrypted (Entropy: {entropy})",
                        "entropy": entropy
                    })
                else:
                    intact += 1
            except Exception as e:
                tripped.append({"filename": canary_name, "reason": f"Read error: {str(e)}"})
                
    is_compromised = len(tripped) > 0
    return {
        "status": "compromised" if is_compromised else "secure",
        "intact_canaries": intact,
        "total_canaries": len(CANARY_FILES),
        "tripped_canaries": tripped,
        "threat_detected": is_compromised,
        "recommendation": "Emergency ransomware isolation advised" if is_compromised else "Normal operations",
    }

def simulate_canary_test() -> Dict[str, Any]:
    """Safely runs a self-test of the ransomware tripwire mechanism."""
    deploy_canaries()
    res = verify_canaries()
    return {
        "test_run": True,
        "tripwire_active": True,
        "canary_directory": CANARY_DIR,
        "result": res,
    }
