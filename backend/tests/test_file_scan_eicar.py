import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.engine.scoring import compute_risk_score

def test_eicar_detection_logic():
    content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    features = {}
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
        features["malware_signatures"] = True
    risk = compute_risk_score(features)
    assert risk['score'] >= 30
