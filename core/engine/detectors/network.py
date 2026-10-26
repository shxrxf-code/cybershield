from __future__ import annotations
from typing import Dict, Any, List

SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 1234, 1337, 6667}

def analyze_connection(src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> Dict[str, Any]:
    features = {}
    reasons = []
    if dst_port in SUSPICIOUS_PORTS:
        features["ip_reputation"] = True
        features["behavior_anomaly"] = True
        reasons.append(f"Connection to suspicious port {dst_port} (C2/RAT indicator)")
    if dst_ip and not dst_ip.startswith(("192.168.", "10.", "172.", "127.")):
        if dst_port in {23, 445, 3389, 135, 139}:
            features["ip_reputation"] = True
            reasons.append("Connection to risky service port from external")
    # Check for Tor exit nodes patterns (simplified)
    if dst_ip.startswith(("185.220.", "199.87.", "51.15.")):
        features["ip_reputation"] = True
        reasons.append("Connection to known anonymization network")
    return {"features": features, "reasons": reasons, "suspicious": len(features) > 0}
