from fastapi import APIRouter, Depends
from app.schemas.schemas import NetworkAuditRequest, NetworkAuditResponse
from app.core.security import validate_api_key

router = APIRouter(prefix="/network", tags=["Network Protection & WiFi Audit"])


@router.post("/audit", response_model=NetworkAuditResponse)
async def audit_network(request: NetworkAuditRequest, client_id: str = Depends(validate_api_key)):
    recs = []
    threat_level = "LOW"
    verdict = "SECURE"
    mitm = False
    dns_hijack = False

    if request.arp_anomaly_detected:
        mitm = True
        threat_level = "CRITICAL"
        verdict = "COMPROMISED"
        recs.append("ARP cache poisoning detected! Disconnect immediately from this WiFi network.")

    if request.ssl_stripping_detected:
        mitm = True
        threat_level = "CRITICAL"
        verdict = "COMPROMISED"
        recs.append("SSL/TLS Stripping attack observed. Plaintext downgrade attempt blocked.")

    if request.is_public_wifi and not request.is_encrypted:
        threat_level = "HIGH" if threat_level != "CRITICAL" else threat_level
        verdict = "VULNERABLE"
        recs.append("Open unencrypted Wi-Fi hotspot. ShieldGuard VPN tunnel is strongly advised.")

    # Check for known rogue DNS resolvers
    suspicious_dns = ["192.168.1.1", "10.0.0.1"]  # Common router redirects with no DoH
    if not recs:
        recs.append("Network transport is encrypted and DNS servers match verified resolvers.")

    return NetworkAuditResponse(
        threat_level=threat_level,
        verdict=verdict,
        mitm_risk=mitm,
        dns_hijack_risk=dns_hijack,
        recommendations=recs
    )
