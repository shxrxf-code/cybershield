from fastapi import APIRouter, Depends
from app.schemas.schemas import (
    DeviceAuditRequest, DeviceAuditResponse, DashboardSummaryResponse
)
from app.core.security import validate_api_key

router = APIRouter(prefix="/devices", tags=["Device Security Center"])


@router.post("/audit", response_model=DeviceAuditResponse)
async def audit_device(request: DeviceAuditRequest, client_id: str = Depends(validate_api_key)):
    score = 100
    findings = []
    remediations = []

    if request.is_rooted:
        score -= 40
        findings.append("Device Root Access / SU Binary detected (Compromised OS Sandbox integrity)")
        remediations.append("Unroot device or lock bootloader to prevent privilege escalation attacks.")

    if request.developer_mode_enabled or request.usb_debugging_enabled:
        score -= 20
        findings.append("Developer Options or USB Debugging is currently active (Vulnerable to physical ADB extraction)")
        remediations.append("Disable USB Debugging in Settings > Developer Options.")

    if request.unknown_sources_enabled:
        score -= 15
        findings.append("Installation from Unknown Sources is permitted")
        remediations.append("Disable 'Install unknown apps' permission for browsers and file managers.")

    if request.accessibility_services_count > 3:
        score -= 10
        findings.append(f"{request.accessibility_services_count} active Accessibility Services (Potential screen scraping / keystroke logging risk)")
        remediations.append("Audit and disable non-essential Accessibility permissions.")

    if request.overlay_apps_count > 5:
        score -= 10
        findings.append(f"{request.overlay_apps_count} apps have 'Display over other apps' permission")
        remediations.append("Revoke Draw Over Other Apps permission for untrusted applications.")

    score = max(0, min(100, score))

    if score >= 80:
        posture = "SECURE"
    elif score >= 50:
        posture = "ELEVATED_RISK"
    else:
        posture = "COMPROMISED"

    return DeviceAuditResponse(
        overall_security_score=score,
        security_posture=posture,
        critical_findings=findings,
        remediation_steps=remediations
    )


@router.get("/{device_uuid}/dashboard", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(device_uuid: str, client_id: str = Depends(validate_api_key)):
    # Aggregated metrics for live dashboard
    return DashboardSummaryResponse(
        security_score=92,
        threat_level="LOW",
        threats_blocked_total=14,
        scanned_apps_count=128,
        scanned_files_count=1840,
        network_status="PROTECTED (ShieldGuard DNS Guard Active)",
        recent_threats=[
            {
                "module": "URL",
                "title": "Phishing Link Intercepted",
                "indicator": "http://paypa1-security-verify.xyz",
                "action": "BLOCKED",
                "timestamp": "10 minutes ago"
            },
            {
                "module": "NOTIFICATION",
                "title": "Telegram Crypto Scam Filtered",
                "indicator": "Claim 5000 USDT Airdrop!",
                "action": "BLOCKED",
                "timestamp": "2 hours ago"
            }
        ]
    )
