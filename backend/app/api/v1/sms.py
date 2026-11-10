from fastapi import APIRouter, Depends
from app.schemas.schemas import SmsScanRequest, SmsScanResponse, NotificationScanRequest, NotificationScanResponse
from app.services.ml_engine.sms_phishing_detector import sms_detector
from app.services.ml_engine.url_classifier import url_classifier
from app.core.security import validate_api_key

router = APIRouter(prefix="/messaging", tags=["SMS & Real-time Notification Protection"])


@router.post("/sms/scan", response_model=SmsScanResponse)
async def scan_sms(request: SmsScanRequest, client_id: str = Depends(validate_api_key)):
    result = sms_detector.analyze(request.sender, request.body)
    return SmsScanResponse(**result)


@router.post("/notifications/scan", response_model=NotificationScanResponse)
async def scan_notification(request: NotificationScanRequest, client_id: str = Depends(validate_api_key)):
    # Combine title and text to analyze scam/threat content
    combined_content = f"{request.title} {request.text}"
    analysis = sms_detector.analyze(request.app_label, combined_content)
    
    # Check any extracted URLs
    is_url_malicious = False
    for url in analysis["extracted_urls"]:
        url_eval = url_classifier.analyze(url)
        if url_eval["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
            is_url_malicious = True
            break

    is_threat = (analysis["risk_score"] >= 35) or is_url_malicious

    threat_type = None
    if "giveaway" in combined_content.lower() or "won" in combined_content.lower():
        threat_type = "FAKE_GIVEAWAY"
    elif "bitcoin" in combined_content.lower() or "crypto" in combined_content.lower() or "airdrop" in combined_content.lower():
        threat_type = "CRYPTO_SCAM"
    elif is_url_malicious:
        threat_type = "PHISHING_LINK"
    elif analysis["classification"] == "BANKING_FRAUD":
        threat_type = "BANKING_FRAUD"

    warning = None
    if is_threat:
        warning = f"ShieldGuard Alert: {threat_type or 'SCAM_DETECTED'} in notification from {request.app_label}."

    return NotificationScanResponse(
        is_threat=is_threat,
        verdict=analysis["classification"],
        threat_type=threat_type,
        risk_score=analysis["risk_score"],
        extracted_links=analysis["extracted_urls"],
        warning_message=warning
    )
