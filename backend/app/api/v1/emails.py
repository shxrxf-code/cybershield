from fastapi import APIRouter, Depends
from app.schemas.schemas import EmailScanRequest, EmailScanResponse
from app.services.ml_engine.email_security_analyzer import email_analyzer
from app.core.security import validate_api_key

router = APIRouter(prefix="/emails", tags=["Email Security Engine"])


@router.post("/scan", response_model=EmailScanResponse)
async def scan_email(request: EmailScanRequest, client_id: str = Depends(validate_api_key)):
    result = email_analyzer.analyze(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        spf=request.spf_result,
        dkim=request.dkim_result,
        dmarc=request.dmarc_result,
        attachments=request.attachments
    )
    return EmailScanResponse(**result)
