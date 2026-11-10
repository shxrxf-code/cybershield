from fastapi import APIRouter, Depends, Response
from app.schemas.schemas import ReportExportRequest
from app.services.report_generator.report_engine import report_engine
from app.core.security import validate_api_key

router = APIRouter(prefix="/reports", tags=["Security Reports"])


@router.post("/generate")
async def generate_report(request: ReportExportRequest, client_id: str = Depends(validate_api_key)):
    # Mock aggregation for demonstration
    mock_threats = [
        {"created_at": "2026-11-10T12:00:00Z", "module_type": "URL", "verdict": "MALICIOUS", "risk_score": 95, "threat_level": "CRITICAL", "title": "Typosquatted Banking Phish", "action_taken": "BLOCKED"},
        {"created_at": "2026-11-10T14:30:00Z", "module_type": "SMS", "verdict": "SCAM", "risk_score": 85, "threat_level": "HIGH", "title": "Smishing Toll Fraud", "action_taken": "BLOCKED"},
        {"created_at": "2026-11-10T18:15:00Z", "module_type": "DOCUMENT", "verdict": "SUSPICIOUS", "risk_score": 60, "threat_level": "MEDIUM", "title": "Macro in Invoice.docm", "action_taken": "QUARANTINED"}
    ]

    if request.format.upper() == "CSV":
        csv_data = report_engine.generate_csv_log(mock_threats)
        return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=shieldguard_report_{request.period.lower()}.csv"})

    # Return structured JSON summary by default
    return report_engine.generate_security_brief(
        device_uuid=request.device_uuid,
        security_score=94,
        threats_blocked=len(mock_threats),
        scans_count=42,
        period=request.period,
        threat_breakdown={"Phishing": 1, "Smishing": 1, "Document": 1, "Malware": 0}
    )
