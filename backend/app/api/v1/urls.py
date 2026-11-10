from fastapi import APIRouter, Depends
from app.schemas.schemas import UrlScanRequest, UrlAnalysisResult
from app.services.ml_engine.url_classifier import url_classifier
from app.services.threat_intel.intel_manager import threat_intel
from app.core.security import validate_api_key

router = APIRouter(prefix="/urls", tags=["Real-time Phishing & URL Scanner"])


@router.post("/scan", response_model=UrlAnalysisResult)
async def scan_url(request: UrlScanRequest, client_id: str = Depends(validate_api_key)):
    intel_data = None
    if request.deep_analysis:
        from urllib.parse import urlparse
        domain = urlparse(request.url).netloc or request.url
        intel_data = await threat_intel.check_url(request.url, domain)

    result = url_classifier.analyze(request.url, intel_data)
    
    return UrlAnalysisResult(
        url=result["url"],
        domain=result["domain"],
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        threat_level=result["threat_level"],
        reasons=result["reasons"],
        features=result["features"],
        is_typosquatting=result["is_typosquatting"],
        is_homograph=result["is_homograph"],
        ssl_valid=result["ssl_valid"],
        threat_intel_matches=intel_data.get("threat_sources", []) if intel_data else []
    )
