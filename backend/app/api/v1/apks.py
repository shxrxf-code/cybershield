from fastapi import APIRouter, Depends
from app.schemas.schemas import ApkStaticScanRequest, ApkMalwareReport
from app.services.scanner.apk_static_engine import apk_engine
from app.core.security import validate_api_key

router = APIRouter(prefix="/apks", tags=["APK Malware Scanner"])


@router.post("/scan", response_model=ApkMalwareReport)
async def scan_apk_metadata(request: ApkStaticScanRequest, client_id: str = Depends(validate_api_key)):
    report = apk_engine.analyze_package_metadata(
        package_name=request.package_name,
        permissions=request.permissions,
        dangerous_apis=request.dangerous_apis,
        embedded_urls=request.embedded_urls,
        native_libraries=request.native_libraries,
        is_debuggable=request.is_debuggable,
        uses_accessibility=request.uses_accessibility,
        uses_overlay=request.uses_overlay
    )
    return ApkMalwareReport(**report)
