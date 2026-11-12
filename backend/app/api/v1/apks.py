from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool
from app.schemas.schemas import ApkStaticScanRequest, ApkMalwareReport
from app.services.scanner.apk_static_engine import apk_engine
from app.core.security import validate_api_key

router = APIRouter(prefix="/apks", tags=["APK Malware Scanner"])

MAX_APK_UPLOAD_BYTES = 150 * 1024 * 1024  # 150 MB guard


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


@router.post("/scan-file", response_model=ApkMalwareReport)
async def scan_apk_file(
    file: UploadFile = File(..., description="Android APK binary for deep Androguard static analysis"),
    is_trusted_store: bool = Form(False),
    client_id: str = Depends(validate_api_key)
):
    apk_bytes = await file.read()
    if not apk_bytes:
        raise HTTPException(status_code=400, detail="Uploaded APK file is empty.")
    if len(apk_bytes) > MAX_APK_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="APK exceeds 150 MB limit for synchronous scan.")

    try:
        report = await run_in_threadpool(
            apk_engine.analyze_apk_bytes,
            apk_bytes,
            file.filename or "upload.apk",
            is_trusted_store,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid APK archive: {exc}")
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return ApkMalwareReport(**report)
