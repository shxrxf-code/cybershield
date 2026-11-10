from fastapi import APIRouter, Depends
from app.schemas.schemas import DocumentScanRequest, DocumentScanResponse
from app.services.scanner.document_security_engine import document_engine
from app.core.security import validate_api_key

router = APIRouter(prefix="/documents", tags=["Document Security Scanner"])


@router.post("/scan", response_model=DocumentScanResponse)
async def scan_document_metadata(request: DocumentScanRequest, client_id: str = Depends(validate_api_key)):
    result = document_engine.analyze_document_metadata(
        file_name=request.file_name,
        file_extension=request.file_extension,
        file_size_bytes=request.file_size_bytes,
        has_macros=request.has_macros,
        embedded_scripts=request.embedded_scripts,
        embedded_urls=request.embedded_urls,
        suspicious_tags=request.suspicious_tags
    )
    return DocumentScanResponse(**result)
