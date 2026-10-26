from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import os
import uuid
from pathlib import Path
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ...db.session import get_db
from ...models.scan import ScannedFile
from ...services.malware_scanner import perform_malware_analysis, check_engine_health

router = APIRouter(prefix="/scan", tags=["File Scanning"])

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB limit

class HashScanRequest(BaseModel):
    file_hash: str
    filename: str = "unknown"

@router.post("/file")
async def scan_file_upload(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty")

    # Read and validate file content
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes)")
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_SIZE // (1024*1024)}MB")

    # Perform multi-engine malware analysis
    try:
        report = perform_malware_analysis(content, file.filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis engine execution failed: {str(e)}")

    # Persist scan report to database
    try:
        record = ScannedFile(
            filename=report["filename"],
            file_path=None,
            file_hash=report["file_hash"],
            md5=report["md5"],
            size_bytes=report["file_size"],
            entropy=report["entropy"],
            scan_engine="+".join(report["scan_engines"]) if report["scan_engines"] else "heuristic",
            is_malicious=report["is_malicious"],
            status=report["status"],
            threat_name=report["threat_name"],
            threat_severity=report["threat_severity"],
            duration_ms=report["duration_ms"],
            recommended_action=report["recommended_action"],
            detections=report["detections"],
            risk_score=report["risk"]["score"],
            action=report["action"]
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        report["id"] = str(record.id)
    except Exception as e:
        db.rollback()
        # Non-fatal if DB write fails, but include fallback ID
        report["id"] = str(uuid.uuid4())

    return report

@router.get("/history")
def get_scan_history(
    search: Optional[str] = Query(None, description="Search by filename or hash"),
    status: Optional[str] = Query("ALL", description="Filter by status (ALL, CLEAN, INFECTED, SUSPICIOUS)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(ScannedFile)
    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter((ScannedFile.filename.ilike(search_filter)) | (ScannedFile.file_hash.ilike(search_filter)))
    
    if status and status.upper() != "ALL":
        query = query.filter(ScannedFile.status == status.upper())

    total = query.count()
    records = query.order_by(desc(ScannedFile.scanned_at)).offset(offset).limit(limit).all()

    items = []
    for r in records:
        items.append({
            "id": str(r.id),
            "filename": r.filename,
            "file_hash": r.file_hash,
            "md5": r.md5,
            "size_bytes": r.size_bytes,
            "entropy": r.entropy,
            "scan_engine": r.scan_engine,
            "is_malicious": r.is_malicious,
            "status": r.status or ("INFECTED" if r.is_malicious else "CLEAN"),
            "threat_name": r.threat_name,
            "threat_severity": r.threat_severity or "low",
            "duration_ms": r.duration_ms or 0,
            "recommended_action": r.recommended_action,
            "detections": r.detections or [],
            "risk_score": r.risk_score or 0,
            "action": r.action or "allow",
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
        })

    return {
        "total": total,
        "items": items,
        "limit": limit,
        "offset": offset,
    }

@router.get("/history/{scan_id}")
def get_scan_report(scan_id: str, db: Session = Depends(get_db)):
    try:
        record_uuid = uuid.UUID(scan_id)
        record = db.query(ScannedFile).filter(ScannedFile.id == record_uuid).first()
    except (ValueError, AttributeError):
        record = db.query(ScannedFile).filter(ScannedFile.id == scan_id).first()

    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    return {
        "id": str(record.id),
        "filename": record.filename,
        "file_hash": record.file_hash,
        "md5": record.md5,
        "file_size": record.size_bytes,
        "entropy": record.entropy,
        "scan_engine": record.scan_engine,
        "is_malicious": record.is_malicious,
        "status": record.status or ("INFECTED" if record.is_malicious else "CLEAN"),
        "threat_name": record.threat_name,
        "threat_severity": record.threat_severity or "low",
        "duration_ms": record.duration_ms or 0,
        "recommended_action": record.recommended_action,
        "detections": record.detections or [],
        "risk_score": record.risk_score or 0,
        "action": record.action or "allow",
        "scanned_at": record.scanned_at.isoformat() if record.scanned_at else None,
    }

@router.delete("/history")
def clear_scan_history(db: Session = Depends(get_db)):
    deleted_count = db.query(ScannedFile).delete()
    db.commit()
    return {"message": f"Successfully cleared {deleted_count} scan records from history", "deleted": deleted_count}

@router.get("/status")
def get_status():
    return check_engine_health()

@router.post("/status/refresh")
def refresh_status():
    return check_engine_health()
