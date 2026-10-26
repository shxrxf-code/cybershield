from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from core.engine.detectors.apps import analyze_running_processes, terminate_process, isolate_process

router = APIRouter(prefix="/apps", tags=["App Monitor"])

class TerminateRequest(BaseModel):
    pid: int

class IsolateRequest(BaseModel):
    pid: int

@router.get("/")
def get_processes(limit: int = 50):
    procs = analyze_running_processes(limit=limit)
    suspicious_count = sum(1 for p in procs if p.get("is_suspicious"))
    return {
        "processes": procs,
        "total_active": len(procs),
        "suspicious_count": suspicious_count,
        "status": "warning" if suspicious_count > 0 else "clean",
    }

@router.post("/scan")
def trigger_process_scan():
    procs = analyze_running_processes(limit=100)
    suspicious = [p for p in procs if p.get("is_suspicious")]
    return {
        "scanned_count": len(procs),
        "suspicious_found": len(suspicious),
        "suspicious_processes": suspicious,
        "recommendation": "Review high risk processes and terminate unauthorized background tasks." if suspicious else "All monitored processes within safe thresholds."
    }

@router.post("/terminate")
def kill_process(req: TerminateRequest):
    result = terminate_process(req.pid)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to terminate process"))
    return result

@router.post("/isolate")
def suspend_proc(req: IsolateRequest):
    result = isolate_process(req.pid)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to isolate process"))
    return result

@router.get("/status")
def status():
    return {"module": "app_monitor", "enabled": True, "realtime_telemetry": True, "status": "operational"}
