from fastapi import APIRouter
from pathlib import Path
import os

router = APIRouter(prefix="/quarantine", tags=["Quarantine"])

QUARANTINE = Path(os.getenv("QUARANTINE_PATH", "./quarantine"))
QUARANTINE.mkdir(parents=True, exist_ok=True)

@router.get("/")
def list_quarantine():
    items = []
    for f in QUARANTINE.iterdir():
        if f.is_file():
            items.append({"name": f.name, "size": f.stat().st_size, "path": str(f)})
    return {"items": items, "count": len(items)}

@router.post("/restore")
def restore(filename: str):
    return {"restored": False, "message": "Restore requires manual approval and verification", "filename": filename}

@router.delete("/{filename}")
def delete_item(filename: str):
    return {"deleted": False, "message": "Permanent deletion requires explicit confirmation", "filename": filename}

@router.get("/status")
def status():
    return {"module": "quarantine", "enabled": True, "path": str(QUARANTINE), "status": "operational"}
