from fastapi import APIRouter

router = APIRouter(prefix="/permissions", tags=["Permissions"])

@router.get("/")
def list_items():
    return {
        "permissions": [
            {"name": "Camera", "status": "denied", "risk": "medium", "apps": []},
            {"name": "Microphone", "status": "denied", "risk": "medium", "apps": []},
            {"name": "Location", "status": "denied", "risk": "medium", "apps": []},
            {"name": "Storage", "status": "granted", "risk": "low", "apps": ["CyberShield"]},
            {"name": "Contacts", "status": "denied", "risk": "high", "apps": []},
            {"name": "SMS", "status": "denied", "risk": "high", "apps": []},
            {"name": "Accessibility", "status": "denied", "risk": "high", "apps": []},
        ],
        "count": 7
    }

@router.get("/status")
def status():
    return {"module": "permissions", "enabled": True, "monitoring": True, "status": "operational"}
