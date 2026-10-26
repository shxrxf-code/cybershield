from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

router = APIRouter(prefix="/settings", tags=["Settings"])

class SettingsUpdate(BaseModel):
    protection_mode: Optional[str] = "smart"  # smart, deep, network_shield, privacy, gaming, manual
    real_time_url_protection: Optional[bool] = True
    file_monitor_enabled: Optional[bool] = True
    network_shield_enabled: Optional[bool] = True
    ransomware_shield_enabled: Optional[bool] = True
    app_permission_monitor_enabled: Optional[bool] = True
    auto_quarantine_critical: Optional[bool] = True
    scan_schedule: Optional[str] = "daily"
    trusted_domains: Optional[List[str]] = []
    blocked_domains: Optional[List[str]] = []

# In-memory store initialized with defaults
ACTIVE_SETTINGS = {
    "protection_mode": "smart",
    "real_time_url_protection": True,
    "file_monitor_enabled": True,
    "network_shield_enabled": True,
    "ransomware_shield_enabled": True,
    "app_permission_monitor_enabled": True,
    "auto_quarantine_critical": True,
    "scan_schedule": "daily",
    "trusted_domains": ["google.com", "microsoft.com", "github.com", "apple.com"],
    "blocked_domains": ["malware-payload-drop.org", "fake-phish-bank.xyz", "cryptostealer-c2.net"],
}

@router.get("/")
def get_settings():
    return ACTIVE_SETTINGS

@router.put("/")
def update_settings(update: SettingsUpdate):
    for key, val in update.dict(exclude_unset=True).items():
        ACTIVE_SETTINGS[key] = val
    return {"message": "Security settings updated successfully", "settings": ACTIVE_SETTINGS}

@router.post("/mode/{mode_name}")
def switch_protection_mode(mode_name: str):
    valid_modes = ["smart", "deep", "network_shield", "privacy", "gaming", "manual"]
    if mode_name.lower() not in valid_modes:
        mode_name = "smart"
    
    mode = mode_name.lower()
    ACTIVE_SETTINGS["protection_mode"] = mode
    
    # Adjust operational profile based on mode
    if mode == "gaming":
        ACTIVE_SETTINGS["file_monitor_enabled"] = False
        ACTIVE_SETTINGS["scan_schedule"] = "manual"
    elif mode == "privacy":
        ACTIVE_SETTINGS["app_permission_monitor_enabled"] = True
        ACTIVE_SETTINGS["network_shield_enabled"] = True
    elif mode == "deep":
        ACTIVE_SETTINGS["real_time_url_protection"] = True
        ACTIVE_SETTINGS["file_monitor_enabled"] = True
        ACTIVE_SETTINGS["ransomware_shield_enabled"] = True
        ACTIVE_SETTINGS["scan_schedule"] = "hourly"
    elif mode == "smart":
        ACTIVE_SETTINGS["real_time_url_protection"] = True
        ACTIVE_SETTINGS["file_monitor_enabled"] = True
        ACTIVE_SETTINGS["network_shield_enabled"] = True
        ACTIVE_SETTINGS["ransomware_shield_enabled"] = True
        ACTIVE_SETTINGS["app_permission_monitor_enabled"] = True
        ACTIVE_SETTINGS["scan_schedule"] = "daily"
        
    return {"message": f"Protection mode switched to {mode.replace('_', ' ').title()}", "settings": ACTIVE_SETTINGS}

@router.post("/reset")
def reset_settings():
    ACTIVE_SETTINGS.update({
        "protection_mode": "smart",
        "real_time_url_protection": True,
        "file_monitor_enabled": True,
        "network_shield_enabled": True,
        "ransomware_shield_enabled": True,
        "app_permission_monitor_enabled": True,
        "auto_quarantine_critical": True,
        "scan_schedule": "daily",
    })
    return {"message": "Settings restored to default security baseline", "settings": ACTIVE_SETTINGS}
