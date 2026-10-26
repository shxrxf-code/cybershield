import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class SecuritySetting(Base):
    __tablename__ = "security_settings"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    user_id = Column(GUID, ForeignKey("users.id"), nullable=True)
    protection_mode = Column(String(50), default="smart")  # smart, deep, network_shield, privacy, gaming, manual
    real_time_url_protection = Column(Boolean, default=True)
    file_monitor_enabled = Column(Boolean, default=True)
    network_shield_enabled = Column(Boolean, default=True)
    ransomware_shield_enabled = Column(Boolean, default=True)
    app_permission_monitor_enabled = Column(Boolean, default=True)
    auto_quarantine_critical = Column(Boolean, default=True)
    scan_schedule = Column(String(50), default="daily")  # manual, hourly, daily, weekly
    advanced_config = Column(JSON, default=dict)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

class MonitoringPermission(Base):
    __tablename__ = "monitoring_permissions"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), index=True)
    permission_name = Column(String(100), index=True)  # camera, microphone, location, contacts, sms, storage, accessibility, notifications, background
    granted = Column(Boolean, default=False)
    risk_level = Column(String(50), default="moderate")  # low, moderate, high, critical
    rationale = Column(String(255), nullable=True)
    last_verified = Column(DateTime(timezone=True), server_default=func.now())
