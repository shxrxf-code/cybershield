import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class DevicePlatform(Base):
    __tablename__ = "device_platforms"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    platform_code = Column(String(50), unique=True, index=True)  # android, ios, windows, macos, linux, browser
    name = Column(String(100))
    agent_language = Column(String(50))  # kotlin, swift, rust, typescript
    supported_capabilities = Column(JSON)  # list of supported security capabilities
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Device(Base):
    __tablename__ = "devices"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id"), nullable=True)
    device_name = Column(String(255))
    platform = Column(String(50), index=True)  # android, ios, windows, macos, linux, browser
    device_id = Column(String(255), unique=True, index=True)
    os_version = Column(String(100))
    ip_address = Column(String(45), nullable=True)
    mac_address = Column(String(50), nullable=True)
    status = Column(String(50), default="active")  # active, offline, isolated, compromised
    protection_mode = Column(String(50), default="smart")  # smart, deep, network_shield, privacy, gaming, manual
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    security_settings = Column(JSON, default=dict)
    system_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
