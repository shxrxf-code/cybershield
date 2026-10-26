import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer, Float, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class ApplicationEvent(Base):
    __tablename__ = "application_events"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    app_name = Column(String(255), index=True)
    package_name = Column(String(255), nullable=True, index=True)
    process_id = Column(Integer, nullable=True)
    executable_path = Column(Text, nullable=True)
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    is_suspicious = Column(Boolean, default=False)
    threat_indicators = Column(JSON, default=list)
    action_taken = Column(String(50), default="monitored")  # monitored, isolated, terminated
    recorded_at = Column(DateTime(timezone=True), server_default=func.now())

class PermissionEvent(Base):
    __tablename__ = "permission_events"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    app_name = Column(String(255), index=True)
    permission_name = Column(String(100), index=True)
    event_type = Column(String(50))  # requested, granted, revoked, accessed_in_background
    is_excessive = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
