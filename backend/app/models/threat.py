import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class Threat(Base):
    __tablename__ = "threats"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    module = Column(String(100), index=True)  # url, malware, apk, network, email, ransomware, vulnerability, usb
    type = Column(String(100), index=True)
    severity = Column(String(20), index=True)  # low, moderate, high, critical, severe
    description = Column(Text)
    risk_score = Column(Integer)
    details = Column(JSON, default=dict)
    action_taken = Column(String(50), default="logged")  # allow, warn, block, quarantine, isolate, terminate
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ThreatEvent(Base):
    __tablename__ = "threat_events"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    threat_id = Column(GUID, ForeignKey("threats.id"), nullable=True, index=True)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    module = Column(String(100), nullable=True)
    event_data = Column(JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
