import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ..db.base import Base

class Threat(Base):
    __tablename__ = "threats"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    module = Column(String(100))
    type = Column(String(100))
    severity = Column(String(20))  # low, moderate, high, critical, severe
    description = Column(Text)
    risk_score = Column(Integer)
    metadata = Column(JSON)
    action_taken = Column(String(50))
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ThreatEvent(Base):
    __tablename__ = "threat_events"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_id = Column(UUID(as_uuid=True), ForeignKey("threats.id"))
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    event_data = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
