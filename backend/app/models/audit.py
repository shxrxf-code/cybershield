import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ..db.base import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    action = Column(String(255))
    module = Column(String(100))
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    details = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
