import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id"), nullable=True)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True)
    action = Column(String(255), index=True)
    module = Column(String(100), index=True)
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    details = Column(JSON, default=dict)
    previous_hash = Column(String(64), nullable=True)  # SHA256 chain
    record_hash = Column(String(64), nullable=True)  # SHA256 of current record + previous_hash
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
