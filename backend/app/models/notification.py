import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id"), nullable=True, index=True)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    category = Column(String(50), default="threat")  # threat, system, quarantine, update
    severity = Column(String(20), default="moderate")  # low, moderate, high, critical, severe
    is_read = Column(Boolean, default=False)
    action_url = Column(String(255), nullable=True)
    extra_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
