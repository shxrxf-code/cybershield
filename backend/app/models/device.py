import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ..db.base import Base

class Device(Base):
    __tablename__ = "devices"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    device_name = Column(String(255))
    platform = Column(String(50))  # android, ios, windows, macos, linux
    device_id = Column(String(255), unique=True)
    os_version = Column(String(100))
    last_seen = Column(DateTime(timezone=True))
    security_settings = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
