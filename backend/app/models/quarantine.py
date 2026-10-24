import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, BigInteger, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ..db.base import Base

class QuarantineItem(Base):
    __tablename__ = "quarantine_items"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    filename = Column(String(512))
    file_hash = Column(String(128), index=True)
    file_path = Column(Text)
    quarantine_path = Column(Text)
    size_bytes = Column(BigInteger)
    reason = Column(Text)
    detections = Column(Text)
    restored = Column(Boolean, default=False)
    deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    restored_at = Column(DateTime(timezone=True))
