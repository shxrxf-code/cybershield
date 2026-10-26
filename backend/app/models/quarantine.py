import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, BigInteger, Text, Boolean, JSON
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class QuarantineItem(Base):
    __tablename__ = "quarantine_items"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    filename = Column(String(512))
    file_hash = Column(String(128), index=True)
    file_path = Column(Text)
    quarantine_path = Column(Text)
    size_bytes = Column(BigInteger)
    reason = Column(Text)
    threat_type = Column(String(100), default="malware")  # malware, ransomware, trojan, suspicious
    detections = Column(Text)
    encryption_algorithm = Column(String(50), default="AES-256-GCM")
    restored = Column(Boolean, default=False)
    deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    restored_at = Column(DateTime(timezone=True), nullable=True)
