import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ..db.base import Base

class ScannedFile(Base):
    __tablename__ = "scanned_files"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    filename = Column(String(512))
    file_hash = Column(String(128), index=True)
    size_bytes = Column(Integer)
    is_malicious = Column(Boolean, default=False)
    detections = Column(JSON)
    risk_score = Column(Integer)
    action = Column(String(50))
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

class URLAnalysis(Base):
    __tablename__ = "url_analysis"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    url = Column(Text)
    domain = Column(String(255))
    is_malicious = Column(Boolean, default=False)
    is_phishing = Column(Boolean, default=False)
    risk_score = Column(Integer)
    categories = Column(JSON)
    action = Column(String(50))
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

class APKAnalysis(Base):
    __tablename__ = "apk_analysis"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    filename = Column(String(512))
    package_name = Column(String(255))
    apk_hash = Column(String(128), index=True)
    permissions = Column(JSON)
    activities = Column(JSON)
    is_malicious = Column(Boolean, default=False)
    threat_score = Column(Integer)
    analysis_data = Column(JSON)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
