import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer, Text, Float
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class ScannedFile(Base):
    __tablename__ = "scanned_files"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    filename = Column(String(512), index=True)
    file_path = Column(Text, nullable=True)
    file_hash = Column(String(128), index=True)
    md5 = Column(String(32), nullable=True)
    size_bytes = Column(Integer)
    entropy = Column(Float, nullable=True)
    scan_engine = Column(String(50), default="clamav+yara+heuristic")  # clamav, yara, internal
    is_malicious = Column(Boolean, default=False)
    status = Column(String(30), default="CLEAN")  # CLEAN, INFECTED, SUSPICIOUS, ERROR
    threat_name = Column(String(255), nullable=True)
    threat_severity = Column(String(20), default="low")  # low, moderate, high, critical, severe
    duration_ms = Column(Integer, default=0)
    recommended_action = Column(Text, nullable=True)
    detections = Column(JSON, default=list)
    risk_score = Column(Integer, default=0)
    action = Column(String(50), default="allow")  # allow, warn, quarantine, delete
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

class URLAnalysis(Base):
    __tablename__ = "url_analysis"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True)
    resolved_ip = Column(String(45), nullable=True)
    is_malicious = Column(Boolean, default=False)
    is_phishing = Column(Boolean, default=False)
    homograph_detected = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="low")
    categories = Column(JSON, default=list)
    features = Column(JSON, default=dict)
    action = Column(String(50), default="allow")  # allow, warn, block
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

class APKAnalysis(Base):
    __tablename__ = "apk_analysis"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    filename = Column(String(512))
    package_name = Column(String(255), index=True)
    version_name = Column(String(100), nullable=True)
    version_code = Column(Integer, nullable=True)
    apk_hash = Column(String(128), index=True)
    cert_fingerprint = Column(String(255), nullable=True)
    permissions = Column(JSON, default=list)
    dangerous_permissions = Column(JSON, default=list)
    suspicious_apis = Column(JSON, default=list)
    embedded_urls = Column(JSON, default=list)
    hardcoded_secrets = Column(JSON, default=list)
    is_malicious = Column(Boolean, default=False)
    threat_score = Column(Integer, default=0)
    analysis_data = Column(JSON, default=dict)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
