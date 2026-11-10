import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_uuid = Column(String(128), unique=True, index=True, nullable=False)
    device_model = Column(String(100), nullable=True)
    os_version = Column(String(50), nullable=True)
    app_version = Column(String(30), nullable=True)
    is_rooted = Column(Boolean, default=False)
    security_score = Column(Integer, default=100)
    last_seen = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    threat_logs = relationship("ThreatLog", back_populates="device", cascade="all, delete-orphan")
    scan_records = relationship("ScanRecord", back_populates="device", cascade="all, delete-orphan")
    reports = relationship("SecurityReport", back_populates="device", cascade="all, delete-orphan")


class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=True, index=True)
    module_type = Column(String(50), nullable=False, index=True)  # URL, APK, DOC, NOTIF, SMS, EMAIL, NETWORK
    threat_level = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    verdict = Column(String(20), nullable=False)  # SAFE, SUSPICIOUS, MALICIOUS
    risk_score = Column(Integer, nullable=False)  # 0 - 100
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    action_taken = Column(String(50), default="BLOCKED")  # BLOCKED, QUARANTINED, WARNED, MONITORED
    indicators = Column(JSON, nullable=True)  # Matched rules, IoCs, lexical signals
    raw_payload = Column(Text, nullable=True)  # Sanitized URL, hash, snippet
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    device = relationship("Device", back_populates="threat_logs")


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=True, index=True)
    scan_type = Column(String(50), nullable=False)  # FULL_DEVICE, APK, FILE, URL, NETWORK
    status = Column(String(30), default="COMPLETED")  # COMPLETED, FAILED, RUNNING
    risk_score = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    scanned_items_count = Column(Integer, default=0)
    details = Column(JSON, nullable=True)
    duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    device = relationship("Device", back_populates="scan_records")


class PhishingDomain(Base):
    __tablename__ = "phishing_domains"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), unique=True, index=True, nullable=False)
    source = Column(String(50), nullable=False)  # OpenPhish, PhishTank, ML_Classifier, ThreatIntel
    confidence_score = Column(Integer, default=90)
    is_active = Column(Boolean, default=True)
    metadata_info = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class MalwareSignature(Base):
    __tablename__ = "malware_signatures"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sha256_hash = Column(String(64), unique=True, index=True, nullable=False)
    package_name = Column(String(255), nullable=True, index=True)
    malware_family = Column(String(50), nullable=False)  # Trojan, Banking, Spyware, Ransomware, Adware
    risk_score = Column(Integer, default=100)
    detection_rule = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=True, index=True)
    period = Column(String(20), nullable=False)  # DAILY, WEEKLY, MONTHLY
    security_score = Column(Integer, default=100)
    threats_blocked = Column(Integer, default=0)
    scans_conducted = Column(Integer, default=0)
    summary_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    device = relationship("Device", back_populates="reports")
