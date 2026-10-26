import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class NetworkEvent(Base):
    __tablename__ = "network_events"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    event_type = Column(String(100), index=True)  # dns_query, outbound_conn, port_scan, arp_spoof, mitm_alert
    source_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(45), index=True)
    destination_port = Column(Integer, index=True)
    protocol = Column(String(20), default="TCP")
    domain = Column(String(255), nullable=True, index=True)
    is_suspicious = Column(Boolean, default=False)
    threat_severity = Column(String(20), default="low")  # low, moderate, high, critical, severe
    action_taken = Column(String(50), default="allow")  # allow, alert, block
    payload_summary = Column(Text, nullable=True)
    extra_data = Column(JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class TrustedDomain(Base):
    __tablename__ = "trusted_domains"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    category = Column(String(100), default="business")
    added_by = Column(String(100), default="system")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class BlockedDomain(Base):
    __tablename__ = "blocked_domains"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    threat_category = Column(String(100), default="phishing")  # phishing, malware, c2, scam
    risk_score = Column(Integer, default=95)
    source = Column(String(100), default="threat_intel")
    added_at = Column(DateTime(timezone=True), server_default=func.now())
