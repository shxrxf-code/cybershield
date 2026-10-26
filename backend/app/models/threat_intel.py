import uuid
from sqlalchemy import Column, String, DateTime, JSON, Integer, Text, Boolean
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    indicator_type = Column(String(50), index=True)  # hash_sha256, domain, ip, url, cve, pattern
    indicator_value = Column(String(512), index=True, nullable=False)
    threat_type = Column(String(100), default="malware")  # malware, phishing, botnet, c2, ransomware
    severity = Column(String(20), default="high")  # low, moderate, high, critical, severe
    confidence_score = Column(Integer, default=85)
    source = Column(String(100), default="internal_engine")  # virustotal, abuse_ch, internal_engine, cisa
    description = Column(Text, nullable=True)
    ioc_metadata = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
