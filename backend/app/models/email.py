import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean, Integer, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class EmailAnalysis(Base):
    __tablename__ = "email_analysis"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    device_id = Column(GUID, ForeignKey("devices.id"), nullable=True, index=True)
    sender = Column(String(255), index=True)
    recipient = Column(String(255), index=True)
    subject = Column(String(512))
    spf_status = Column(String(20), default="pass")  # pass, fail, softfail, none
    dkim_status = Column(String(20), default="pass")  # pass, fail, none
    dmarc_status = Column(String(20), default="pass")  # pass, fail, none
    is_phishing = Column(Boolean, default=False)
    is_spoofed = Column(Boolean, default=False)
    is_bec = Column(Boolean, default=False)  # Business Email Compromise
    threat_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="low")  # low, moderate, high, critical, severe
    attachments = Column(JSON, default=list)
    embedded_urls = Column(JSON, default=list)
    indicators = Column(JSON, default=list)
    action_taken = Column(String(50), default="allow")  # allow, flag, quarantine
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())
