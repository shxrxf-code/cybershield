import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Integer, Text
from sqlalchemy.sql import func
from ..db.base import Base
from ..db.guid import GUID

class SecurityReport(Base):
    __tablename__ = "security_reports"
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id"), nullable=True)
    report_type = Column(String(50), default="audit")  # audit, compliance, vulnerability, threat_summary
    title = Column(String(255), nullable=False)
    overall_score = Column(Integer, default=85)
    summary = Column(Text, nullable=True)
    content = Column(JSON, default=dict)
    format = Column(String(20), default="json")  # json, pdf, csv
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
