from __future__ import annotations
from pydantic import BaseModel, Field, HttpUrl
from typing import Literal, List, Dict, Any, Optional
from datetime import datetime
import uuid

RiskLevel = Literal["low", "moderate", "high", "critical", "severe"]
ActionType = Literal["allow", "warn", "block", "quarantine", "isolate", "terminate", "request_approval", "restore"]

class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    reasons: List[str] = []
    explainability: Dict[str, float] = {}
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    sources: List[str] = []

class URLAnalysisRequest(BaseModel):
    url: HttpUrl
    referrer: Optional[HttpUrl] = None
    user_agent: Optional[str] = None
    device_id: Optional[uuid.UUID] = None

class URLAnalysisResult(BaseModel):
    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    url: str
    is_malicious: bool = False
    is_phishing: bool = False
    risk: RiskScore
    categories: List[str] = []
    redirects: List[str] = []
    final_url: Optional[str] = None
    blocked: bool = False
    action: ActionType = "allow"
    reasons: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class FileScanRequest(BaseModel):
    file_hash: str
    filename: str
    size_bytes: int = 0
    mime_type: Optional[str] = None
    device_id: Optional[uuid.UUID] = None

class FileScanResult(BaseModel):
    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    file_hash: str
    filename: str
    is_malicious: bool = False
    detections: List[Dict[str, Any]] = []
    risk: RiskScore
    action: ActionType = "allow"
    quarantined: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ThreatEvent(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    device_id: Optional[uuid.UUID] = None
    module: str
    type: str
    severity: RiskLevel
    description: str
    metadata: Dict[str, Any] = {}
    action_taken: ActionType = "warn"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    resolved: bool = False
