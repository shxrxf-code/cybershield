from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime


class VerdictEnum(str):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ThreatLevelEnum(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ----------------------------------------------------
# URL & Phishing Models
# ----------------------------------------------------
class UrlScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan for phishing/malware")
    device_uuid: Optional[str] = None
    deep_analysis: bool = Field(default=True, description="Query external threat intel if true")


class UrlAnalysisResult(BaseModel):
    url: str
    domain: str
    verdict: str  # SAFE, SUSPICIOUS, MALICIOUS
    risk_score: int  # 0 to 100
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    reasons: List[str] = []
    features: Dict[str, Any] = {}
    is_typosquatting: bool = False
    is_homograph: bool = False
    domain_age_days: Optional[int] = None
    ssl_valid: bool = True
    threat_intel_matches: List[str] = []


# ----------------------------------------------------
# APK Malware Models
# ----------------------------------------------------
class ApkStaticScanRequest(BaseModel):
    package_name: str
    app_name: Optional[str] = None
    version_code: Optional[int] = None
    permissions: List[str] = []
    dangerous_apis: List[str] = []
    embedded_urls: List[str] = []
    native_libraries: List[str] = []
    cert_sha256: Optional[str] = None
    is_debuggable: bool = False
    uses_accessibility: bool = False
    uses_overlay: bool = False
    device_uuid: Optional[str] = None


class ApkMalwareReport(BaseModel):
    package_name: str
    verdict: str
    risk_score: int
    threat_level: str
    detected_families: List[str] = []  # Banking, Trojan, Spyware, Ransomware
    risky_permissions: List[str] = []
    suspicious_behaviors: List[str] = []
    reputation_status: str
    recommendation: str


# ----------------------------------------------------
# Document Security Models
# ----------------------------------------------------
class DocumentScanRequest(BaseModel):
    file_name: str
    file_hash_sha256: str
    file_size_bytes: int
    file_extension: str
    has_macros: bool = False
    embedded_scripts: List[str] = []
    embedded_urls: List[str] = []
    suspicious_tags: List[str] = []


class DocumentScanResponse(BaseModel):
    file_name: str
    verdict: str
    risk_score: int
    threat_level: str
    exploit_indicators: List[str] = []
    macro_risk: bool
    safe_to_open: bool
    quarantine_recommended: bool


# ----------------------------------------------------
# SMS & Notification Scam Models
# ----------------------------------------------------
class SmsScanRequest(BaseModel):
    sender: str
    body: str
    timestamp_ms: Optional[int] = None


class SmsScanResponse(BaseModel):
    sender: str
    classification: str  # SAFE, SCAM, PHISHING, BANKING_FRAUD
    risk_score: int
    threat_level: str
    extracted_urls: List[str] = []
    matched_patterns: List[str] = []
    recommended_action: str


class NotificationScanRequest(BaseModel):
    package_name: str  # com.whatsapp, org.telegram.messenger, etc.
    app_label: str
    title: str
    text: str
    device_uuid: Optional[str] = None


class NotificationScanResponse(BaseModel):
    is_threat: bool
    verdict: str
    threat_type: Optional[str] = None  # CRYPTO_SCAM, PHISHING_LINK, FAKE_GIVEAWAY, MALWARE_DOWNLOAD
    risk_score: int
    extracted_links: List[str] = []
    warning_message: Optional[str] = None


# ----------------------------------------------------
# Email Security Models
# ----------------------------------------------------
class EmailScanRequest(BaseModel):
    sender: str
    subject: str
    body: str
    headers: Dict[str, str] = {}
    spf_result: Optional[str] = "PASS"  # PASS, FAIL, SOFTFAIL, NONE
    dkim_result: Optional[str] = "PASS"
    dmarc_result: Optional[str] = "PASS"
    attachments: List[str] = []


class EmailScanResponse(BaseModel):
    verdict: str
    risk_score: int
    auth_status: Dict[str, str]
    suspicious_elements: List[str] = []
    phishing_probability: float


# ----------------------------------------------------
# Device Security Center Models
# ----------------------------------------------------
class DeviceAuditRequest(BaseModel):
    device_uuid: str
    device_model: str
    os_version: str
    is_rooted: bool
    developer_mode_enabled: bool
    usb_debugging_enabled: bool
    adb_enabled: bool
    unknown_sources_enabled: bool
    accessibility_services_count: int
    overlay_apps_count: int
    installed_apps_count: int


class DeviceAuditResponse(BaseModel):
    overall_security_score: int  # 0 to 100
    security_posture: str  # SECURE, ELEVATED_RISK, COMPROMISED
    critical_findings: List[str] = []
    remediation_steps: List[str] = []


# ----------------------------------------------------
# Network Event Models
# ----------------------------------------------------
class NetworkAuditRequest(BaseModel):
    ssid: Optional[str] = None
    is_public_wifi: bool = False
    is_encrypted: bool = True
    dns_servers: List[str] = []
    gateway_mac: Optional[str] = None
    arp_anomaly_detected: bool = False
    ssl_stripping_detected: bool = False


class NetworkAuditResponse(BaseModel):
    threat_level: str
    verdict: str
    mitm_risk: bool
    dns_hijack_risk: bool
    recommendations: List[str] = []


# ----------------------------------------------------
# Dashboard & Reports
# ----------------------------------------------------
class DashboardSummaryResponse(BaseModel):
    security_score: int
    threat_level: str
    threats_blocked_total: int
    scanned_apps_count: int
    scanned_files_count: int
    network_status: str
    recent_threats: List[Dict[str, Any]] = []


class ReportExportRequest(BaseModel):
    device_uuid: str
    period: str = "WEEKLY"  # DAILY, WEEKLY, MONTHLY
    format: str = "JSON"  # JSON, PDF, CSV
