-- ==============================================================================
-- ShieldGuard AI - Enterprise Cybersecurity Platform SQL Schema
-- Target: PostgreSQL 15+ / TimescaleDB Compatible
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------------------------
-- Table: devices
-- Stores enrolled endpoint telemetry, hardware identity, and baseline posture
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_uuid VARCHAR(128) NOT NULL UNIQUE,
    device_model VARCHAR(100),
    os_version VARCHAR(50),
    app_version VARCHAR(30),
    is_rooted BOOLEAN DEFAULT FALSE,
    developer_mode_enabled BOOLEAN DEFAULT FALSE,
    usb_debugging_enabled BOOLEAN DEFAULT FALSE,
    adb_enabled BOOLEAN DEFAULT FALSE,
    unknown_sources_enabled BOOLEAN DEFAULT FALSE,
    security_score INTEGER DEFAULT 100 CHECK (security_score BETWEEN 0 AND 100),
    last_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_devices_uuid ON devices(device_uuid);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at DESC);

-- ------------------------------------------------------------------------------
-- Table: threat_logs
-- Central telemetry ledger for all intercepted threats across 12 modules
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    module_type VARCHAR(50) NOT NULL, -- URL, APK, DOCUMENT, NOTIFICATION, SMS, EMAIL, NETWORK
    threat_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    verdict VARCHAR(20) NOT NULL,      -- SAFE, SUSPICIOUS, MALICIOUS
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    action_taken VARCHAR(50) DEFAULT 'BLOCKED', -- BLOCKED, QUARANTINED, WARNED, MONITORED
    indicators JSONB DEFAULT '{}'::jsonb,
    raw_payload TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threat_logs_device ON threat_logs(device_id);
CREATE INDEX idx_threat_logs_module ON threat_logs(module_type);
CREATE INDEX idx_threat_logs_level ON threat_logs(threat_level);
CREATE INDEX idx_threat_logs_created ON threat_logs(created_at DESC);
CREATE INDEX idx_threat_logs_indicators ON threat_logs USING GIN(indicators);

-- ------------------------------------------------------------------------------
-- Table: scan_records
-- Audit history of full-device, app, file, and network security scans
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL, -- FULL_DEVICE, APK, FILE, URL, NETWORK
    status VARCHAR(30) DEFAULT 'COMPLETED', -- COMPLETED, RUNNING, FAILED
    risk_score INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    scanned_items_count INTEGER DEFAULT 0,
    details JSONB DEFAULT '{}'::jsonb,
    duration_ms INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scan_records_device ON scan_records(device_id);
CREATE INDEX idx_scan_records_created ON scan_records(created_at DESC);

-- ------------------------------------------------------------------------------
-- Table: phishing_domains
-- Real-time threat intelligence cache for typosquatted and malicious domains
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS phishing_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL UNIQUE,
    source VARCHAR(50) NOT NULL, -- OpenPhish, PhishTank, ML_Classifier, ThreatIntel
    confidence_score INTEGER DEFAULT 90 CHECK (confidence_score BETWEEN 0 AND 100),
    is_active BOOLEAN DEFAULT TRUE,
    metadata_info JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_phishing_domain ON phishing_domains(domain);
CREATE INDEX idx_phishing_active ON phishing_domains(is_active);

-- ------------------------------------------------------------------------------
-- Table: malware_signatures
-- Static & dynamic signatures for banking trojans, ransomware, spyware APKs
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS malware_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sha256_hash VARCHAR(64) NOT NULL UNIQUE,
    package_name VARCHAR(255),
    malware_family VARCHAR(50) NOT NULL, -- Trojan, Banking, Spyware, Ransomware, Adware
    risk_score INTEGER DEFAULT 100,
    detection_rule JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_malware_hash ON malware_signatures(sha256_hash);
CREATE INDEX idx_malware_package ON malware_signatures(package_name);
CREATE INDEX idx_malware_family ON malware_signatures(malware_family);

-- ------------------------------------------------------------------------------
-- Table: security_reports
-- Consolidated Daily, Weekly, and Monthly security summaries
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    period VARCHAR(20) NOT NULL, -- DAILY, WEEKLY, MONTHLY
    security_score INTEGER DEFAULT 100,
    threats_blocked INTEGER DEFAULT 0,
    scans_conducted INTEGER DEFAULT 0,
    summary_json JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_reports_device ON security_reports(device_id);
CREATE INDEX idx_reports_period ON security_reports(period);
CREATE INDEX idx_reports_created ON security_reports(created_at DESC);
