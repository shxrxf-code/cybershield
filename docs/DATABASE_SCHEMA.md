# CyberShield Database Schema & Data Dictionary

The persistence layer is implemented with SQLAlchemy DeclarativeBase with cross-database support for SQLite and PostgreSQL. All 21 required tables are enumerated below.

## Entity Relationship Summary

```
                      +-------------------+
                      |       users       |
                      +---------+---------+
                                |
             +------------------+------------------+
             |                                     |
   +---------v---------+                 +---------v---------+
   |      devices      |                 | security_reports  |
   +---------+---------+                 +-------------------+
             |
             +---> security_settings
             +---> monitoring_permissions
             +---> threats --------> threat_events
             +---> scanned_files
             +---> apk_analysis
             +---> url_analysis
             +---> network_events
             +---> email_analysis
             +---> application_events
             +---> permission_events
             +---> quarantine_items
             +---> notifications
             +---> audit_logs (chained SHA256)
```

## Table Definitions

### 1. `users`
- `id` (GUID / CHAR(36), PK): Unique user identifier.
- `email` (VARCHAR(255), UNIQUE, INDEX): Account email address.
- `name` (VARCHAR(255)): Display name.
- `hashed_password` (VARCHAR(255)): Bcrypt password hash.
- `role` (VARCHAR(50)): User RBAC role (`admin`, `analyst`, `operator`, `user`).
- `api_key` (VARCHAR(255), UNIQUE): Machine-to-machine integration token.
- `is_active` (BOOLEAN): Account status.
- `created_at`, `updated_at` (TIMESTAMP): Audit timestamps.

### 2. `devices`
- `id` (GUID, PK): Endpoint device identifier.
- `user_id` (GUID, FK -> `users.id`): Enrolled user.
- `device_name` (VARCHAR(255)): Hostname or friendly device name.
- `platform` (VARCHAR(50), INDEX): OS identifier (`android`, `ios`, `windows`, `macos`, `linux`, `browser`).
- `device_id` (VARCHAR(255), UNIQUE, INDEX): Hardware/installation GUID.
- `os_version` (VARCHAR(100)): OS release string.
- `ip_address`, `mac_address` (VARCHAR): Network hardware addresses.
- `status` (VARCHAR(50)): Health state (`active`, `offline`, `isolated`, `compromised`).
- `protection_mode` (VARCHAR(50)): Active mode (`smart`, `deep`, `network_shield`, `privacy`, `gaming`, `manual`).
- `last_seen` (TIMESTAMP): Heartbeat timestamp.

### 3. `device_platforms`
- `id` (GUID, PK): Primary key.
- `platform_code` (VARCHAR(50), UNIQUE, INDEX): Short code (`android`, `linux`, etc.).
- `name` (VARCHAR(100)): Full platform title.
- `agent_language` (VARCHAR(50)): Implementation language (`kotlin`, `swift`, `rust`, `typescript`).
- `supported_capabilities` (JSON): Array of platform-supported security hooks.
- `is_active` (BOOLEAN): Support state.

### 4. `security_settings`
- `id` (GUID, PK): Primary key.
- `device_id` (GUID, FK -> `devices.id`): Associated device.
- `protection_mode` (VARCHAR(50)): Policy preset.
- `real_time_url_protection` (BOOLEAN): Module A switch.
- `file_monitor_enabled` (BOOLEAN): Module B switch.
- `network_shield_enabled` (BOOLEAN): Module E switch.
- `ransomware_shield_enabled` (BOOLEAN): Module H switch.
- `app_permission_monitor_enabled` (BOOLEAN): Module D switch.
- `auto_quarantine_critical` (BOOLEAN): Automated mitigation switch.
- `scan_schedule` (VARCHAR(50)): Frequency (`manual`, `hourly`, `daily`, `weekly`).
- `advanced_config` (JSON): Custom tuning parameters.

### 5. `monitoring_permissions`
- `id` (GUID, PK): Primary key.
- `device_id` (GUID, FK -> `devices.id`): Target device.
- `permission_name` (VARCHAR(100), INDEX): Monitored permission (`camera`, `microphone`, `sms`, etc.).
- `granted` (BOOLEAN): Grant state.
- `risk_level` (VARCHAR(50)): Risk evaluation (`low`, `moderate`, `high`, `critical`).
- `last_verified` (TIMESTAMP): Telemetry verification time.

### 6. `threats`
- `id` (GUID, PK): Threat incident ID.
- `device_id` (GUID, FK -> `devices.id`): Affected device.
- `module` (VARCHAR(100), INDEX): Detection origin (`url`, `malware`, `apk`, `network`, `ransomware`).
- `type` (VARCHAR(100), INDEX): Threat category.
- `severity` (VARCHAR(20), INDEX): Level (`low`, `moderate`, `high`, `critical`, `severe`).
- `description` (TEXT): Incident summary.
- `risk_score` (INTEGER): Explainable score 0–100.
- `details` (JSON): Raw telemetry payload.
- `action_taken` (VARCHAR(50)): Policy action (`allow`, `warn`, `block`, `quarantine`, `isolate`, `terminate`).
- `resolved` (BOOLEAN): Incident lifecycle state.

### 7. `threat_events`
- `id` (GUID, PK): Primary key.
- `threat_id` (GUID, FK -> `threats.id`): Parent threat.
- `device_id` (GUID, FK -> `devices.id`): Source device.
- `module` (VARCHAR(100)): Originating detector.
- `event_data` (JSON): Event details.
- `timestamp` (TIMESTAMP): Occurrence time.

### 8. `scanned_files`
- `id` (GUID, PK): Primary key.
- `device_id` (GUID, FK -> `devices.id`): Target device.
- `filename` (VARCHAR(512), INDEX): Base filename.
- `file_path` (TEXT): Absolute path.
- `file_hash` (VARCHAR(128), INDEX): SHA256 hash.
- `md5` (VARCHAR(32)): MD5 hash.
- `size_bytes` (INTEGER): File size.
- `entropy` (FLOAT): Shannon entropy.
- `scan_engine` (VARCHAR(50)): Engine identifier.
- `is_malicious` (BOOLEAN): Malware indicator.
- `detections` (JSON): Engine detection strings.
- `risk_score` (INTEGER): 0–100 score.
- `action` (VARCHAR(50)): File action.

### 9. `apk_analysis`
- `id` (GUID, PK): Primary key.
- `device_id` (GUID, FK -> `devices.id`): Target device.
- `filename` (VARCHAR(512)): Package file.
- `package_name` (VARCHAR(255), INDEX): Android package ID.
- `version_name`, `version_code`: Version info.
- `apk_hash` (VARCHAR(128), INDEX): SHA256 hash.
- `cert_fingerprint` (VARCHAR(255)): Signing certificate hash.
- `permissions`, `dangerous_permissions`, `suspicious_apis`, `embedded_urls`, `hardcoded_secrets` (JSON): Static analysis findings.
- `is_malicious` (BOOLEAN): Threat flag.
- `threat_score` (INTEGER): 0–100 risk score.

### 10. `url_analysis`
- `id` (GUID, PK): Primary key.
- `url` (TEXT): Target URL.
- `domain` (VARCHAR(255), INDEX): Host domain.
- `is_malicious`, `is_phishing`, `homograph_detected` (BOOLEAN): Detection flags.
- `risk_score` (INTEGER): 0–100 score.
- `categories`, `features` (JSON): Extracted indicators.
- `action` (VARCHAR(50)): Policy enforcement.

### 11. `network_events`
- `id` (GUID, PK): Primary key.
- `event_type` (VARCHAR(100), INDEX): Event type (`dns_query`, `outbound_conn`, `arp_spoof`).
- `source_ip`, `destination_ip`, `protocol`, `domain`: Connection metadata.
- `is_suspicious` (BOOLEAN): Anomaly flag.
- `action_taken` (VARCHAR(50)): Filter action (`allow`, `alert`, `block`).

### 12. `email_analysis`
- `id` (GUID, PK): Primary key.
- `sender`, `recipient`, `subject`: Email headers.
- `spf_status`, `dkim_status`, `dmarc_status`: Auth results.
- `is_phishing`, `is_spoofed`, `is_bec`: Threat indicators.
- `attachments`, `embedded_urls`, `indicators` (JSON): Payload findings.

### 13. `application_events`
- `id` (GUID, PK): Primary key.
- `app_name`, `package_name`, `process_id`, `executable_path`: Process metadata.
- `cpu_percent`, `memory_percent` (FLOAT): Resource usage.
- `is_suspicious` (BOOLEAN): Anomaly flag.
- `action_taken` (VARCHAR(50)): Action (`monitored`, `isolated`, `terminated`).

### 14. `permission_events`
- `id` (GUID, PK): Primary key.
- `app_name`, `permission_name`, `event_type`: Permission access log.
- `is_excessive` (BOOLEAN): Risk flag.
- `risk_score` (INTEGER): Heuristic score.

### 15. `quarantine_items`
- `id` (GUID, PK): Primary key.
- `filename`, `file_hash`, `file_path`, `quarantine_path`: File paths and hashes.
- `reason`, `threat_type`, `detections`: Incident context.
- `encryption_algorithm` (VARCHAR(50)): Default `AES-256-GCM`.
- `restored`, `deleted` (BOOLEAN): State flags.

### 16. `threat_intelligence`
- `id` (GUID, PK): Primary key.
- `indicator_type`, `indicator_value`: Indicator of Compromise (IoC).
- `threat_type`, `severity`, `confidence_score`, `source`: Intel feeds.

### 17. `security_reports`
- `id` (GUID, PK): Primary key.
- `title`, `report_type`, `overall_score`, `summary`, `content`, `format`: Generated report metadata.

### 18. `notifications`
- `id` (GUID, PK): Primary key.
- `title`, `message`, `category`, `severity`, `is_read`: User alerts.

### 19. `audit_logs`
- `id` (GUID, PK): Primary key.
- `action`, `module`, `resource_type`, `resource_id`, `ip_address`: Audit event.
- `previous_hash` (VARCHAR(64)): SHA-256 hash of previous audit record.
- `record_hash` (VARCHAR(64)): SHA-256 hash of this record + previous hash (tamper evidence).

### 20. `trusted_domains`
- `id` (GUID, PK): Primary key.
- `domain` (VARCHAR(255), UNIQUE, INDEX): Whitelisted hostname.

### 21. `blocked_domains`
- `id` (GUID, PK): Primary key.
- `domain` (VARCHAR(255), UNIQUE, INDEX): Blacklisted hostname.
- `threat_category`, `risk_score`: Filter severity.
