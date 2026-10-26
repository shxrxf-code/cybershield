# CyberShield API Reference & Specification

CyberShield Backend API is built on FastAPI and runs at `http://localhost:8000/api/v1` with interactive OpenAPI Swagger UI at `http://localhost:8000/docs`.

## 1. Authentication & RBAC (`/api/v1/auth`)
- `POST /register`: Registers new cybersecurity user/operator.
- `POST /login`: Issues JWT bearer access token (`HS256`).
- `GET /me`: Returns currently authenticated identity and role permissions.
- `POST /api-key`: Generates or rotates a machine-to-machine API key.

## 2. Device Management (`/api/v1/devices`)
- `GET /`: Lists all registered endpoint devices, platforms, and current health status.
- `POST /enroll`: Registers a new device agent with cryptographic device UUID.
- `GET /{device_id}`: Fetches telemetry, OS version, and security settings for an endpoint.
- `POST /{device_id}/heartbeat`: Receives agent heartbeat and syncs state.

## 3. Threat Detection & Events (`/api/v1/threats`)
- `GET /`: Fetches detected threat incidents with severity filters (`low`, `moderate`, `high`, `critical`, `severe`).
- `POST /`: Ingests an endpoint detection event.
- `POST /{threat_id}/resolve`: Marks an incident as mitigated/resolved.
- `GET /stats`: Aggregates active vs blocked threats and risk distribution.

## 4. Full Device & File Scanner (`/api/v1/scan`)
- `POST /file`: Multipart file upload for on-demand ClamAV, YARA, and heuristic static inspection.
- `POST /batch`: Batch file path scan for local desktop agents.
- `POST /eicar-test`: Harmless EICAR antivirus verification endpoint.
- `GET /history`: Returns historical scanned files, hashes, and detections.

## 5. URL & Phishing Protection (`/api/v1/url`)
- `POST /scan`: Scans URL for phishing keywords, newly registered domains, Punycode homographs, and risk score.
- `POST /unshorten`: Expands shortened redirects (`bit.ly`, `tinyurl`) to identify underlying destinations.
- `GET /reputation/{domain}`: Checks domain against trusted and blocked lists.

## 6. Android APK Security (`/api/v1/apk`)
- `POST /analyze`: Multipart APK upload. Parses manifest, dangerous permissions, cert fingerprint, and hardcoded secrets.
- `GET /results/{apk_id}`: Retrieves static analysis report and MobSF adapter score.

## 7. Network Shield & DNS (`/api/v1/network`)
- `POST /check`: Evaluates destination IP or domain against intrusion lists.
- `GET /events`: Lists suspicious outbound connections, DNS queries, and ARP alerts.
- `POST /block-domain`: Blacklists a malicious domain.
- `POST /whitelist-domain`: Adds trusted domain to bypass filter.

## 8. App & Process Monitor (`/api/v1/apps`)
- `GET /`: Lists active host processes with CPU, memory, and risk scores.
- `POST /scan`: Runs behavioral anomaly detection across running processes.
- `POST /terminate`: Terminates malicious process by PID (`{"pid": 1234}`).
- `POST /isolate`: Suspends process execution to prevent damage.

## 9. Browser Protection (`/api/v1/browser`)
- `POST /check-url`: Validates webpage safety for browser extension.
- `POST /check-download`: Pre-screens download payload safety.
- `POST /analyze-extension`: Audits extension manifest permissions.
- `GET /stats`: Real-time browser protection metrics.

## 10. Ransomware Protection (`/api/v1/ransomware`)
- `GET /status`: Retrieves honeypot canary status and mass modification monitor health.
- `POST /deploy-canaries`: Deploys decoy canary tokens to monitored folders.
- `POST /verify-canaries`: Verifies canaries are intact and unencrypted.
- `POST /test-tripwire`: Safely executes a self-test of the canary alarm.
- `POST /check-entropy`: Calculates Shannon entropy for sample payload.

## 11. System Vulnerability Scanner (`/api/v1/vulnerabilities`)
- `GET /`: Returns latest listening ports and configuration findings.
- `POST /scan`: Runs full host port audit and posture evaluation.

## 12. Quarantine Management (`/api/v1/quarantine`)
- `GET /`: Lists all isolated files in encrypted vault.
- `POST /quarantine`: Encrypts (AES-256) and moves file to `./quarantine`.
- `POST /{item_id}/restore`: Restores quarantined file to original location (false-positive handling).
- `DELETE /{item_id}`: Permanently deletes malicious payload.

## 13. Settings & Protection Modes (`/api/v1/settings`)
- `GET /`: Fetches active protection mode, module toggles, and domain lists.
- `PUT /`: Updates security preferences.
- `POST /mode/{mode_name}`: Switches operational profile (`smart`, `deep`, `network_shield`, `privacy`, `gaming`, `manual`).
- `POST /reset`: Resets settings to baseline defaults.

## 14. AI Threat Intelligence (`/api/v1/ai`)
- `POST /predict`: Generates explainable risk score (0–100) with factor breakdowns.
- `GET /models`: Returns status of Isolation Forest and Scikit-learn inference engines.

## 15. Security Reports & Audit (`/api/v1/reports`, `/api/v1/audit`)
- `GET /reports/summary`: Generates compliance audit summary.
- `GET /audit/logs`: Fetches SHA-256 chained tamper-evident audit logs.
