# Test Cases

## URL Protection
- TC-URL-001: Phishing URL with login keywords -> high/critical risk
- TC-URL-002: Benign URL -> low risk, allow
- TC-URL-003: IP-based URL -> flagged
- TC-URL-004: Suspicious TLD -> flagged

## File Scanning
- TC-FILE-001: EICAR test file -> detected, quarantined
- TC-FILE-002: Clean file -> allow
- TC-FILE-003: ClamAV detection -> reported

## API
- TC-API-001: Health check returns ok
- TC-API-002: URL scan endpoint functional
- TC-API-003: File scan endpoint functional

## Core Engine
- TC-CORE-001: Risk scoring 0-100 range
- TC-CORE-002: Risk levels correct
- TC-CORE-003: Explainability populated
