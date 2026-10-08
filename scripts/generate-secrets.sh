#!/usr/bin/env bash
#
# Generate fresh random secrets for the CyberShield stack.
#
# Paste the output into infrastructure/.env (see infrastructure/.env.example).
# Output is stdout-only so you can pipe it anywhere; nothing is written or
# stored by this script.
#
# Equivalent one-liners:
#   SECRET_KEY                python -c "import secrets; print(secrets.token_urlsafe(64))"
#   POSTGRES_PASSWORD          python -c "import secrets; print(secrets.token_urlsafe(32))"
#   QUARANTINE_ENCRYPTION_KEY python -c "import secrets; print(secrets.token_hex(32))"
#
# Why 32 bytes for the quarantine key: the app (app/services/quarantine.py)
# SHA-256-wraps the configured secret into the AES-256 key, so any high-entropy
# value works — but 32 bytes of hex maximizes the entropy available. NEVER
# rotate it after deployment: quarantined blobs are encrypted with it and
# become unreadable if it changes.

set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to generate secrets" >&2
    exit 1
fi

python3 - <<'PY'
import secrets

print("# CyberShield secrets for infrastructure/.env", end="\n\n")
print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(32)}")
print(f"SECRET_KEY={secrets.token_urlsafe(64)}")
print(f"QUARANTINE_ENCRYPTION_KEY={secrets.token_hex(32)}")
PY