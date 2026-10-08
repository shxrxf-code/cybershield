# CyberShield support scripts

| Script | What it does |
|---|---|
| `generate-secrets.sh` | Prints `POSTGRES_PASSWORD`, `SECRET_KEY`, `QUARANTINE_ENCRYPTION_KEY` for `infrastructure/.env` (nothing is stored). |

## `generate-secrets.sh`

```bash
scripts/generate-secrets.sh
```

Copy the three lines into `infrastructure/.env` (see
`infrastructure/.env.example`). Secrets are environment-only in CyberShield;
no `.env` file is ever committed.

Notes:

- `SECRET_KEY` — token signing secret. The API refuses to boot in production
  with a per-process generated value (tokens would invalidate on restart).
- `QUARANTINE_ENCRYPTION_KEY` — 64 hex chars (32 bytes) wrapped by the app into
  its AES-256-GCM quarantine key. **Never rotate** once quarantine data exists.
- Equivalent one-liners if you prefer to do it by hand:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"   # SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"   # POSTGRES_PASSWORD
python -c "import secrets; print(secrets.token_hex(32))"       # QUARANTINE_ENCRYPTION_KEY
```