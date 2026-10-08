# Configuration

All configuration is environment-driven (12-factor). No secret is hardcoded
and no secret is ever returned to API clients. Values are loaded by
`Settings` (`backend/app/core/config.py`) from the process environment and
optionally `.env` files (`.env`, then `../.env`, via
`pydantic-settings`). `get_settings()` caches the result as a process-wide
singleton (`functools.lru_cache`, maxsize 1), so tests replace it wholesale
rather than mutating shared state.

> **Note on `.env.example`:** `backend/.env.example` documents a
> `DEFAULT_YARA_RULES_DIR` variable. That variable is **ignored by the
> application**; the real YARA directory variable is `YARA_RULES_DIR`
> (field `yara_rules_dir`). When unset it defaults to
> `detection-engine/yara/rules` under the project root — see the
> [SSRF and URL scanning section](#url-scanning-and-ssrf-protection) below.

Every variable below is read as an environment variable name derived from the
field name by uppercasing (e.g. `app_name` ← `APP_NAME`). File/directory
settings accept plain paths.

## Application

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_NAME` | `CyberShield API` | Display name (API `title`). |
| `APP_VERSION` | `1.0.0` | Version string (API `version`). |
| `ENVIRONMENT` | `development` | `development` \| `test` \| `staging` \| `production`. |
| `DEBUG` | `false` | SQL echo on the engine; refused in production. |
| `API_V1_PREFIX` | `/api/v1` | Prefix for every route. |
| `DOCS_ENABLED` | `true` | Serve `/docs` (Swagger) and `/redoc`. |

## Database / Redis

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cybershield.db` | Async SQLAlchemy URL. SQLite for dev/test; `postgresql+asyncpg://…` for deployment. |
| `DATABASE_POOL_SIZE` | `10` | Pool size for non-SQLite engines. |
| `DATABASE_MAX_OVERFLOW` | `20` | Pool overflow for non-SQLite engines. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis for the distributed rate limiter and (when enabled) the queue. |
| `USE_REDIS_QUEUE` | `false` | When `true` the scan worker must run as a separate service; the API only publishes jobs. When `false` an in-process asyncio worker is started at boot. |

## Security / authentication

| Variable | Default | Meaning |
| --- | --- | --- |
| `SECRET_KEY` | random (64 url-safe chars) | Signs JWTs. **Must be pinned in production** — a generated key invalidates all tokens on restart and differs per replica. Production refuses to boot without an explicit key. |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access-token lifetime. Reported to clients as `expires_in`. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `14` | Refresh-token lifetime. Reported as `refresh_expires_in`. |
| `BCRYPT_ROUNDS` | `12` | Cost for legacy bcrypt verification (password rehash upgrades to Argon2id). |
| `ARGON2_ENABLED` | `true` | Enforce Argon2id (19 MiB, 2 iterations, 1 lane) for new hashes. |
| `PASSWORD_MIN_LENGTH` | `12` | Enforced minimum password length. |
| `MAX_FAILED_LOGINS` | `5` | Failed logins that lock an account. |
| `LOCKOUT_MINUTES` | `15` | Lockout window after the failure threshold. |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins (single value or JSON list accepted). |
| `CORS_ALLOW_CREDENTIALS` | `false` | Must not be combined with a wildcard origin (checked in production). |
| `TRUST_PROXY_HEADERS` | `false` | When `true`, `X-Forwarded-For` is honoured for client IP (rate limiting + audit). Only enable behind a proxy that overwrites it; the header is spoofable on a directly exposed host. |

## Rate limiting

| Variable | Default | Meaning |
| --- | --- | --- |
| `RATE_LIMIT_ENABLED` | `true` | Master switch for the rate limiter. |
| `RATE_LIMIT_DEFAULT_PER_MINUTE` | `60` | Requests/minute for the `default` bucket (API-key creation). |
| `RATE_LIMIT_AUTH_PER_MINUTE` | `10` | Requests/minute for the `auth` bucket (login, refresh, change-password, password-strength). |
| `RATE_LIMIT_SCAN_PER_MINUTE` | `30` | Requests/minute for the `scan` bucket (URL/email/text submissions). |
| `RATE_LIMIT_FILE_SCAN_PER_MINUTE` | `10` | Requests/minute for the `file_scan` bucket (file/APK uploads). |

The limiter is a sliding window. Redis-backed when `REDIS_URL` is reachable;
otherwise it degrades to an in-process per-process window and the health
endpoint reports `rate_limiter.degraded: true` (see
[../api/intel-and-health.md](../api/intel-and-health.md#health)).

## Upload / quarantine storage

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAX_UPLOAD_BYTES` | `104857600` (100 MiB) | File/APK upload ceiling. |
| `MAX_EMAIL_BYTES` | `26214400` (25 MiB) | Ceiling for the raw email message body (chars at the schema layer). |
| `STORAGE_ROOT` | `PROJECT_ROOT/var` | Parent for `uploads/`, `quarantine/`, `tmp/`. `.env.example` uses `./data`. |
| `KEEP_FILES_AFTER_SCAN` | `false` | Keep worker temp blobs after the job (forensic value). |
| `QUARANTINE_ENABLED` | `true` | Master switch for the quarantine sink. |
| `QUARANTINE_ENCRYPTION_KEY` | unset | When set, quarantined blobs are encrypted at rest with AES-256-GCM. **Never change the key.** Requires the `cryptography` package; if the key is set but the package is missing the service fails closed. |
| `SCAN_RETENTION_DAYS` | `90` | Scan rows expire after this window (`expires_at`). A scan can expire while its quarantined copy is still held. |
| `QUARANTINE_RETENTION_DAYS` | `14` | Quarantine items expire and are reaped after this window. |

## URL scanning and SSRF protection

| Variable | Default | Meaning |
| --- | --- | --- |
| `URL_FETCH_ENABLED` | `true` | Master switch for the URL fetch stage. |
| `URL_FETCH_TIMEOUT_SECONDS` | `10.0` | Overall fetch timeout (connect 5 s separately). |
| `URL_FETCH_MAX_BYTES` | `2097152` (2 MiB) | Response body cap. |
| `URL_MAX_REDIRECTS` | `10` | Redirect cap (fetch does not follow redirects automatically; each hop is checked). |
| `URL_ALLOWED_PORTS` | `80,443,8080,8443` | Comma-separated (or JSON) allowed TCP ports for fetch targets. |
| `URL_ALLOW_PRIVATE_NETWORKS` | `false` | When `false`, private/loopback/link-local/reserved ranges are blocked (SSRF). |
| `URL_DNS_TIMEOUT_SECONDS` | `5.0` | DNS resolution timeout. |
| `URL_USER_AGENT` | `CyberShield-Scanner/1.0 (+defensive-url-analysis)` | Outbound User-Agent. |

## Threat intelligence

| Variable | Default | Meaning |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | unset | Enables the VirusTotal provider. |
| `VIRUSTOTAL_ENABLED` | `true` | Provider master switch. |
| `URLHAUS_ENABLED` | `true` | Provider master switch. |
| `URLHAUS_ENDPOINT` | `https://urlhaus-api.abuse.ch/v1/url/` | URLhaus endpoint. |
| `URLHAUS_AUTH_KEY` | unset | abuse.ch `Auth-Key`; without it URLhaus is excluded from lookups rather than failing each request. |
| `ABUSEIPDB_API_KEY` | unset | Enables the AbuseIPDB provider. |
| `GOOGLE_SAFEBROWSING_API_KEY` | unset | Enables the Google Safe Browsing provider. |
| `THREAT_INTEL_TIMEOUT_SECONDS` | `8.0` | Per-provider lookup timeout; a slow provider degrades one data point, not the whole scan. |
| `THREAT_INTEL_CACHE_TTL_SECONDS` | `900` | Base cache TTL; negatives are cached shorter (300 s) and unknowns shorter still (120 s). |

A provider must be **configured** (key present / required headers) to run;
providers also only run when scan consent allows third-party lookups.

## External scanners

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLAMAV_ENABLED` | `true` | Master switch for ClamAV. |
| `CLAMAV_HOST` / `CLAMAV_PORT` | `localhost` / `3310` | ClamAV daemon endpoint. |
| `CLAMAV_TIMEOUT_SECONDS` | `60.0` | Command timeout. |
| `CLAMAV_MAX_SCAN_BYTES` | `104857600` (100 MiB) | Ceiling for a single scan. |
| `YARA_ENABLED` | `true` | Master switch for YARA. |
| `YARA_RULES_DIR` | unset | Directory of `.yar`/`.yara` rule files. **When unset** defaults to `detection-engine/yara/rules` under the project root. The `DEFAULT_YARA_RULES_DIR` line in `.env.example` is not read by the application. |
| `OCR_ENABLED` | `false` | Tesseract/OCR pass for images. |
| `OCR_MAX_CHARACTERS` | `20000` | OCR text cap. |

**Scanner availability is allowed to be false.** When ClamAV or YARA is
unavailable, the corresponding check simply does not run: coverage falls, and
the report says so (health `degraded`, `scanner_coverage`, `UNKNOWN` on
incomplete analyses). See
[../project-report/limitations-and-non-guarantees.md](../project-report/limitations-and-non-guarantees.md#3-if-a-scanner-did-not-run-the-report-says-so).

## Logging

| Variable | Default | Meaning |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` | One of `CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET`. |
| `LOG_JSON` | `true` | Structured JSON logs. |
| `LOG_FILE` | unset | Optional file sink path. |

## Production hardening

The `Settings` model validator refuses to boot with insecure production
defaults (`ENVIRONMENT=production`):

- `SECRET_KEY` must be set explicitly.
- `DEBUG` must be `false`.
- `CORS_ALLOW_CREDENTIALS=true` cannot be combined with a wildcard
  (`*`) origin.

The `backend/.env.example` file documents the recommended production set,
including PostgreSQL and a 32-hex `QUARANTINE_ENCRYPTION_KEY`.