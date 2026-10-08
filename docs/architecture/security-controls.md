# Security controls

This page documents every security control implemented in the CyberShield
backend, where it lives in the code, and the situations in which it is
deliberately *not* stronger than it is. Cross-reference:
[configuration.md](configuration.md) for the exact settings,
[../threat-model/README.md](../threat-model/README.md) for what these controls
defend against.

## Authentication surface

Two credential types resolve to the same `AuthPrincipal`
(`app/api/deps.py`):

| Credential | Header | Notes |
| --- | --- | --- |
| Access token | `Authorization: Bearer <JWT>` | Short-lived (30 min), carries `scopes`. |
| API key | `X-API-Key: <key>` | Long-lived (default 90 days), stored as SHA-256 digest, per-key scopes. |

Rules that matter:

- A request with **no** credential reaching a protected route → `401
  auth_required`.
- A request with an **invalid** credential → `401 auth_invalid`, never treated
  as anonymous.
- Rate limiting keys on the **account** (`user:<id>`), not the credential, so
  rotating tokens or keys cannot multiply the budget.
- `X-Forwarded-For` is honoured **only** when `TRUST_PROXY_HEADERS=true`
  (client IP feeds rate limiting and audit logs); it is never trusted on a
  directly exposed host.

## Scopes and roles

- Ordinary accounts carry exactly the four scopes `scan:read`, `scan:write`,
  `quarantine:read`, `quarantine:write`
  (`USER_SCOPES` in `app/api/deps.py`). Tokens carry the scopes of the account
  that logged in; administrators additionally receive `admin:read`, which is a
  marker scope that lets the API recognise admin credentials.
- Administrator-only routes enforce both the `admin:read` scope **and** the
  account's `is_admin` flag through `require_admin` — a hijacked user token
  cannot mint admin privileges by scope alone.
- API keys may be minted with any supported subset of the scopes (default
  `scan:read`). Unknown requested scopes are dropped rather than rejected
  wholesale, so a client asking for a scope that does not exist gets a valid
  key with the scopes that do (`app/security/api_keys.py`).

## Tokens

- **HS256** with a pinned `SECRET_KEY`; only HS256 is accepted (config
  selecting `none` or an asymmetric algorithm is refused).
- Verification enforces an explicit allow-list: the token type (`typ`),
  algorithm, issuer (`cybershield`), audience (`cybershield-api`), and
  required claims `exp`, `iat`, `nbf`, `sub`, `jti`. This blocks
  algorithm-confusion and token-substitution attacks.
- **Typed tokens**: access and refresh tokens carry different `typ` values and
  are not interchangeable — a leaked refresh token cannot be replayed as an
  access token.
- 30 s leeway for clock skew.
- Error messages never distinguish "wrong signature" from "expired", so an
  attacker cannot probe token state.
- **Revocation store**: a process-local, bounded (50k entries) `jti` mapping.
  Logout, `change-password`, and refresh rotation revoke the relevant `jti`.
  This is **best-effort, per-process** state: in a multi-replica deployment a
  token evicted in one process may still be accepted by another until it
  expires. Multi-replica deployments that require immediate cluster-wide
  revocation should back this store with shared state (e.g. Redis) behind the
  same interface.

## Password storage

- **Argon2id** per OWASP 2024 guidance: 19 MiB memory, 2 iterations, 1 lane,
  16-byte salt, 32-byte hash.
- **bcrypt compatibility**: stored hashes prefixed `$2a$/$2b$/$2y$` are
  verifiable at login (when the optional `bcrypt` package is installed — the
  module has no hard bcrypt dependency). Successful logins detect and upgrade
  legacy hashes via `needs_rehash`.
- **Policy** (`PasswordPolicyError` → `422 password_policy_violation`):
  minimum length `password_min_length` (12), maximum 256 (blocks
  memory-exhaustion abuse of the hasher), at least 3 distinct characters, and
  a well-known-breach-list guard.
- **Timing equalisation**: unknown emails burn an Argon2 verify against a
  dummy hash, so login timing does not reveal which emails are registered.
- `verify` returns `False` rather than raising for unknown/malformed hashes —
  a corrupt row cannot become an authentication bypass or an account-enumeration
  oracle.
- **Lockout**: `max_failed_logins` (5) consecutive failures set
  `locked_until` for `lockout_minutes` (15). The counter resets on success.
  The failed-login counter is committed *before* the `401` is raised so the
  dependency session rollback cannot discard it.

## API keys

- Format `cs_<live|test>_<40 hex>` (160 bits of CSPRNG entropy).
- Stored as **SHA-256 digest** + a 6-char display prefix. A DB dump is not a
  credential dump; the plaintext is shown once at creation.
- Verify compares digests in constant time.
- Scopes are stored as a comma string from a validated allow-list; unknown
  requested scopes are dropped, never rejected wholesale.
- Revocation is a flag flip (`is_active=false`, `revoked_at`); authentication
  via the key stops on the next use.

## Rate limiting (`app/security/rate_limit.py`)

- **Sliding-window** algorithm (two weighted fixed buckets) implemented as an
  atomic Lua script in Redis, with a pipelined fallback for clients that lack
  `eval`.
- Backends: Redis when `use_redis_queue=true` and Redis is reachable;
  otherwise an **in-process per-process** window. `LimiterState.degraded`
  reports which mode is active, and the health endpoint surfaces it — a
  degraded limiter is *reported*, never silently implied to be global.
- Keys: `user:<id>` for authenticated callers, `ip:<address>` otherwise.
  An attacker rotating identities under one account still shares the same
  `user:<id>` budget.
- Every rejection is recorded in `rate_limit_events` (identifier, rule, limit,
  window, path) before the `429` is raised.

## SSRF protection

Seven layers defend the outbound URL scanner so it cannot become a proxy into
its own network:

1. **Scheme allowlist** — only `http`/`https` may be dereferenced (`file://`,
   `gopher://`, `dict://`, … are blocked).
2. **Port allowlist** — `url_allowed_ports` (80, 443, 8080, 8443).
3. **Credential stripping** — `user:pass@` is removed before any request, so
   attacker-supplied credentials are never transmitted.
4. **Full-DNS IP filtering** — *every* A/AAAA answer is checked, not just the
   first (defeats DNS answers that return a public IP first and `127.0.0.1`
   second).
5. **IPv6 unwrapping** — IPv4-mapped (`::ffff:127.0.0.1`), NAT64
   (`64:ff9b::`), 6to4 (`2002::/16`), and Teredo addresses are unwrapped and
   re-checked.
6. **Per-hop redirect revalidation** — redirects are followed manually and each
   hop re-validated, so a public host cannot redirect into a metadata endpoint.
7. **Post-connect peer verification** — the socket's actual peer address is
   compared after connect (defeats DNS rebinding).

Blocked ranges include every private/RFC1918/ULA block, loopback, link-local
(`169.254.0.0/16` — includes cloud metadata `169.254.169.254`), multicast,
reserved/test/documentation ranges, and a denylist of metadata hostnames
(`metadata.google.internal`, `instance-data.ec2.internal`, `localhost`, …).
Enabling `URL_ALLOW_PRIVATE_NETWORKS` is refused outright in production.

## Path and filename sanitisation

The governing rule: **a client-supplied string is never used to build a
filesystem path**. Concretely:

- `generate_storage_key` produces a server-generated opaque key
  (`secrets.token_hex(16)`) for stored bytes; the untrusted name is used only
  as a sanitised *display* label.
- `sanitize_filename` allows only `[A-Za-z0-9._ -]`, strips directory
  components for both `\` (Windows) and `/`, normalises NFKD Unicode
  look-alikes, prefixes reserved device names (`CON`, `NUL`, …), truncates on a
  character boundary while keeping the extension (max 120).
- `safe_join` is the containment check re-applied at every storage read/write:
  it resolves the final path and verifies it stays under the root, which also
  defeats symlink escapes planted inside the root. Violations are
  `400 unsafe_path`.
- `escape_for_display` HTML-escapes report text at the point of storage, and
  `defang` turns IOCs into non-clickable form (`hxxp://evil[.]example`) so a
  report cannot become active content or an accidental click.

## Quarantine encryption

- At-rest encryption is **AES-256-GCM** (`CBSQ1` magic envelope, 12-byte nonce,
  AAD bound to `cybershield-quarantine-v1`). The key is derived SHA-256 of the
  configured `QUARANTINE_ENCRYPTION_KEY`.
- **Fail-closed**: if the key is set but the `cryptography` package is
  missing, quarantine refuses to store plaintext. A blob whose stored SHA-256
  no longer matches the record on read is refused — integrity check runs
  before decrypt and before any bytes are returned.
- The client-supplied filename never participates in a path; storage keys are
  server-generated.
- Every read/release/delete/reap is recorded in `quarantine_access_log`.

## Other hardening

- **CORS** is explicit-allowlist (`CORS_ORIGINS`); wildcard plus
  `CORS_ALLOW_CREDENTIALS` is refused in production.
- **Production bootstrap validation** (`app/core/config.py`) refuses to boot
  without an explicit `SECRET_KEY`, with `DEBUG=true`, and with insecure CORS
  combinations.
- **Error discipline** (`app/core/exceptions.py`): internal exception text is
  never placed in client-facing messages; it is logged and correlated by
  `correlation_id`/`X-Request-ID`. Expo runbooks and the threat model
  reference the canonical error codes.
- **Audit logging**: privilege-changing actions (user create/update/
  deactivate, API-key create/revoke, quarantine access, logins) write
  `audit_events`; every quarantine byte read is audited separately.
- **Worker hygiene**: async scan failures mark the scan row `FAILED` with a
  bounded message and are never retried in a loop; temp upload blobs are
  removed after the job unless `keep_files_after_scan`.