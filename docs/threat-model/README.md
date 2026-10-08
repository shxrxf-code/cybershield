# Threat Model

A STRIDE-style analysis of the CyberShield backend. The goal of this document
is not to list every CVE-shaped possibility, but to name the adversary goals
that matter to *this* product, the trust boundaries an attacker must cross, and
the controls — and honest residual risks — that sit at each boundary.

Style note: this document is written in the same evidenced voice as the rest of
the documentation. Claims about controls resolve to
[architecture/security-controls.md](../architecture/security-controls.md);
claims about what *cannot* be guaranteed resolve to
[project-report/limitations-and-non-guarantees.md](../project-report/limitations-and-non-guarantees.md).

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| User credentials (passwords) | `users.password_hash` (Argon2id) | Reuse across the product's real workload makes these a credential-stuffing target. |
| Access & refresh JWTs | client-held; `jti` tracking in-process | Session impersonation. |
| API keys | SHA-256 digests in `api_keys`; plaintext shown once | Long-lived machine access; a leaked key is a standing backdoor until revoked. |
| Scan reports & signals | `scans` rows, `signals` JSON | The product's entire value is trust in these reports; poisoning them corrupts decision-making downstream. |
| Scanner health + metadata | `scan.metadata_json` | Used by clients to decide how much to trust a report. |
| Quarantined samples | `storage_root/quarantine/`, `quarantine_items` | Stored sample integrity = legal/evidence integrity; a corrupted or exfiltrated sample is both a confidentiality and integrity failure. |
| Threat-intel cache | in-memory, TTL'd | A poisoned cache spreads bad reputation data until it expires. |
| Audit log | `audit_events` | The only tamper-evidence trail; must stay append-only in practice. |
| Storage root & uploads | `storage_root/` | Path traversal here is the road to arbitrary read/write. |
| `SECRET_KEY` / `QUARANTINE_ENCRYPTION_KEY` | process env / config | Key compromise defeats token and quarantine confidentiality. |

## Trust boundaries

```
┌───────────────────────────────────────────────────────────────────────────┐
│  Untrusted: internet clients                                              │
│   (Flutter app, attacker scripts, scanners, CI jobs)                      │
└──────────────────────┬────────────────────────────────────────────────────┘
                       │ HTTPS / bearer JWT / X-API-Key
                       ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  Trusted edge: the API process               │  boundary ① credential/   │
│   (FastAPI, middleware, routes, services)    │  payload entry             │
└──────┬──────────┬───────────┬────────────┬───┴────────────────────────────┘
       │          │           │            │
       ▼          ▼           ▼            ▼
  DB (SQLite/  storage/    intel outbound    external scanners
  Postgres)    uploads,     (boundary ③       ClamAV daemon,
               quarantine   consent-gated     YARA engine
  boundary ②   (boundary ④  + SSRF-shielded)  boundary ⑤
  data at rest  filesystem)
```

- **Boundary ① — credential & payload entry.** Everything untrusted first
  crosses here: auth headers, API keys, uploads, URLs, email text. Controls:
  auth dependency stack, scopes, rate limiting, validation limits.
- **Boundary ② — data at rest.** Account data, reports, API-key digests,
  audit rows. Controls: parameterised ORM, sanitised filenames, AES-256-GCM for
  quarantine, least-privilege storage paths.
- **Boundary ③ — outbound contact.** The URL fetcher's DNS + HTTP, the four
  reputation providers, and the ClamAV socket. Controls: 7-layer SSRF shield,
  consent gates, per-provider timeouts, TLS for provider calls.
- **Boundary ④ — the filesystem.** Upload staging and quarantine blobs.
  Controls: server-generated opaque keys, `safe_join` containment re-check on
  every read/write, integrity hash before read.
- **Boundary ⑤ — external scanners.** ClamAV/YARA receive untrusted bytes.
  Controls: subprocess isolation *in those tools* (out of scope here), plus the
  availability-aware "never fabricate a clean result" contract on this side.

## STRIDE mapping

| STRIDE | Where it applies in this product | Primary defence |
| --- | --- | --- |
| **Spoofing** | Bearer token forgery; API key forgery; account impersonation; admin impersonation | Typed HS256 JWT with claim allow-list; 160-bit random API keys stored as digests; `admin:read` marker scope + `require_admin` |
| **Tampering** | Report/signal poisoning; quarantine sample modification; metadata rewriting; path traversal; symlink escape | Signals only produced by detectors; integrity hash on quarantine read; `unsafe_path`/`safe_join` containment; read-only-to-client storage keys |
| **Repudiation** | Attacker deletes traces of their access | `audit_events` on auth, key, user, and quarantine actions; rate-limit events recorded before `429` |
| **Information disclosure** | SQL/logic error leakage; `detail`-shaped leaks; quarantine byte exfiltration; account enumeration via timing | Unified error envelope with `correlation_id`; logging redaction; AES-GCM quarantine; Argon2 dummy-hash timing equalisation; owner mismatches collapsed to 404 |
| **Denial of service** | Scan flood; upload exhaustion; login enumeration; cache poisoning at scale; queue jam | Per-bucket sliding-window rate limiting on account/IP; upload caps (100 MiB) + body limits; expired-token/`lockout`; bounded intel cache TTLs; worker marks `FAILED`, never hammers providers |
| **Elevation of privilege** | Path traversal → storage read/write; `admin:read` scope abuse; algorithm-confusion on JWT | Allow-list verification of algorithm/typ/issuer/aud; `safe_join` on every storage op; admin routes require both `admin:read` and an actual admin account |

## Adversarial goals and mitigations

### Goal 1 — Credential stuffing (login abuse)

Tries to log in with breached passwords at volume, or to distinguish registered
emails from unregistered ones.

- **Mitigations.** `auth` rate bucket (10/min, account *and* IP); Argon2id;
  dummy-verify on unknown emails so timing does not reveal registration;
  lockout at `max_failed_logins` (5) for `lockout_minutes` (15); every failure
  writes `audit_events` with source IP; audit keeps attack shape visible when
  identity rotation hides the actor.
- **Residual.** Lockout itself is a DoS lever — an attacker who knows an email
  can lock the real owner out for 15 minutes. Logins remain possible forever at
  human speed; rate limits are the only bulwark, and in the in-process fallback
  mode they are per process.

### Goal 2 — API-key theft and abuse

Steals a `cs_live_*` key (client device compromise, log leak, DB dump) and
scans—or worse, mints more keys—under that identity.

- **Mitigations.** Keys are never stored in plaintext (SHA-256 digest + 6-char
  prefix only); plaintext is shown once at creation; scopes come from an
  allow-list so a hijacked `scan:read` key cannot submit scans; revocation is a
  flag flip that takes effect on next use; account-based rate limiting means
  rotating keys cannot multiply the budget.
- **Residual.** A DB dump still leaks the *prefix + digest* mapping that lets an
  attacker recognise keys afterwards; revoked keys are only as good as the
  revocation flag (single store); and any long-lived credential rides the
  "best-effort per-process state" caveat in a multi-replica deployment.

### Goal 3 — Scan-result poisoning

Gets the system to emit `SAFE`/`LOW_RISK` for something malicious (or the
reverse), to steer a downstream decision (allow / block / release).

- **Mitigations.** Signals are produced only by the detector engines plus
  external verdicts; the scorer has documented category budgets, escalation
  floors, precise-detection floors, and a heuristic ceiling of 78 — heuristics
  alone cannot reach `HIGH_RISK`. `UNKNOWN` is forced when coverage < 0.5
  without an authoritative hit, so *downgrading to safe* is structurally
  blocked rather than merely discouraged. YARA/ClamAV/intel availability is
  reported, not hidden.
- **Residual.** Poisoning the *sources* (compromising a reputation provider,
  swapping YARA rules on disk, feeding the ML calibration corpus) is out of the
  product's write-protection; the model is advisory and fitted on a small
  corpus; and a crafted object can always sit in detector blind spots (static
  analysis cannot see packed/encrypted-at-rest payloads that a sandbox would).

### Goal 4 — SSRF via URL scans

Submits a URL that makes the scanner fetch internal infrastructure:
`169.254.169.254` cloud metadata, databases, admin consoles.

- **Mitigations.** Seven defence-in-depth layers
  ([security-controls.md](../architecture/security-controls.md#ssrf-protection)):
  scheme allowlist; port allowlist; credential stripping; *every* A/AAAA answer
  checked; IPv6-mapped/NAT64/6to4/Teredo unwrapping; per-hop redirect
  revalidation; post-connect peer verification against DNS rebinding. Blocked
  ranges cover RFC1918, loopback, link-local (incl. metadata), reserved and
  test/documentation nets; metadata hostnames are denylisted by name;
  `URL_ALLOW_PRIVATE_NETWORKS` is refused in production.
- **Residual.** SSRF defence is as strong as the resolver and networking stack:
  exotic IPv6 encodings or split-horizon DNS inside the deployment could
  theoretically route elsewhere; the allow-private flag exists for legitimate
  internal use-cases and is a deliberate, production-refused escape hatch.

### Goal 5 — Upload abuse / storage exhaustion

Floods uploads to exhaust disk or the queue, or submits archives/paths that
escape the storage root.

- **Mitigations.** Upload caps (files/APKs 100 MiB, email raw 2 MB, text
  100 KB, URL 2048 chars) before any analysis; `file_scan` rate bucket
  (10/min); async uploads parked under opaque server-generated keys; filename
  sanitisation + `unsafe_path`/`safe_join` containment on every storage op
  (resolved-path re-check, symlink-safe); quarantine reads fail closed; temp
  blobs removed after the worker runs.
- **Residual.** Disk quotas are the operator's job — the caps bound per-request
  size, not total growth; retention reaping (90 d scans, 14 d quarantine) is
  housekeeping, not a quota. Decompression-bomb *detection* exists, but a
  huge-but-legal archive still consumes the per-request budget.

### Goal 6 — Data exfiltration

Reads scan reports, quarantined samples, or audit data of other tenants (or of
no tenant at all: the sample store).

- **Mitigations.** Ownership is enforced on every scan/read route (owner
  mismatches collapse to `404` — indistinguishable from non-existence); API
  keys carry scoped permissions; `quarantine:read` is separate from
  `quarantine:write`; quarantine blobs are encrypted at rest with integrity
  checked before decryption; every byte read is audited in
  `quarantine_access_log`; error responses never leak internal details (only
  `correlation_id` references server-side logs).
- **Residual.** Sample *hashes* and metadata are intentionally visible to
  authorised users (that is the product); encrypted blobs are decryptable by
  anyone holding `QUARANTINE_ENCRYPTION_KEY`; the audit log is a database table
  — a fully compromised DB can rewrite it. Cross-tenant isolation rests on the
  single-service ownership checks, so any future multi-tenant change must
  re-audit those routes.

## Residual-risk register (sorted by operational weight)

1. **Multi-replica state is best-effort.** Token revocation, queue jobs, and
   the rate-limit fallback are per-process. Not a bug, but a hard boundary —
   documented in [limitations-and-non-guarantees.md](../project-report/limitations-and-non-guarantees.md).
2. **Static-only blind spots.** Packed, encrypted, or runtime-revealed payloads
   are invisible to a static pass; `SAFE` is bounded by "every detector that
   ran produced nothing".
3. **Trust in the analytical tail.** Compromise of a reputation provider, YARA
   rule set, calibration corpus, or `SECRET_KEY`/`QUARANTINE_ENCRYPTION_KEY`
   defeats the respective control silently. Keys should live in a secrets
   manager and rule sets should be reproducibility-pinned.
4. **Search/lookup abuse.** `/intel/search` is cache-only, but an attacker with
   `scan:read` can still mass-probe indicators and learn which are in cache —
   a bounded information oracle, throttled by the same limits.
5. **Lockout-as-DoS** on known emails (Goal 1 residual).

## Cross-references

- The controls named here, in code: [architecture/security-controls.md](../architecture/security-controls.md)
- Where the guarantees end: [project-report/limitations-and-non-guarantees.md](../project-report/limitations-and-non-guarantees.md)
- Tokens, scopes, error codes: [api/README.md](../api/README.md)
- Diagrams of the flows being protected: [diagrams/](../diagrams/README.md)