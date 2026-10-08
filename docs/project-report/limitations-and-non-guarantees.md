# Limitations and Non-Guarantees

This page collects everything CyberShield **does not** do and every place where
the honest answer is "we cannot be sure". It exists so operators, reviewers,
and the client UI make decisions from the same caveats the code encodes. If a
claim is not here or in [detection-methodology.md](detection-methodology.md),
treat it as unsupported.

## 1. Static analysis only — nothing is ever executed

- Files, archives, documents, images, and APKs are **parsed and inspected
  structurally only**. The APK pipeline reads the manifest, permissions, DEX
  strings, and signature blocks; it never installs, runs, or instruments
  anything. `dynamically_analysed` is always `false` in APK reports.
- PDFs with JavaScript, OLE2 documents with VBA/DDE, and archives containing
  hidden executables are **detected**, not detonated.
- Every report carries a disclaimer that no runtime behaviour was observed and
  that the assessment is evidence-based, not a guarantee.

## 2. "No detection" is not "safe"

- A `SAFE` verdict means: *no detector available to this pipeline produced a
  finding*. It cannot rule out detections outside the pipeline's reach
  (unknown malware families, YARA rules not loaded, a reputation provider that
  has never seen the hash).
- The code is explicit about this in two places: the empty-signals reason text
  ("This does not guarantee the object is safe") and the `UNKNOWN` forcing
  rule (an incomplete analysis is never downgraded to `SAFE`).
- The ML model — even when available — is fitted on a small hand-authored
  calibration corpus (17 cases). Its opinion is advisory and never
  authoritative. Do not generalise from it.

## 3. If a scanner did not run, the report says so

The rule is "availability ≠ cleanliness" — a check that could not run is
simply **not completed**, and never recorded as a clean result:

- **ClamAV unavailable** (daemon down, connection refused) → the check is
  uncompleted; `scanner_coverage` drops; `metadata.scanners.clamav.available`
  is `false` with an `error` string. **No ClamAV detection is reported.**
- **YARA rules missing / engine unavailable** → the same, under
  `metadata.scanners.yara`. The relevant environment variable is
  `YARA_RULES_DIR` (the `.env.example` key `DEFAULT_YARA_RULES_DIR` is legacy
  and ignored) — [../architecture/configuration.md](../architecture/configuration.md).
- When `coverage < 0.5` and no authoritative source fired, the reply is
  `UNKNOWN` with `manual_review`, not a downgraded "safe".
- Quick scans (`quick=true`) intentionally skip fetch, reputation, and ClamAV;
  metadata records `quick: true` and the skipped checks are not counted as
  completed.

## 4. Third-party reputation lookups only with consent

- `consent.third_party_lookup` gates every outbound reputation query
  (VirusTotal, URLhaus, Google Safe Browsing, AbuseIPDB). `consent.dns_lookup`
  and `consent.active_fetch` gate the URL fetch's DNS and HTTP contact.
- A declined lookup returns an explicit "not asked" state in metadata
  (`reputation.providers_queried: 0`); it is **not** reported as "clean".
- The *email* and *text* pipelines never contact the network at all — extracted
  URLs and addresses are reported for visibility and nothing is submitted back.

## 5. Quarantine is best-effort evidence storage, not a security sandbox

- Quarantined blobs are stored (optionally AES-256-GCM-encrypted under a
  `CBSQ1` envelope with integrity hash), expire after 14 days, and are never
  executed — but quarantine is a *holding area*, not malware containment.
- Quarantine fails **closed** when encryption is required but the crypto
  dependencies are missing: reads and releases are refused rather than served
  in plaintext. If the store cannot initialise, scans still complete, with the
  quarantine gap recorded in metadata.
- Files are encrypted only when `QUARANTINE_ENABLED` and a
  `QUARANTINE_ENCRYPTION_KEY` are configured; with neither set, blobs are
  stored plaintext under opaque keys inside the (private) storage root.

## 6. Best-effort, in-process state (single process only)

- **Token revocation** is an in-process jti allow-list/deny-list (up to 50k
  entries). Logout, refresh rotation, and password change only take effect on
  the process that performed them; a multi-replica deployment needs shared
  state for immediate cross-node revocation, and key changes after restart
  invalidate old tokens.
- **The scan queue** is an in-process asyncio `ScanQueue`; jobs queued at
  shutdown are lost (re-submittable by design), and a failed job marks its scan
  row `FAILED` with a bounded error message rather than retrying forever.
- **Rate limiting** uses a sliding-window Lua approach when Redis is configured
  (`USE_REDIS_QUEUE=true`); otherwise it falls back to a per-process window,
  and the health endpoint truthfully reports `rate_limiter.degraded: true`.
  In fallback mode limits are per process, not global.
- The threat-intel **cache** is in-memory with TTLs (900 s providers, 300 s
  consensus, 120 s blocks) and is cold after restart; `/intel/search` is
  cache-only and never performs a live lookup on demand.

## 7. No 100% certainty, ever

- `confidence` is capped at **0.99** and is degraded by coverage and by
  authoritative/heuristic disagreement. The score and verdict are a risk
  assessment, not a ground-truth verdict.
- Error codes `auth_expired`, `scan_timeout`, and `scanner_error` exist in the
  canonical vocabulary but are reserved: the current code emits
  `auth_invalid` (expired tokens), `scan_failed` (timeouts), and
  `service_unavailable`/coverage degradation instead. Clients should still
  recognise the disabled constants — future versions may emit them.
  See the [error table in the API reference](../api/README.md#error-codes).

## 8. Retention and other operational facts

- Scans expire after **90 days** (`scan_retention_days`), quarantined items
  after **14 days** (`quarantine_retention_days`). Expired rows are reaped by
  housekeeping, not returned.
- The dashboard's `detector_agreement` is hardcoded to
  `{"compared": 0, "rule_only": 0}` — detector-agreement telemetry is **not
  yet implemented**, so those numbers are informational placeholders, not a
  measurement.
- Uploads are capped (URL 2048 chars, email 2,000,000 raw chars, text 100k
  chars, file/APK uploads 100 MiB); a `413 payload_too_large` is returned
  before any analysis starts. File uploads are stored outside the database
  under opaque keys.

## 9. Flutter client behaviour this API is contractually tied to

The error envelope is exactly `{"error": {code, message, status_code,
correlation_id, details?}}` — **there is no top-level `detail` key**. The
client parses `error.*`; adding or renaming top-level keys would break it.
This is contractual, not incidental — see [api/README.md](../api/README.md#errors).

## Cross-references

- [Detection methodology](detection-methodology.md)
- [Threat model: residual risks are the product of these limits](../threat-model/README.md)
- [Testing: what the suite pins down](testing.md)