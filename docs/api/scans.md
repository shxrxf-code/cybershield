# Scan endpoints

This section covers all ten scan-related routes. They require the following
scopes: submitting scans uses `scan:write`; reading history/reports/dashboard/
signal search uses `scan:read`.

Two important facts up front:

1. **Nothing executed. Ever.** Files and APKs are inspected statically — never
   run, installed, mounted, or instrumented. URL analysis may perform a
   controlled HTTP fetch *only if* you consent (`consent.active_fetch`) and the
   target passes SSRF defense checks.
2. **Outbound reputation lookups are consent-gated.** Any scan that consults
   third-party threat-intelligence providers does so only when
   `consent.third_party_lookup` is `true` (default true for authenticated
   users, but the client can switch it off per request). DNS resolution is
   similarly gated by `consent.dns_lookup`.

## Shared request surface

All JSON scan bodies extend a common base with `extra="forbid"`:

```json
{
  "consent": {
    "third_party_lookup": true,
    "dns_lookup": true,
    "active_fetch": true
  },
  "quick": false,
  "client_label": "android-tablet"
}
```

- `quick` — skip the slowest checks (in practice a fast pass).
- `client_label` — free-form tag (max 64) recorded in scan metadata.
- Invalid/unknown fields are rejected (`422 validation_error`), not ignored.

## Asynchronous mode

Every submission endpoint accepts `?async=true` and then returns `202` instead
of a report:

```json
{
  "scan_id": "…",
  "status": "QUEUED",
  "object_type": "url",
  "poll_url": "/api/v1/scans/<scan_id>"
}
```

Poll `GET /api/v1/scans/{scan_id}` until `status` is `COMPLETED` (report
fields populated) or `FAILED` (`error_message` populated). Async file uploads
are stored under an opaque key and removed when the worker has consumed them
unless `keep_files_after_scan` is on.

Rate limiting: URL/email/text submissions use the **`scan`** bucket
(30/min); file and APK submissions use **`file_scan`** (10/min).

---

## `POST /scan/url`

Scan a URL **without opening it in a browser**: structural analysis of the
link plus a controlled, consent-gated fetch.

Body:

```json
{
  "url": "https://example.com/…",
  "resolve_dns": true,
  "consent": { "third_party_lookup": true, "dns_lookup": true, "active_fetch": true },
  "quick": false,
  "client_label": null
}
```

- `url` — at most 2048 chars. Must contain a scheme (`://`) or a dotted host
  (or the literal `localhost`); otherwise `422 validation_error`. A malformed
  or suspicious scheme is the detector's job to report, not validation's to
  reject.
- `resolve_dns` — if true, the hostname is resolved (when consent permits) and
  the resolved addresses are reported.

`200` — `UrlScanResponse` (core report fields plus):

```json
{
  "url": "https://example.com/…",
  "normalised_url": "https://example.com/…",
  "host": "example.com",
  "resolved_ips": ["93.184.215.14"],
  "fetch_blocked_reason": null,
  "page_title": null,
  "http_status": 200,
  "reputation": { "…": "per-provider results when lookups ran" },
  "score": 71.25,
  "verdict": "HIGH_RISK",
  "confidence": 0.72,
  "recommendation": "block",
  "recommendation_text": "…",
  "signals": [],
  "reasons": [],
  "indicators": [],
  "score_breakdown": { "…": "category budgets" },
  "duration_ms": 4210,
  "disclaimer": "…",
  "created_at": "…"
}
```

Notable outcomes:

- `400 ssrf_blocked` — the URL resolved to a destination blocked by the SSRF
  defense (private/loopback/link-local ranges, disallowed ports, etc.). See
  [architecture/security-controls.md](../architecture/security-controls.md#ssrf-protection).
- `fetch_blocked_reason` is set (and the fetch skipped) when an outbound fetch
  was refused but the scan is still able to complete on the available
  evidence.

## `POST /scan/email`

Analyse a raw **RFC 5322** message. Nothing is sent; the message is only
parsed and scored.

Body:

```json
{
  "raw_message": "From: …\nTo: …\nSubject: …\n\nBody…",
  "subject": "Invoice",
  "sender": "attacker@evil.example",
  "analyse_headers_only": false,
  "quick": false,
  "client_label": null
}
```

- `raw_message` — 1–2,000,000 chars (25 MiB ceiling enforced at the body
  layer).
- `subject` — at most 998 chars (the RFC 5322 header-line limit).
- `analyse_headers_only` — only parse and analyse headers (SPF/DKIM/DMARC,
  Received chain); nothing is submitted to reputation services.
- `quick: true` is handled as headers-only in practice.

`200` — `EmailScanResponse` (core report fields plus):

```json
{
  "subject": "Invoice",
  "sender": "attacker@evil.example",
  "sender_domain": "evil.example",
  "reply_to": null,
  "return_path": null,
  "authentication": { "spf": "…", "dkim": "…", "dmarc": "…" },
  "headers_of_interest": { "received_chain": "…", "originating_ip": "…" },
  "attachment_count": 0,
  "score": 0,
  "verdict": "SAFE",
  "confidence": 0.9,
  "recommendation": "none",
  "recommendation_text": "…",
  "signals": [],
  "reasons": [],
  "indicators": [],
  "score_breakdown": null,
  "duration_ms": 120,
  "disclaimer": "…",
  "created_at": "…"
}
```

Email header authentication results (SPF/DKIM/DMARC evaluation) live in
`authentication`, and the Received chain primarily in `headers_of_interest`.

## `POST /scan/text`

Scan free text (an email body, a message, pasted content) with the phishing
heuristics. **Fully local** — nothing leaves the process.

Body:

```json
{ "text": "Click here to win…", "consent": {…}, "quick": false, "client_label": null }
```

- `text` — 1–100,000 chars, must not be blank.

`200` — `TextScanResponse` (core report fields plus):

```json
{
  "character_count": 42,
  "extracted_urls": ["https://evil.example/…"],
  "extracted_emails": [],
  "score": 88,
  "verdict": "MALICIOUS",
  "confidence": 0.81,
  "recommendation": "do_not_open",
  "recommendation_text": "…",
  "signals": [],
  "reasons": [],
  "indicators": [],
  "score_breakdown": null,
  "duration_ms": 8,
  "disclaimer": "…",
  "created_at": "…"
}
```

## `POST /scan/file` (multipart)

Analyse a file's bytes statically. **Never executed or mounted.**

`multipart/form-data` with:

- `file` — the file part (up to `max_upload_bytes`, default **100 MiB**).
- `options` — a JSON **string** (Form field) of `FileScanOptions`:

```json
{
  "quarantine": true,
  "skip_antivirus": false,
  "skip_yara": false,
  "inspect_archives": true,
  "extract_text": true,
  "consent": { "third_party_lookup": true, "dns_lookup": true, "active_fetch": true },
  "quick": false,
  "client_label": null
}
```

- `quarantine` — keep a copy of the file in quarantine after analysis.
- `skip_antivirus` / `skip_yara` — exclude ClamAV / YARA from the run.
- `inspect_archives` — walk nested archives (bounded by depth/expansion limits).
- `extract_text` — pull text from documents for phishing analysis.

`200` — `FileScanResponse`. The filename is **sanitised** on ingest (see
[architecture/security-controls.md](../architecture/security-controls.md#path-and-filename-sanitisation)).
The file's type is detected from **content**, not the filename, and reported
in `detected_type`.

```json
{
  "scan_id": "…",
  "scan_type": "file",
  "object_type": "file",
  "status": "COMPLETED",
  "filename": "invoice.pdf",
  "size_bytes": 48127,
  "detected_type": "pdf",
  "sha256": "…", "sha1": "…", "md5": "…", "entropy": 7.9,
  "score": 23.5,
  "verdict": "LOW_RISK",
  "confidence": 0.55,
  "recommendation": "monitor",
  "recommendation_text": "…",
  "signals": [], "reasons": [], "indicators": [],
  "score_breakdown": null,
  "quarantined": true,
  "duration_ms": 900,
  "disclaimer": "…",
  "created_at": "…"
}
```

Errors specific to uploads:

- `413 payload_too_large` — over 100 MiB (or the file body is empty).
- `415 unsupported_type` — the detected content type is not analysable.
- `400 unsafe_path` / `ssrf_blocked` family — sanitisation refuses a poisoned
  filename / extraction target.

## `POST /scan/apk` (multipart)

Analyse an Android APK **statically**. Never installed, run, or instrumented.

Identical multipart structure to `/scan/file`, with `ApkScanOptions`
extending `FileScanOptions`:

```json
{
  "quarantine": true,
  "skip_antivirus": false,
  "skip_yara": false,
  "inspect_archives": true,
  "extract_text": true,
  "inspect_dex": true,
  "inspect_manifest": true,
  "verify_signature": true,
  "consent": {…},
  "quick": false,
  "client_label": null
}
```

`200` — `ApkScanResponse` (extends `FileScanResponse`):

```json
{
  "…": "all FileScanResponse fields",
  "scan_type": "apk",
  "object_type": "apk",
  "package_name": "com.example.app",
  "version_name": "1.2.3",
  "version_code": "123",
  "min_sdk": 24,
  "target_sdk": 33,
  "permissions_requested": ["android.permission.INTERNET"],
  "dangerous_permissions": ["android.permission.SEND_SMS"],
  "declared_components": { "activities": [], "services": [], "receivers": [], "providers": [] },
  "signature": { "verified": true, "certificate_sha256": "…", "signing_scheme": "v2" },
  "dynamically_analysed": false
}
```

`dynamically_analysed` is **always `false`**, stated explicitly so the client
cannot imply otherwise.

---

## `GET /scans`

The caller's scan history with filters and paging. Requires `scan:read`.
Admins are shown only their own scans here (self-service view).

Query parameters (`ScanFilterParams`):

| Param | Type | Meaning |
| --- | --- | --- |
| `scan_type` | `url\|email\|file\|apk\|quick` | Filter by entry point |
| `verdict` | `SAFE\|LOW_RISK\|SUSPICIOUS\|HIGH_RISK\|MALICIOUS\|UNKNOWN` | Filter by verdict |
| `min_score` / `max_score` | 0–100 | Score range |
| `search` | string ≤ 200 | Match against target URL/host/email/filename/label |
| `since` / `until` | ISO datetime | Creation window |
| `page` | ≥ 1 (default 1) | Page number |
| `page_size` | 1–100 (default 20) | Page size |

`200` — `PaginatedResponse`:

```json
{
  "items": [
    {
      "scan_id": "…",
      "scan_type": "url",
      "object_type": "url",
      "status": "COMPLETED",
      "target": "example.com",
      "score": 71.25,
      "verdict": "HIGH_RISK",
      "created_at": "…"
    }
  ],
  "total": 7,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

## `GET /scans/{scan_id}`

The full persisted report for one scan. Requires `scan:read`. Scanner owner
visibility applies: a non-admin requesting someone else's scan — or any
unknown id — gets `404 not_found` (not `403`).

`200` — `ScanDetail` (the generic envelope; type-specific responses carry the
same core fields):

```json
{
  "scan_id": "…", "scan_type": "url", "object_type": "url", "status": "COMPLETED",
  "target": "example.com",
  "score": 71.25, "verdict": "HIGH_RISK", "confidence": 0.72,
  "recommendation": "block", "reasons": ["…"],
  "signals": [], "score_breakdown": { "…": "…" },
  "metadata_json": { "scanner_coverage": "…", "analysis_incomplete": false, "reputation": {…} },
  "target_url": "https://example.com/…", "target_host": "example.com",
  "target_email": null, "email_subject": null,
  "original_filename": null, "storage_key": null, "sha256": null, "size_bytes": null,
  "is_quarantined": false,
  "duration_ms": 4210,
  "analyzers_run": "av,yara,heuristics,ml",
  "error_message": null,
  "created_at": "…", "expires_at": "…"
}
```

`metadata_json` carries scan-type-specific detail and the honestly-reported
coverage bookkeeping (`scanner_coverage`, `analysis_incomplete`). Scan rows are
retained `scan_retention_days` (90) with `expires_at`, even when a quarantined
copy is still held (the indicator may be cleaned while the sample remains).

## `POST /scans/{scan_id}/feedback`

Record one verdict label on a finished scan (one per scan, ever). Requires
`scan:write` and ownership of the scan.

Body (`SubmitFeedbackRequest`):

```json
{
  "label": "true_positive",   // true_positive | false_positive | false_negative | unsure
  "comment": "optional free text ≤ 1000 chars"
}
```

- `204 No Content` on success.
- `404 not_found` for unknown/non-owned scans.
- `409 conflict` if feedback was already submitted (duplicate feedback —
  including a raced duplicate that hits the unique index).

## `GET /dashboard`

Aggregate counters and trends for the **caller's own** scans. Requires
`scan:read`.

`200` — `DashboardStats`:

```json
{
  "total_scans": 42,
  "safe_count": 10, "low_risk_count": 8, "suspicious_count": 12,
  "high_risk_count": 9, "malicious_count": 3, "unknown_count": 0,
  "average_score": 34.21,
  "average_confidence": 0.74,
  "quarantined_files": 2,
  "timeline": [
    { "date": "2026-09-07T00:00:00Z", "total": 3, "safe": 2, "suspicious": 1, "malicious": 0 }
  ],
  "top_threat_types": [ { "category": "url_obfuscation", "count": 11 } ],
  "detector_agreement": { "compared": 0, "rule_only": 0 },
  "generated_at": "…"
}
```

- `timeline` — 30 daily buckets (empty days included), starting 29 days back.
- `top_threat_types` — up to five signal categories across the 200 most recent
  scans, ordered by descending count.
- `detector_agreement` — the current implementation does **not** compare ML
  against rule detectors yet, so it is hardcoded to
  `{"compared": 0, "rule_only": 0}`. It is present in the schema and always
  reports "nothing compared", truthfully.

## `GET /signals/search`

Search findings across the **caller's own** scans by signal code/category/title
substring. Requires `scan:read`.

Query parameters:

| Param | Type | Meaning |
| --- | --- | --- |
| `q` | string, 2–200 chars | Case-insensitive substring matched against signal code + title + category |
| `limit` | 1–100 (default 20) | Max hits returned |

`200` — `PaginatedResponse` of signal hits:

```json
{
  "items": [
    {
      "scan_id": "…",
      "code": "url.obfuscation.homoglyph",
      "title": "Homoglyph domain …",
      "description": "…",
      "severity": "HIGH",
      "source": "heuristic",
      "category": "url_obfuscation",
      "confidence": 0.9,
      "created_at": "…"
    }
  ],
  "total": 1, "page": 1, "page_size": 20, "pages": 1
}
```

The search scans up to the 500 most recent scans of the caller; `total` equals
the number of hits actually returned (capped at `limit`).