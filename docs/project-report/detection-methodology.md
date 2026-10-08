# Detection Methodology

How a scan turns raw input into a report. The pipeline is the same shape at the
top for every scan type — **detectors emit signals, the risk engine scores** —
and the details are documented below in the order they appear in the code.

Architecturally this lives in three layers (`backend/app/services/scan_service.py`,
`backend/app/services/risk_engine.py`, and the detector engines under
`backend/app/detection_engine/`). A compact component map is in
[../architecture/README.md](../architecture/README.md), and a life-size diagram
of the request lifecycle is in [../diagrams/request-lifecycle.md](../diagrams/request-lifecycle.md).

## 1. Input families and their pipelines

Each scan type is a distinct pipeline in `ScanService`, but every one follows
the same contract: **produce `DetectionSignal`s, accumulate `_Coverage`, run
the advisory ML opinion, then call `risk_engine.assess_risk`** once.

| Endpoint group | Pipeline stages (`analyzers_run`) | Notes |
| --- | --- | --- |
| URL (`POST /scan/url`) | `structural` → `fetch` → `intel` | Structural analysis always runs. The fetch is consent-gated (`active_fetch`, `dns_lookup`) and SSRF-defended ([security-controls.md](../architecture/security-controls.md#ssrf-protection)). Reputation lookup runs only when `consent.third_party_lookup` is true. `quick=true` skips fetch and intel. |
| Email (`POST /scan/email`) | `parse` → `headers` → (`body`) → (`urls`) | Never makes any network contact and is never submitted anywhere. `quick` or `analyse_headers_only` stops after headers. |
| Text (`POST /scan/text`) | `heuristics` | Phishing heuristics over free text; extracted URLs/addresses are reported for visibility and never recursively scanned or submitted. |
| File (`POST /scan/file`) | `static` → `clamav` → `yara` → `intel` | Static structural analysis (entropy, embedded URLs/domains, archive/document/PDF introspection). ClamAV runs unless `quick` or `skip_antivirus`; YARA unless `skip_yara`; SHA-256 reputation lookup only with consent. |
| APK (`POST /scan/apk`) | `static` → `clamav` → `yara` → `intel` | Static APK analysis (manifest, permissions, exported components, signature schemes, DEX string scanning when `inspect_dex`), then the same scanner/reputation stages as file uploads. Never installed or run. |
| Quick-write scans (`scan_type=QUICK`) | text only | |

See [../api/scans.md](../api/scans.md) for the request schemas, options, and limits.

## 2. Detector families (the signal catalog)

Detectors are grouped under `backend/app/detection_engine/`. Each function
returns a list of `DetectionSignal`s with stable `code` strings, a `category`,
a `severity`, a `source`, a `confidence`, and `impact`. The category budgets in
the risk engine are keyed by these categories; the full signal catalog is:

- **URL structure** (`url/analyzer.py`, `url/parser.py`) — scheme, hostname,
  port, TLS, punycode/IDN, IP hosts, credential deception
  (`url.credential_deception_ip`), double extensions, executable downloads,
  redirect chain, URL shorteners, DGA-like hosts, government namespaces
  (`url.government_namespace`), suspicious credentials/query keys.
- **Email** (`email/{parser,header_analyzer,analyzer}.py`) — RFC 5322 parse,
  SPF/DKIM/DMARC (`email.dmarc_failure`), header-injection, sender/reply-to
  mismatches, brand impersonation on free domains, attachments (double
  extension, executables, macro-capable types), recipient scatter, single
  received hops, originating-IP data centres.
- **Phishing heuristics** (`phishing/heuristics.py`, `phishing/keywords.py`) —
  urgency/credential/financial/secrecy language, authority impersonation,
  brand impersonation, homograph domains, typosquatting, link-text mismatch,
  character-separated obfuscation, active markup.
- **Files & containers** (`file/analyzer.py`, `file/archive_analyzer.py`,
  `file/document_analyzer.py`, `file/image_analyzer.py`) — entropy & entropy by
  region, MIME/extension mismatch, double extension, trailing dots, empty or
  undersized files; archive members (hidden executables, path traversal,
  compression bombs, encrypted entries, entry floods, nested archives); OLE2
  macros, DDE execution, auto-execute macros, ActiveX, RTF objects, external
  links, corrupt containers; PDFs (JavaScript, embedded payloads, launch
  actions, XFA forms, form submission, encryption); images (zero/abnormal
  dimensions, appended data, GPS/metadata URLs, SVG active content).
- **APK** (`apk/{manifest,dex,signature,analyzer}.py`) — manifest parsing,
  dangerous/exported components (`apk.exported_unprotected`), dangerous
  permissions, cleartext traffic, debuggable builds, allow-backup, missing or
  unreadable manifest, unsigned/old target SDK, native code, DEX SMS/overlay/
  notification abuse, device-admin / accessibility-service misuse.
- **External scanners** (`scanners/clamav.py`, `scanners/yara_scanner.py`) —
  ClamAV daemon verdicts (`av.malware_detected`,
  `av.multiple_detections`) and YARA rule matches (`yara.mass_matches`).
  Availability-aware: if the daemon is down or no rules are loaded, the check
  is *not completed* (see Coverage below) — it is never a clean result.
- **Threat intelligence** (`threat_intelligence/`) — VirusTotal, URLhaus,
  Google Safe Browsing, and AbuseIPDB fan-out on domain/URL/IP/SHA-256
  indicators with per-provider timeout and consensus. Only **positive** results
  become signals; ERROR/UNKNOWN answers never count toward clean.
- **ML opinion** (`ml/`) — an advisory `machine_learning` category signal, see
  the section below.

## 3. The scoring engine (`risk_engine.py`)

`assess_risk` is the **only** component in the codebase that computes a
`score`, `verdict`, `confidence`, `reasons`, or `recommendation`. It does not
trust raw sums; the module docstring spells out why: *twenty trivial
informational observations must not outrank a single authoritative antivirus
detection*. The steps, in code order:

1. **Category budgets.** Signals are grouped by `category`; each category has a
   maximum share of the 0–100 scale. `malware_detection` (62.0) and
   `threat_intelligence` (58.0) are the largest; purely structural observations
   (`lexical` 16.0, `transport` 12.0, `transparency` 8.0) are small.
   `scanner_health` is 0 — it can never raise risk, only inform confidence.
2. **Noisy-OR collapse within a category.** Repeated weak signals inside one
   category saturate (`1 − Π(1 − impact`) rather than accumulating without
   bound, and a gentle logarithmic discount applies by **distinct** signal
   codes, so ten variations of one detector do not outrank three independent
   findings.
3. **Corroboration across categories.** Each additional independent category
   multiplies the base score (`1.0 + 0.55 × (categories − 1)`, capped at 3.2).
   Independent detectors agreeing is treated as the strongest available
   evidence.
4. **Heuristic ceiling.** If no *authoritative* source (antivirus, threat
   intelligence, or YARA) fired, the raw score is capped at **78.0** — pure
   heuristics alone can never reach `HIGH_RISK`, let alone `MALICIOUS`.
5. **Mitigation.** Positive evidence of legitimacy (`legitimacy` category) can
   reduce the score by up to 12 points.
6. **Escalation floors.** Authoritative confirmations lift the score above the
   cap:
   - **Precise detections** (curated, near-zero-FP lists) are decisive on their
     own: `phish.typosquatting` / `phish.homograph_domain` → 68 (variant 78),
     `url.credential_deception_ip` → 72, `document.dde_execution` →
     70, `document.auto_execute_macro` → 70, `archive.hidden_executable` → 66,
     `pdf.javascript` → 62, `url.double_extension` → 48.
   - **Combination floors** escalate when *all* member codes are present, e.g.
     the BEC pattern `phish.secrecy_request` + `phish.financial_request` +
     `phish.urgency_language` → 48.
   - **Source floors**: antivirus CRITICAL → 92, threat intel CRITICAL → 90,
     YARA CRITICAL → 86, antivirus HIGH → 78, threat intel HIGH → 74.
7. **Confidence** is computed separately from score and *never reaches 1.0*:
   it starts at 0.30, gains up to 0.22 for authoritative sources, plus volume
   and family bonuses, is **multiplied by `0.45 + 0.55 × coverage`** (a thin
   pipeline cannot be confident), and loses 0.15 when a score ≥ 40 rests only
   on non-authoritative categories (the agreement penalty). Clamped to
   `[0.05, 0.99]`.
8. **UNKNOWN handling.** If `analysis_incomplete` is true and no authoritative
   source fired, the verdict is forced to `UNKNOWN`, score is raised to a floor
   of 1.0, confidence is capped at 0.3, and the recommendation becomes
   `manual_review`.

### Verdict bands

Half-open intervals on the 0–100 score (`low <= score < next_low`):

`SAFE` 0–19 · `LOW_RISK` 20–39 · `SUSPICIOUS` 40–59 · `HIGH_RISK` 60–79 ·
`MALICIOUS` 80–100. With no signals at all the engine returns `SAFE` (0.55
confidence) when coverage is complete and `UNKNOWN` (0.35 confidence) when it
is not.

### Recommendation mapping

`MALICIOUS` → `block` (URL) / `do_not_install` (APK) / `delete` (file
families) / `verify_sender` (email). `HIGH_RISK` → `block` / `quarantine` /
`do_not_open` (email). `SUSPICIOUS` → `block` / `verify_sender` (email) /
`do_not_download`. `LOW_RISK` → `monitor`. `UNKNOWN` → `manual_review`.
`SAFE` → `none`.

## 4. The advisory ML opinion (`ml/`)

The ML layer answers one constrained question: *given the signals already
extracted, how risky does a statistical model think the object is?* It is
explicitly **not authoritative**:

- It sees only the **feature vector** derived from the signal bundle
  (`ml/features.py`), never raw content.
- It outputs a **probability and label**, never a verdict.
- It degrades: `OpinionService` prefers a lazily-fitted regularised logistic
  regression (`logistic_regression`, fitted on the hand-authored calibration
  corpus in `tests/calibration_set.py` — 17 cases, ~20 features, deterministic
  seed) and falls back to the deterministic `rule_based` logistic baseline
  whenever `sklearn`/`numpy` are missing or the fit fails. A model that cannot
  answer simply does not participate (`ml_opinion.error = "model_unavailable"`).

Disagreement handling in `scan_service._apply_ml` / `_ml_opinion` is
asymmetric on purpose:

- **Model more risky** (`probability ≥ 0.7`, rule verdict `SAFE`/`LOW_RISK`):
  a single `ml.risk_underestimate` signal is added. It is `MEDIUM` severity in
  the `machine_learning` category (budget 14.0) with confidence capped at
  `min(0.8, probability)` — it raises suspicion but cannot, alone, reach a
  risky verdict.
- **Model more optimistic** (`probability < 0.3`, rule verdict risky): recorded
  in metadata as `disagreement: "model_more_optimistic"` for calibration and
  **never** changes the verdict — an evidence-backed verdict is never diluted.

## 5. Coverage and the honesty rules (`_Coverage`)

Every pipeline declares *expected* check units and marks *completed* units.
`scanner_coverage = completed / expected` and `analysis_incomplete = coverage < 0.5`.
The docstring in the class is the ground rule: **availability ≠ cleanliness**,
and a check that could not run is simply not completed.

- URL fetch: a *blocked* or *refused* fetch is still a completed check (the
  scanner answered "no"); only genuine unavailability reduces coverage.
- ClamAV/YARA: a daemon that is down, or a YARA engine with no rules, is an
  uncompleted check — **never** a clean result. `analysis_incomplete` drops
  coverage and, absent an authoritative detection, forces `UNKNOWN`.
- A failed static pass (`scan.static_analysis_failed`, `scanner_health`) marks
  the analysis incomplete even when other checks completed.

The raw numbers are echoed in every report (`scanner_coverage`,
`analysis_incomplete` in `metadata_json`, and the `coverage` field of the
`score_breakdown`).

## 6. What a report contains

The report assembles the score, verdict, confidence, an ordered `reasons[]`
list, the deduplicated `signals[]`, `indicators[]`, the full
`score_breakdown` (per-category contributions, corroboration factor,
escalations, mitigation, coverage, agreement penalty), reputation metadata, and
a standing disclaimer. Verification vocabulary and the exact response shapes
are in [../api/README.md](../api/README.md).

## Cross-references

- [Limitations and non-guarantees](limitations-and-non-guarantees.md)
- [Testing the methodology](testing.md)
- [Threat model of the product itself](../threat-model/README.md)
- [Request lifecycle diagrams](../diagrams/request-lifecycle.md)