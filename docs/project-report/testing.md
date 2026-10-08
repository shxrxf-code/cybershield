# Testing

The backend ships a pytest suite that exercises the API end-to-end (live ASGI
app with lifespan), the static analyzers against **synthetic** fixtures, and
the scoring engine against a documented calibration set. Nothing in the suite
touches the network.

## Running the suite

```bash
cd /home/sharaf/Projects/cybershield/backend
../.venv/bin/python -W ignore -m pytest
```

- `-W ignore` suppresses the deprecation/drizzle from optional third-party
  imports so the result is readable; `pytest.ini` additionally ignores
  `DeprecationWarning` and `UserWarning`, sets `asyncio_mode = auto`, restricts
  collection to `tests/`, and defaults to `-q`.
- The suite is **87 tests across 11 files** (as collected):

| File | Tests | Covers |
| --- | --- | --- |
| `tests/test_auth_api.py` | 11 | Login, refresh rotation + replay, logout, change-password, password policy, lockout, token response shape |
| `tests/test_users_api.py` | 11 | Registration, profile, settings, admin user management, audit trails |
| `tests/test_api_keys_api.py` | 6 | Key minting, scoping (unknown scopes dropped), default TTL, revocation |
| `tests/test_scan_api.py` | 14 | Every `/scan/*` endpoint end-to-end, report shape, score bounds, history, dashboard, signal search |
| `tests/test_apk.py` | 24 | Static APK analysis: synthetic manifest/DEX/signature/zip fixtures |
| `tests/test_async_scan.py` | 3 | Async submission → `202` → worker → poll to terminal state |
| `tests/test_quarantine_api.py` | 6 | Quarantine list/read/release/delete/access-log over HTTP |
| `tests/test_ml_disagreement.py` | 4 | Over-/under-estimate disagreement rules of the advisory ML layer |
| `tests/test_rate_limit_api.py` | 3 | Sliding-window limiting and `429` envelope + headers |
| `tests/test_intel_api.py` | 3 | `/intel/search` cache-only contract and consensus |
| `tests/test_health_api.py` | 2 | `/health` shape and degraded-mode reporting |

## What the harness pins down (`tests/conftest.py`)

`conftest.py` runs **at import time**, before any application module imports,
because `app.core.config.get_settings()` constructs a `Settings` singleton from
the process environment:

- `ENVIRONMENT=test`; the database is a fresh session-scoped SQLite file in a
  `tempfile.mkdtemp`, and `STORAGE_ROOT` points inside it.
- A fixed `SECRET_KEY`, `JWT_ALGORITHM=HS256`, and a
  `QUARANTINE_ENCRYPTION_KEY`, with `QUARANTINE_ENABLED=true`.
- Rate limits are raised to `1000/min` on every bucket so tests probe
  behaviour, not throttling, and `MAX_FAILED_LOGINS`/`LOCKOUT_MINUTES` stay at
  their real defaults (5 / 15) so lockout is tested truthfully.
- **Third-party threat-intel keys are stripped from the environment**
  (`VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `IPQUALITYSCORE_API_KEY`) — no test can
  accidentally make a live outbound lookup.
- An autouse fixture disposes and re-creates the schema per test and resets the
  process-wide service singletons (scan service, scan queue, quarantine
  service) so no state leaks between tests.
- Helpers build users (`make_user`), sign tokens directly
  (`token_headers`), and provide an HTTP client over a **live ASGI app with
  lifespan** — the in-process worker is up, so async scans are real.

## What the suite asserts about the product's promises

- **The honest-report rules**: a near-miss brand domain (`paypa1-secure-login`)
  is never declared safe; verdicts always come from the documented enum;
  scores stay in `[0, 100]`; `confidence` is a number; `reasons` are present.
- **The error envelope**: `400/401/403/404/409/413/415/422/429/500/503`
  responses carry `error.{code,message,status_code,correlation_id}` and the
  suite asserts there is **no top-level `detail` key** where tests hit errors.
- **Refresh rotation**: a replayed refresh token yields `401 auth_invalid`.
- **Lockout**: `MAX_FAILED_LOGINS` consecutive bad passwords lock the account.
- **Coverage honesty**: unavailable scanners degrade the report instead of
  fabricating a clean result (exercised through the scanner availability path).
- **ML asymmetry**: `risk_underestimate` appears only when the model is
  strongly (≥ 0.7) more risky than a SAFE/LOW verdict; optimistic disagreement
  stays in metadata.

## Fixture builders

`tests/apk_fixtures.py` builds entirely synthetic APK artifacts (compiled XML
binary-tree manifest, DEX payloads, JPEG/ZIP/APK containers, PKCS#7-signed
certificates) so the APK tests need no real samples — a scanner's CI pipeline
deliberately contains **no labelled malware**. `tests/calibration_set.py` holds
the hand-authored, labelled cases that both the risk engine and the ML
calibration corpus derive from.

## What the suite does NOT cover

- No live VirusTotal/URLhaus/GSB/AbuseIPDB calls (keys are stripped).
- No real ClamAV daemon or YARA engine integration (those scans test the
  unavailable-paths and the metadata contract).
- No load/perf tests and no distributed (multi-process) behaviour — the
  single-process best-effort semantics from
  [limitations-and-non-guarantees.md](limitations-and-non-guarantees.md) are
  the untested frontier.

## Cross-references

- How to run the suite from the project root: [../README.md](../README.md)
- What the tests protect against: [../threat-model/README.md](../threat-model/README.md)
- Pipeline and coverage rules under test: [detection-methodology.md](detection-methodology.md)