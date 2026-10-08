# Request lifecycle: synchronous vs asynchronous scans

Both flows run the **same** `ScanService` pipeline
([detection-methodology.md](../project-report/detection-methodology.md)); they
differ only in *when* and *by whom* it runs, and in what the client sees first.
Status transitions for async scans: `QUEUED → SCANNING → ANALYZING → COMPLETED`,
with `FAILED` on a worker-caught exception.

## Synchronous (default, `?async=false`)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant API as FastAPI + deps
    participant SS as ScanService
    participant DE as Detectors / scanners / intel / ML
    participant RE as risk_engine
    participant DB as Database
    participant AU as audit_events

    C->>API: POST /api/v1/scan/url (Bearer / X-API-Key)
    API->>API: resolve AuthPrincipal · check scope scan:write · rate-limit bucket
    API->>SS: scan_url(request)
    SS->>DE: run pipeline (structural / fetch / intel …)
    Note over DE: coverage.unit() / coverage.done() per check<br/>unavailable scanner ⇒ not completed
    DE-->>SS: DetectionSignals + scanner_coverage
    SS->>RE: assess_risk(bundle, coverage)
    RE-->>SS: score · verdict · confidence · reasons · breakdown
    SS->>DB: insert/update scans row (status COMPLETED)
    SS-->>API: UrlScanResponse (200)
    API->>AU: audit scan.submit
    API-->>C: 200 report
```

## Asynchronous (`?async=true`)

The upload blob (files/APKs) is parked under an opaque key in
`storage_root/uploads/` before the `202` is returned; the worker removes it
after the job unless `keep_files_after_scan`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant API as FastAPI + deps
    participant Q as workers.queue ScanQueue
    participant W as Worker task
    participant SS as ScanService
    participant DE as Detectors / scanners / intel / ML
    participant RE as risk_engine
    participant DB as Database

    C->>API: POST /api/v1/scan/file?async=true (Bearer / X-API-Key)
    API->>API: validate · scope scan:write · rate-limit bucket
    API->>DB: create Scan row (status QUEUED, expires_at = +90d)
    API->>DB: store upload blob under opaque storage key
    API->>Q: enqueue ScanJob (scan_id, options, storage_key)
    API-->>C: 202 {scan_id, status: QUEUED, poll_url}
    Note over Q: row is committed BEFORE enqueue<br/>so the worker never races the record
    Q-->>W: worker pops job
    W->>DB: fetch Scan by scan_id (status → SCANNING)
    W->>SS: scan_file(scan_id=…, options replay, data from storage)
    SS->>DE: run pipeline
    DE-->>SS: signals + coverage
    SS->>RE: assess_risk(bundle, coverage)
    RE-->>SS: score · verdict · confidence · reasons
    SS->>DB: status → ANALYZING → COMPLETED, report persisted
    SS->>DB: delete temp upload blob (unless keep_files_after_scan)
    par Client polls
        C->>API: GET /api/v1/scans/{scan_id}
        API->>DB: read scan row
        API-->>C: QUEUED / SCANNING / ANALYZING / COMPLETED / FAILED
    end
    Note over W: exception at worker boundary ⇒ row → FAILED (bounded error_message),<br/>never retried in a loop
```

Note on timeouts in the diagram: a scan that does not complete is reported as
`scan_failed` (`500`) on the sync path; there is no background crash-recovery
loop in the current worker — see
[limitations-and-non-guarantees.md](../project-report/limitations-and-non-guarantees.md).

Related: [../architecture/README.md](../architecture/README.md#request-lifecycles)
and [../api/scans.md](../api/scans.md).