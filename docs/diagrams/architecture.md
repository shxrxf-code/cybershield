# Architecture diagram

Component map of the single-process deployment (the documented default). Dashed
boxes are the trust boundaries numbered in the
[threat model](../threat-model/README.md). Solid lines are the request/data
paths; the scanning pipeline runs **once** and is shared by sync routes and the
async worker.

```mermaid
flowchart TB
    subgraph Client["Untrusted clients"]
        C1["Flutter app / CLI / CI"]
    end

    subgraph B1["Boundary ① credential & payload entry"]
        M["app.main: middleware<br/>(X-Request-ID, CORS)"]
        R["app.api.routes<br/>31 endpoints under /api/v1"]
        D["app.api.deps<br/>Bearer JWT | X-API-Key → AuthPrincipal<br/>scope checks · rate-limit identity"]
    end

    subgraph SVC["Services"]
        SS["scan_service<br/>pipelines · _Coverage · report assembly"]
        RE["risk_engine<br/>the ONLY scorer"]
        QS["quarantine<br/>AES-256-GCM blob store"]
        UF["url_fetcher<br/>consent-gated, SSRF-shielded"]
        AU["audit · audit_events writer"]
    end

    subgraph ENG["Detectors & signals"]
        DE["detection_engine<br/>url · email · file · apk · phishing · text"]
        SC["scanners<br/>clamav · yara_scanner"]
        TI["threat_intelligence<br/>VT · URLhaus · GSB · AbuseIPDB"]
        ML["ml.model<br/>advisory opinion<br/>(feature vector only)"]
        WK["workers.queue<br/>asyncio ScanQueue worker"]
    end

    subgraph B3["Boundary ③ outbound contact"]
        E1["ClamAV daemon (unix socket)"]
        E2["Reputation HTTPS APIs"]
        E3["YARA rules on disk<br/>detection-engine/yara/rules"]
    end

    subgraph B2["Boundary ② data at rest"]
        DB[("DB<br/>SQLite / PostgreSQL<br/>9 tables")]
        FS[("storage_root/<br/>uploads/ · quarantine/ · tmp/")]
        RD[("Redis<br/>optional: rate limits + queue")]
    end

    C1 -- "HTTPS" --> M
    M --> R
    R --> D
    D --> SS
    SS --> RE
    SS --> QS
    SS --> AU
    SS --> WK
    SS --> DE
    SS --> SC
    SS --> TI
    SS --> ML
    DE -->|"DetectionSignal"| SS
    SC -->|"ScanResult (availability-aware)"| SS
    TI -->|"positive results only"| SS
    ML -->|"advisory opinion"| SS
    SC -- "subprocess/socket" --> E1
    SC -. "rules" .-> E3
    TI -- "consent-gated HTTPS" --> E2
    D --> DB
    SS --> DB
    QS --> FS
    SS --> FS
    R -- "enqueue (async)" --> WK
    WK -- "re-runs SS pipeline" ---> SS
    SS -. "rate-limit windows (if Redis)" .-> RD
    WK -. "queue (if USE_REDIS_QUEUE)" .-> RD
```

Key invariants the diagram encodes:

1. The API layer and the worker call the **same** `scan_service` entry points —
   there is one pipeline, two trigger paths (see
   [request-lifecycle.md](request-lifecycle.md)).
2. Detectors and scanners **emit signals**; only `risk_engine.assess_risk`
   scores. The arrows into the scan service are signal-producing, not
   score-producing.
3. Outbound contact (boundary ③) is consent-gated and, for URL fetch,
   defended by the seven-layer SSRF shield —
   [security-controls.md](../architecture/security-controls.md#ssrf-protection).
4. Storage keys are server-generated; client filenames never reach the
   filesystem path (boundary ④ merges into ② visually) —
   [security-controls.md](../architecture/security-controls.md#path-and-filename-sanitisation).
5. Redis is *optional*; without it, rate limiting and the queue are in-process
   best-effort (report `rate_limiter.degraded: true`).

Related: [project-report/README.md](../project-report/README.md),
[../architecture/README.md](../architecture/README.md).