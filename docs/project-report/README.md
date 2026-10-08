# Project Report

This is the honest project status: what CyberShield does, how it detects, what
it *cannot* guarantee, and how it is tested. Everything here is backed by the
source in `backend/` and is deliberately written in the same caveated voice the
product itself uses. CyberShield never claims certainty the evidence cannot
support; this report holds itself to the same standard.

## Contents

| Page | What it answers |
| --- | --- |
| [detection-methodology.md](detection-methodology.md) | How a scan produces a score, verdict, and confidence. The detector families, the scoring engine, the advisory ML opinion, and the coverage rules. |
| [limitations-and-non-guarantees.md](limitations-and-non-guarantees.md) | What CyberShield does **not** do and why. Static-only analysis, the "absence of detection is not safety" rule, scanner availability, consent gating, and best-effort state. |
| [testing.md](testing.md) | The test suite: how to run it, what it pins down, and what each file covers (87 tests across 11 files). |

## The one-paragraph status

CyberShield is a **working static-analysis scanner**, not a finished commercial
security product. It implements its core promise faithfully:

- Every scan produces an evidence-based, explainable report (`score`,
  `verdict`, `confidence`, `reasons`, `breakdown`) from the rules in
  [detection-methodology.md](detection-methodology.md).
- When it could not look, it says so: `scanner_coverage` and
  `analysis_incomplete` are real, and an incomplete analysis resolves to
  `UNKNOWN`, never to a silent all-clear.
- Nothing it receives is ever executed, mounted, installed, or submitted to a
  third party without per-scan consent.

What it is **not**:

- Not a sandbox / dynamic analyzer. APKs and files are inspected statically —
  an APK is parsed for manifest, permissions, signatures, and DEX strings; it
  is never run.
- Not a guarantee of safety. A `SAFE` verdict means *no detector available to
  this pipeline flagged the object*, not that the object is clean — see
  [limitations-and-non-guarantees.md](limitations-and-non-guarantees.md).
- Not a distributed system. Revocation, queueing, and rate limiting fall back
  to best-effort in-process state unless Redis / a shared store is configured.

## What "done" means here

The feature set this documentation describes is implemented and tested:

- **31 endpoints** under `/api/v1` — [api/README.md](../api/README.md).
- **87 passing tests** across 11 files — [testing.md](testing.md).
- **9 database tables** managed by Alembic — [../architecture/database.md](../architecture/database.md).
- **External scanners** (ClamAV, YARA) and **4 reputation providers** with
  availability-aware degradation — [detection-methodology.md](detection-methodology.md).
- **Hardening controls**: Argon2id passwords, JWT refresh rotation,
  sliding-window rate limiting, a 7-layer SSRF shield, upload caps, and
  AES-256-GCM-encrypted at-rest quarantine blobs — [../architecture/security-controls.md](../architecture/security-controls.md).

## Cross-references

- [Root documentation index](../README.md)
- [API reference](../api/README.md)
- [Architecture](../architecture/README.md)
- [Threat model (what could go wrong and what is done about it)](../threat-model/README.md)
- [Diagrams](../diagrams/README.md)