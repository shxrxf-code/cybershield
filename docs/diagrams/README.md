# Diagrams

Mermaid diagrams for the flows described in prose elsewhere in this
documentation set. Each file renders on GitHub, GitLab, and any
[Mermaid](https://mermaid.js.org) renderer; the raw source is the diagram.

| Diagram | File | Shows |
| --- | --- | --- |
| Architecture | [architecture.md](architecture.md) | Component map: client ↔ API layer ↔ services ↔ detectors/scanners/intel/ML ↔ data stores |
| Request lifecycle | [request-lifecycle.md](request-lifecycle.md) | Synchronous vs asynchronous scan flow, including worker completion and polling |
| Auth flow | [auth-flow.md](auth-flow.md) | Login, access-token use, refresh rotation with `jti` revocation, logout |
| Quarantine flow | [quarantine-flow.md](quarantine-flow.md) | Store → integrity-verified read → release/download → reaping |

## Reading notes

- All diagram facts match the code. Node labels name real endpoints, service
  classes, and configuration keys.
- The **dashed** boundaries in the architecture diagram mark the trust
  boundaries numbered in the [threat model](../threat-model/README.md).
- The request-lifecycle diagram distinguishes the two paths through the same
  pipeline — see [project-report/detection-methodology.md](../project-report/detection-methodology.md)
  for what each stage does.

## Cross-references

- [Architecture overview](../architecture/README.md)
- [API reference](../api/README.md)
- [Threat model](../threat-model/README.md)