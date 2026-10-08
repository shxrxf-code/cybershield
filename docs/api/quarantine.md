# Quarantine endpoints

All paths are prefixed with `/api/v1` and `/quarantine` and require the
`quarantine:read` (browse/download) or `quarantine:write` (release/delete)
scopes. Administrators may access every item; regular users only their own —
anything else, including unknown ids, is reported as `404 not_found`.

Quarantine is best-effort **evidence storage**: when a scan produces a
suspicious file (or the caller opts in), a copy may be held here, optionally
encrypted at rest. Three universal facts:

1. **Stored bytes are never executed or mounted.** Every read decrypts (when
   encryption is on) and integrity-checks the payload first.
2. **Every read, release, and delete is audited** in `quarantine_access_log`
   (actions `read` / `release` / `delete` / `reap`).
3. The filename attached to downloads and releases is always the **sanitised
   display name** — the original (possibly hostile) filename is never used as
   a path or route. See
   [architecture/security-controls.md](../architecture/security-controls.md#path-and-filename-sanitisation).

Items expire after `quarantine_retention_days` (14) and are reaped by a
maintenance sweep.

## `GET /quarantine`

List quarantined samples the caller may access (metadata only, never bytes).
Admins see all items; regular users see only their own.

`200` — `list[QuarantineItemSummary]`, newest first:

```json
[
  {
    "id": "uuid",
    "scan_id": "uuid | null",
    "original_filename": "invoice.pdf",
    "size_bytes": 48127,
    "sha256": "…",
    "detected_type": "pdf",
    "verdict": "HIGH_RISK",
    "score": 71.25,
    "is_encrypted": true,
    "is_released": false,
    "created_at": "…",
    "expires_at": "…",
    "metadata_json": {}
  }
]
```

`metadata_json` may carry the scan-time details recorded when the item was
quarantined.

## `GET /quarantine/{item_id}`

Metadata for one item (never its bytes).

`200` — a single `QuarantineItemSummary`.

`404 not_found` for unknown or non-owned items.

## `GET /quarantine/{item_id}/download`

Download the **verified, decrypted** bytes. Audited (`read`).

`200` — `application/octet-stream` with the file bytes and headers:

```
Content-Disposition: attachment; filename="invoice.pdf"   (sanitised name)
X-Quarantine-Id: <uuid>
X-Quarantine-Sha256: <hex>
Content-Length: <size>
```

- `404 not_found` for unknown/non-owned items.
- `500 quarantine_error` if the stored payload fails integrity verification or
  decryption (fail-closed: corrupted bytes are never returned).

Downloading does **not** change the item's state.

## `POST /quarantine/{item_id}/release`

Mark the item released and return its verified bytes in one call. Audited
(`release`) and persisted as `is_released=true`.

`200` — `application/octet-stream` with the same headers as the download. The
row and blob remain stored (until expiry reap) so a release is traceable.

`404 not_found` on unknown/non-owned items; `500 quarantine_error` on
integrity/decryption failure (fail-closed).

## `DELETE /quarantine/{item_id}`

Delete the blob and its row. **Permanent** — there is no undelete. Audited
(`delete`).

`204 No Content`.

`404 not_found` for unknown/non-owned items; `500 quarantine_error` if the
deletion could not be completed.