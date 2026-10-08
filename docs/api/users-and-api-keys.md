# Users & API keys

All paths are prefixed with `/api/v1`. The router prefixes are `/users` and
`/api-keys`. Users self-service routes require any valid credential; the six
administration routes additionally require an **administrator** account
(`require_admin`).

Every administrator action (create, update flags, deactivate) is written to the
audit log (`audit_events`) and any `UserResponse` is a deliberately safe
projection: password hashes, lockout counters, and internal timestamps are
never exposed.

## `GET /users/me`

The caller's own profile.

`200` — `UserResponse`:

```json
{
  "id": "uuid",
  "email": "analyst@example.com",
  "full_name": null,
  "is_active": true,
  "is_admin": false,
  "is_verified": false,
  "created_at": "…",
  "last_login_at": null
}
```

`404 not_found` if the account cannot be resolved (defensive; API-key auth
always resolves to an account).

## `PATCH /users/me`

Update the caller's profile. Currently only the display name can be changed
(password changes go through `POST /auth/change-password`).

Body (`UserUpdateRequest`):

```json
{ "full_name": "Jane Analyst" }
```

`200` — the updated `UserResponse`. The change is audited as `profile.update`.

## `GET /users` (admin)

List all accounts ordered by creation time. **Administrator only.**

`200` — `list[UserResponse]`.

`403 forbidden` for non-admins; `401 auth_required` without a credential.

## `POST /users` (admin)

Create an account. **Administrator only.**

Body (`UserCreateRequest`):

```json
{
  "email": "new@example.com",
  "password": "…",
  "full_name": "New Analyst"
}
```

- `email` is lower-cased/trimmed.
- `password` must satisfy the enforced policy, exactly as in
  `POST /auth/change-password`: ≥ `password_min_length` (12), sufficiently
  varied, not on the known breach list. Failures return
  `422 password_policy_violation`.
- New accounts are created `is_active=true`, `is_admin=false`, `is_verified=false`.

`201` — the created `UserResponse`.

- `422 validation_error` when the email is already taken (guarded against
  races by the unique index).

`403 forbidden` for non-admins.

## `PATCH /users/{user_id}` (admin)

Modify an account's flags. **Administrator only.**

Body (`AdminUserUpdate`):

```json
{ "is_active": false, "is_admin": true }
```

Both fields optional; only provided fields change.

- `404 not_found` for an unknown id.
- `422 validation_error` if you try to deactivate yourself or change your own
  admin flag.
- Actions are audited (`user.update`) with the submitted flags.

`200` — the updated `UserResponse`.

## `DELETE /users/{user_id}` (admin)

Deactivate (soft-delete) an account: `is_active=false` and the lockout is
cleared (a locked-then-deactivated account must not stay locked for a frozen
account). **Administrator only.**

- Self-deactivation is refused with `422 validation_error`.
- `404 not_found` for an unknown id.
- Audited as `user.deactivate`.

`204 No Content`. Deactivated accounts can no longer log in, refresh tokens,
or authenticate via their API keys (`auth_invalid`).

---

## API keys

API keys are machine credentials. Facts:

- Format: `cs_live_<40 hex>` (production) or `cs_test_<40 hex>`
  (non-production). The tag carries no authority — it is a display hint.
- The **plaintext is shown exactly once**, in the creation response. It can
  never be recovered later, not even by an administrator.
- The database stores only the SHA-256 digest plus a 6-char non-secret display
  prefix, so a dump of `api_keys` is not a credential dump.
- Default expiry: **90 days** (`DEFAULT_TTL_DAYS`); configurable per key from
  1–365 days (`expires_in_days`).
- Scopes default to `["scan:read"]`; unknown requested scopes are dropped.
- Revocation is immediate: authentication via the key stops on next use
  (`auth_invalid`).

Use them in the `X-API-Key` header. Rate limiting keys on the owning account
(`user:<id>`), so rotating keys cannot multiply the budget.

## `GET /api-keys`

List the caller's API keys with metadata (never plaintext).

`200` — `list[ApiKeyResponse]`:

```json
[
  {
    "id": "uuid",
    "name": "ci-builder",
    "prefix": "cs_test_0a1b2c",
    "scopes": ["scan:read"],
    "is_active": true,
    "created_at": "…",
    "expires_at": "…",
    "last_used_at": null,
    "plaintext": null
  }
]
```

`plaintext` is `null` except in the creation response.

## `POST /api-keys`

Create a machine credential. Uses the **`default`** rate-limit bucket.

Body (`ApiKeyCreateRequest`):

```json
{
  "name": "ci-builder",
  "scopes": ["scan:read", "scan:write"],
  "expires_in_days": 30
}
```

- `name` — 1–120 chars, `[A-Za-z0-9 ._-]` only.
- `expires_in_days` — 1–365; omitted means the 90-day default.

`201` — `ApiKeyResponse` with `plaintext` populated **exactly once**:

```json
{
  "id": "uuid",
  "name": "ci-builder",
  "prefix": "cs_test_0a1b2c",
  "scopes": ["scan:read", "scan:write"],
  "is_active": true,
  "created_at": "…",
  "expires_at": "…",
  "last_used_at": null,
  "plaintext": "cs_test_0a1b2c3d…"
}
```

Store the plaintext immediately — it cannot be retrieved again. Creation is
audited (`api_key.create`, recording only the prefix and scopes — never the
key).

## `POST /api-keys/{key_id}/revoke`

Revoke a key immediately. The caller may only revoke their own keys (a
foreign/unknown id is `404 not_found`).

Body (`RevokeRequest`):

```json
{ "reason": "rotated in CI" }
```

`204 No Content`. Audited as `api_key.revoke`. The revoked key stops working on
its next presentation.