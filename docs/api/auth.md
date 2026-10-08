# Authentication endpoints

All paths in this section are prefixed with `/api/v1`. The router prefix is
`/auth`. Rate limiting: every endpoint here uses the **`auth`** bucket
(10/min by default), keyed on the login email's account when authenticated and
on the client IP otherwise.

Authentication design in one paragraph: the server is stateless and issues
signed JWT pairs (access + refresh). It does **not** store sessions; instead it
keeps an in-process **best-effort revocation list** so logout, password change,
and refresh rotation are still meaningful in a single-process deployment. In
multi-replica deployments immediate cross-node revocation requires backing
that store with shared state — this limitation is documented in
[project-report/limitations-and-non-guarantees.md](../project-report/limitations-and-non-guarantees.md).

Token facts:

- Access tokens live **30 min** (`access_token_expire_minutes`); refresh tokens
  **14 days** (`refresh_token_expire_days`).
- Both are `HS256`, carry `sub` (user UUID), `iss`, `aud`, a `jti`, an `exp`,
  and a `scopes` claim.
- A token pair is **rotated** on every refresh: the presented refresh token's
  `jti` is revoked and a brand-new pair is issued.
- Logout and `change-password` revoke the presented access token's `jti`.

## `POST /auth/login`

Exchange credentials for a fresh access/refresh pair. No prior authentication
required.

Body (`LoginRequest`; `extra="forbid"` — extra fields are rejected):

```json
{
  "email": "analyst@example.com",
  "password": "…",
  "client": "flutter-ios"   // optional, max 64, echoed in audit log
}
```

`email` is lower-cased and trimmed. `password` must be 1–256 characters.

`200` — `TokenResponse`:

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<JWT>",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_expires_in": 1209600
}
```

Failure modes (all `401 auth_invalid`, identical wording — do not rely on the
message to distinguish them):

- Unknown email. A **dummy Argon2 verification** is performed so the response
  timing does not reveal whether an email is registered.
- Wrong password. The failure counter increments; after
  `max_failed_logins` (5) failures the account is locked for
  `lockout_minutes` (15). The counter resets on a successful login.
- The account is locked (`is_locked()`).
- The account is disabled (`is_active == false`).

Successful logins reset the failure counter, update `last_login_at`, rehash the
password if the stored hash uses the legacy bcrypt algorithm (bcrypt
compatibility — see
[architecture/security-controls.md](../architecture/security-controls.md#password-storage)),
and audit `auth.login` with the granted scopes.

## `POST /auth/refresh`

Rotate a refresh token into a fresh pair. No prior authentication required.

Body (`RefreshRequest`):

```json
{ "refresh_token": "<JWT>" }
```

The presented token is decoded (strictly as a **refresh** token), the account
is loaded, and — *before* issuing anything — its `jti` is **revoked**. A
replayed refresh token therefore stops working on its second use.

`200` — a new `TokenResponse` pair (with new `expires_in`/`refresh_expires_in`).

`401 auth_invalid` when the token is invalid, unparseable, revoked, expired,
or its account is missing/disabled.

## `POST /auth/logout`

Revoke the presented access token and end the session. Requires an authenticated
caller (`Authorization: Bearer …` or `X-API-Key`).

`204 No Content` — always, even when the presented access token was already
invalid at decode time (there is nothing more to revoke). The API-key path has
no session to invalidate: a key is revoked through
`POST /api-keys/{key_id}/revoke`.

## `POST /auth/change-password`

Rotate the caller's own password. Requires an authenticated caller (Bearer —
use the access token you intend to keep valid until logout).

Body (`PasswordChangeRequest`):

```json
{
  "current_password": "…",
  "new_password": "…"
}
```

Rules enforced here (and by the accounts that call `hash()`):

```text
password_policy_violation (422) when:
  - new_password < password_min_length (default 12)
  - new_password is not sufficiently varied (all one character class, e.g. all digits)
  - new_password appears in a well-known breach list
```

`401 auth_invalid` when `current_password` is wrong, or when `new_password`
equals the current one.

On success:

- The hash and `password_changed_at` are updated.
- The presented access token's `jti` is revoked (best effort). Other sessions
  (other devices, refresh tokens) are **not** invalidated — no token store
  exists to enumerate them; this gap is noted in the project report.
- Audit `auth.password_change`.

`204 No Content`.

## `POST /auth/password-strength`

Advisory strength readout for client-side password meters. **Never grants
access and is not a policy check.**

Body (`PasswordStrengthRequest`):

```json
{ "password": "…" }
```

`200` — `PasswordStrengthResponse`:

```json
{
  "score": 0.83,
  "length": 32,
  "character_classes": 4,
  "problems": []
}
```

`score` is 0–1; `problems` lists human-readable weaknesses. Rejected only for
validation (empty / > 256 chars → `422 validation_error`).