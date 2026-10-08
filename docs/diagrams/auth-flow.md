# Auth flow: login, token rotation, logout

Stateless JWT session management with a **best-effort, in-process** revocation
store (`jti` mapping, bounded at 50k entries). Details and code:
[security-controls.md](../architecture/security-controls.md#tokens) and
[../api/auth.md](../api/auth.md).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant API as API routes
    participant RATE as rate_limit (auth bucket)
    participant PW as passwords (Argon2id)
    participant TOK as tokens service
    participant REV as revocation store (in-process)
    participant DB as Database

    C->>API: POST /api/v1/auth/login {email, password}
    API->>RATE: check auth bucket (10/min)
    API->>PW: verify(password, user.password_hash)
    alt unknown email
        PW->>PW: dummy Argon2 verify (timing equaliser)
        API-->>C: 401 auth_invalid
    else wrong password
        PW->>DB: failed_login_count += 1 (commit now)
        alt count >= max_failed_logins (5)
            PW->>DB: locked_until = now + lockout_minutes (15)
        end
        API-->>C: 401 auth_invalid
    else success
        API->>TOK: create_token_pair(subject, scopes)
        TOK-->>API: access (30 min) + refresh (14 d)
        API->>DB: reset failures · last_login_at · audit auth.login
        API-->>C: 200 {access_token, refresh_token, token_type, expires_in, refresh_expires_in}
    end

    C->>API: GET /api/v1/scans (Authorization: Bearer access)
    API->>TOK: decode_access_token (HS256, allow-list claims)
    API->>REV: jti revoked?
    alt valid & not revoked
        API-->>C: 200 data
    else
        API-->>C: 401 auth_invalid
    end

    C->>API: POST /api/v1/auth/refresh {refresh_token}
    API->>RATE: check auth bucket
    API->>TOK: decode_refresh_token (typ=refresh)
    API->>REV: revoke(presented jti)
    %% ^ refresh rotation: old jti is revoked before minting a fresh pair
    API->>TOK: create_token_pair(subject, scopes)
    %% ^ fresh access + refresh
    API-->>C: 200 new access + new refresh
    Note over REV: a replayed old refresh token<br/>is now revoked ⇒ 401 auth_invalid

    C->>API: POST /api/v1/auth/logout (Bearer access)
    API->>REV: revoke(access jti)
    %% ^ always 204; nothing further is revoked if the token already expired
    API->>DB: audit auth.logout
    API-->>C: 204
```

Notes that matter for the diagram:

- Access and refresh tokens are **typed** and not interchangeable — a leaked
  refresh token cannot be presented as an access token.
- `change-password` revokes the access token presented in that request (the
  store never sees the others — a documented gap, see
  [limitations-and-non-guarantees.md](../project-report/limitations-and-non-guarantees.md)).
- Revocation is per-process: replica B does not see replica A's stores.
  Multi-replica deployments needing cluster-wide rotation should back this
  store with shared state.
- Login without any credential → `401 auth_required`; token verification errors
  never distinguish "expired" from "bad signature" in the message.

Related: [auth-flow](../api/auth.md) API reference,
[token design](../architecture/security-controls.md#tokens).