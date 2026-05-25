# Auth Setup

## Cloudflare Resources

Create two KV namespaces:

```powershell
wrangler kv namespace create OAUTH_KV
wrangler kv namespace create AUTH_FLOW_KV
```

`OAUTH_KV` stores `@cloudflare/workers-oauth-provider` state.
`AUTH_FLOW_KV` stores short-lived pending authorization UI payloads.

## Turso

Create an auth Turso Cloud database and token:

```powershell
turso db create mcp-auth
turso db show --url mcp-auth
turso db tokens create mcp-auth
```

Apply migrations before deploy:

```powershell
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db migrate
```

The auth Worker connects only through `AUTH_TURSO_DATABASE_URL` and `AUTH_TURSO_DATABASE_TOKEN`.

## Database Maintenance

Scheduled Worker cleanup deletes expired short-lived records and old session rows. It also runs `PRAGMA optimize` for lightweight query-planner maintenance.

Full compaction is explicit operator work:

```powershell
$env:AUTH_TURSO_DATABASE_URL="libsql://..."
$env:AUTH_TURSO_DATABASE_TOKEN="..."
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db run compact
```

The compact command runs `VACUUM` and then `PRAGMA optimize`. It is not part of Worker cron because `VACUUM` rewrites storage and should be run intentionally.

## Required Secrets

```txt
AUTH_TURSO_DATABASE_URL
AUTH_TURSO_DATABASE_TOKEN
RESEND_API_KEY
OTP_EMAIL_FROM
OTP_PEPPER_CURRENT
OTP_PEPPER_CURRENT_VERSION
OTP_SUBJECT_ENCRYPTION_KEY_CURRENT
OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION
EMAIL_HASH_KEY_CURRENT
```

`OTP_SUBJECT_ENCRYPTION_KEY_CURRENT` must be a base64url encoded 256-bit raw AES key.

## Required Vars

```txt
MCP_RESOURCE_URI
BOOTSTRAP_ADMIN_EMAILS=admin@example.com
```

`MCP_RESOURCE_URI` must be an https URL outside local development. A localhost resource URI is accepted only when `ALLOW_LOCAL_RESOURCE_URI=true`, which belongs in `.dev.vars` and not in production deploy config.

Initial admin bootstrap is only the first admin seed. Additional admins are created in `/admin` after login and step-up OTP.

## Timeout Model

- `ACCESS_TOKEN_TTL_SECONDS` is in seconds. The default is 600 seconds and the maximum is 3600 seconds.
- `REFRESH_TOKEN_TTL_SECONDS` is in seconds when set. It is unset by default, which means provider refresh grants do not expire by time.
- Local MCP authorization expiration is managed by `auth_settings`, `user_oauth_policies`, and `oauth_consents.expires_at`.
- The admin UI can set a global default expiration, set per-user override/inherit/no-expiration behavior, or update selected users in bulk.
- Non-expiring provider refresh grants are controlled by local consent expiry, admin revoke, user authorization revoke, client revoke, user disable, and local consent/version checks.
- Web/admin sessions are separate from MCP bearer access. They use idle and absolute expiry.

## Login Model

- Users authenticate by email OTP through Resend.
- Passwords, usernames, and display names are not stored.
- Multiple sessions for the same email are allowed.
- Session cookies use `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, and no `Domain`.
- Sessions have both idle expiry and absolute expiry.
- Session touch is allowed only through the route registry after required checks such as session validation, CSRF, admin permission, and fresh step-up.
- The admin session table lists active sessions only. It shows a session fingerprint, IP prefix, user-agent hash, created time, last seen, last touched, active-until, and absolute-until.
- Expired or revoked sessions are not shown as active sessions. Scheduled cleanup deletes expired or revoked session rows after retention.

## OAuth Model

- Public clients only.
- PKCE S256 is required.
- Implicit flow, plain PKCE, and token exchange grant are disabled.
- OAuth metadata advertises the deployed authorization, token, and protected resource endpoints.
- URL-based OAuth client metadata is fetched only from public HTTPS URLs and accepted only after redirect URI validation. ChatGPT connector metadata URLs are normalized to their matching redirect URI.
- Token endpoint client authentication supports public clients and `private_key_jwt` clients with RS256 `jwks` / `jwks_uri` verification.
- Non-URL client IDs must already exist in the local OAuth client app table.
- Existing grants are not revoked by new authorization; revocation is explicit through local policy/version checks.
- Individual provider grant revoke requires provider grant metadata to match an active local consent. If metadata is missing or stale, use the bulk user authorization revoke path.
- Admin bulk user operations can disable/enable users, revoke sessions, revoke local authorizations, revoke all authorization, or set MCP authorization expiration for selected users. They require step-up, show a confirmation page, and execute through one repository transaction.

## Recovery

Recovery is separate from initial bootstrap and uses its own `recovery_attempts` / `recovery_consumes` state machine. It requires recovery env, nonce, OTP, security contact notification, one-time consume, and audit. It never reopens or consumes `bootstrap_state`.

If all app recovery paths fail, use the manual Turso operator runbook:

1. Require two-person approval.
2. Record operator identities, timestamp, and database snapshot.
3. Apply the minimal Turso change needed to restore an admin.
4. Increment all affected `authz_version` values.
5. Revoke active sessions/grants through admin UI or job runner.
6. Insert an audit record after service recovery.

The manual runbook stays in operator procedure and audit records.
