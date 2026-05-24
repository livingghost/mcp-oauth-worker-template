# MCP OAuth Worker Implementation Plan

## Objective

Build an OAuth 2.1 protected remote MCP server on Cloudflare Workers and make MCP usage authentication-required by construction.

## Completion Criteria

- `/authorize`, `/token`, and `/mcp` are fail-closed before and after provider handling, and published OAuth metadata points only at deployable endpoints.
- Public client, PKCE S256, and resource/audience validation are mandatory.
- User, client, and consent revocation are enforced immediately through current Turso repository state and version checks.
- OTP, initial bootstrap, break-glass recovery, pending authorization, rate limiting, last-active-admin checks, and audit are handled by Turso atomic APIs.
- Session idle TTL, absolute TTL, and touch policy are separated. Touch is possible only through route policy and validated context.
- The admin session list shows active sessions only and includes session fingerprint, IP prefix, user-agent hash, last seen, last touched, active-until, and absolute-until.
- Expired or revoked session rows are hidden from the active session list and removed by scheduled cleanup after retention.
- Scheduled database maintenance runs lightweight `PRAGMA optimize`.
- Full storage compaction with `VACUUM` is available as an explicit operator command and is not executed from Worker cron.
- Provider grant revoke first checks provider metadata against local consent and revokes local consent before queuing provider grant cleanup.
- `OAUTH_KV` is reserved for `@cloudflare/workers-oauth-provider` state and is not used as an authorization source of truth.
- Auth packages are separated from MCP tool packages so the auth layer can be reused by another Worker project.
- The test suite includes an OAuth provider authorization-code, refresh-token, and protected `/mcp` smoke test, not only source-string invariants.

## Runtime Architecture

- `apps/mcp-worker` owns the deployable Worker.
- `packages/auth-worker` owns OAuth provider composition, login, admin, consent, preflight, token callback, scheduled cleanup, and scheduled lightweight DB optimization.
- `packages/auth-db` owns the Turso repository, migrations, atomic transaction/CAS methods, and explicit operator maintenance scripts.
- `packages/mcp-tools` owns the MCP capability registry and request-local MCP server creation.
- `packages/shared` owns scopes, token props, `AuthContext`, and utility types.

## Security Decisions

- Published OAuth metadata is limited to deployed authorization, token, and protected resource endpoints.
- CIMD allows only exact allowlisted `client_id` URLs by default.
- `completeAuthorization()` always uses `revokeExistingGrants: false` so multiple devices and multiple grants can coexist with explicit revoke.
- `/mcp` revalidates `unwrapToken()` output against current Turso user, client, and consent state after the provider authenticates the request.
- `tokenExchangeCallback` is the final defense for stale authorization state and does not rely on provider-internal auth-code ordering for correctness.
- High-risk admin operations require route policy, CSRF, step-up OTP, and transactional audit.
- Bulk user admin operations are handled by one repository transaction and require a confirmation page.
- Scheduled cleanup may delete expired rows and run `PRAGMA optimize`; full `VACUUM` remains a manual operator action.

## Data Placement

- `OAUTH_KV`: provider internal state only.
- `AUTH_FLOW_KV`: pending authorization UI payload only.
- Turso: users, permission catalog, sessions, clients, consents, OTP, rate limit counters, initial bootstrap state, recovery attempts/consumes, pending authorization redeem marker, jobs, audit logs, migration state.

## Operational Requirements

- Apply `packages/auth-db/migrations/*.sql` before deployment and before Worker startup.
- The Worker fails closed when the expected schema migration is missing.
- `AUTH_TURSO_DATABASE_URL` points to the Turso database that stores auth data.
- `MCP_RESOURCE_URI` must use HTTPS in deployable configuration; localhost requires explicit local-development opt-in.
- Audit logs are append-only.
- Manual recovery is documented as a Turso operator runbook.
- Manual compaction uses `pnpm --filter @mcp-auth/auth-db run compact` after setting auth Turso environment variables.

## Package Boundary

```txt
apps/mcp-worker
  -> @mcp-auth/auth-worker
  -> @mcp-auth/mcp-tools

@mcp-auth/auth-worker
  -> @mcp-auth/auth-db
  -> @mcp-auth/shared
  -> @cloudflare/workers-oauth-provider

@mcp-auth/mcp-tools
  -> @mcp-auth/shared
  -> @modelcontextprotocol/sdk

@mcp-auth/auth-db
  -> @mcp-auth/shared
  -> @tursodatabase/serverless
```

`mcp-tools` does not import `auth-db`; authorization is injected through `AuthContext` and `AuthorizationRuntime`.

## Verification

- `tsc -b` must pass.
- OAuth provider integration test must pass.
- Dependency decisions must match package manifests and lockfile.
- Post-implementation review must verify this implementation against the completion criteria above.
