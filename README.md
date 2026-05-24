# MCP OAuth Worker

OAuth 2.1 protected MCP server for Cloudflare Workers. The template uses `@cloudflare/workers-oauth-provider` as the OAuth provider, requires email OTP login for MCP authorization, stores durable auth data in Turso Cloud, and keeps OAuth provider internal state in Cloudflare KV.

## Current Structure

```txt
apps/mcp-worker
  deployable Cloudflare Worker

packages/auth-worker
  OAuth provider composition, login, admin, consent, preflight, scheduled jobs

packages/auth-db
  Turso repository, migrations, atomic/CAS APIs, operational maintenance scripts

packages/mcp-tools
  MCP server and capability registry

packages/shared
  shared OAuth scopes, token props, AuthContext, utilities
```

`packages/mcp-tools` does not depend on `packages/auth-db`. MCP tools receive authorization through `AuthContext` and `AuthorizationRuntime`.

## Security Model

- Public clients only.
- PKCE S256 is required.
- OAuth implicit flow, plain PKCE, and token exchange grant are disabled.
- `/authorize`, `/token`, and `/mcp` are fail-closed before and after provider handling.
- `/mcp` rechecks `unwrapToken()` output against current Turso user, client, consent, scope, and version state.
- OTP, initial bootstrap, break-glass recovery, pending authorization, rate limiting, last-active-admin checks, and audit are handled by Turso repository atomic APIs.
- Login sessions split idle TTL and absolute TTL. Session touch is allowed only through route policy and validated context.
- The admin session list shows active sessions only, with session fingerprint, IP prefix, user-agent hash, last seen, last touched, active-until, and absolute-until columns.
- Provider grant revoke is allowed only when provider metadata matches an active local consent. The local consent is revoked first.
- `OAUTH_KV` is reserved for `@cloudflare/workers-oauth-provider`.
- `AUTH_FLOW_KV` is reserved for short-lived pending authorization UI payloads.
- Auth data is stored only in the Turso database referenced by `AUTH_TURSO_DATABASE_URL`.
- `MCP_RESOURCE_URI` must be an explicit HTTPS URL in deployable config. Localhost is accepted only in local development with `ALLOW_LOCAL_RESOURCE_URI=true`.

These constraints are the design basis for treating MCP access as authentication-required.

## Requirements

- Node.js compatible with the checked-in toolchain
- pnpm `11.3.0`
- Cloudflare Wrangler `4.94.0`
- Turso Cloud database
- Resend API key
- Two Cloudflare KV namespaces

The dependency decisions are recorded in [docs/dependency-decisions.md](docs/dependency-decisions.md).

## Setup

Install dependencies:

```powershell
pnpm install
```

Create Cloudflare KV namespaces:

```powershell
wrangler kv namespace create OAUTH_KV
wrangler kv namespace create AUTH_FLOW_KV
```

Create an auth Turso database and token:

```powershell
turso db create mcp-auth
turso db show --url mcp-auth
turso db tokens create mcp-auth
```

Copy the local env template:

```powershell
Copy-Item apps/mcp-worker/.dev.vars.example apps/mcp-worker/.dev.vars
```

Set at least these values:

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
MCP_RESOURCE_URI
BOOTSTRAP_ADMIN_EMAILS
```

`OTP_SUBJECT_ENCRYPTION_KEY_CURRENT` must be a base64url encoded 256-bit AES-GCM key.

Operational timeout vars are seconds:

```txt
ACCESS_TOKEN_TTL_SECONDS=600
SESSION_ABSOLUTE_TTL_SECONDS=43200
SESSION_IDLE_TTL_SECONDS=1800
SESSION_TOUCH_INTERVAL_SECONDS=300
```

`ACCESS_TOKEN_TTL_SECONDS` controls short-lived MCP bearer tokens. `REFRESH_TOKEN_TTL_SECONDS` is intentionally unset by default, so provider refresh grants do not expire by time. Local OAuth grant timeout is managed in the admin UI, with an unlimited default and optional global or per-user limits.

## Database Operations

Build the DB package and apply migrations before running or deploying the Worker:

```powershell
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db migrate
```

Runtime DDL is intentionally forbidden. The Worker fails closed if the expected schema version is missing.

Scheduled cleanup deletes expired short-lived auth data and old session rows. It also runs `PRAGMA optimize` as lightweight database maintenance. Full space reclamation with `VACUUM` is a manual operation:

```powershell
$env:AUTH_TURSO_DATABASE_URL="libsql://..."
$env:AUTH_TURSO_DATABASE_TOKEN="..."
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db run compact
```

Do not run full compaction from the Worker cron. `VACUUM` rewrites storage and should remain an explicit operator action.

## Development

Run the Worker locally:

```powershell
pnpm dev
```

The app package also exposes:

```powershell
pnpm --filter @mcp-auth/mcp-worker run dev
```

By default, local Wrangler runs on port `8788`.

## Verification

Run the full local verification set:

```powershell
pnpm build
pnpm test
pnpm verify:dependencies
pnpm --filter @mcp-auth/mcp-worker exec wrangler deploy --dry-run
```

The current verification set covers:

- raw SQL API not being exported from the auth DB package root
- auth-worker not bypassing repository APIs
- token endpoint public-client/resource preflight checks
- OAuth provider authorization-code and refresh-token flow reaching the protected MCP handler
- pending authorization lease fencing before OAuth completion
- MCP tool package not depending on auth DB
- redirect/client URL rejection for ambiguous and internal hosts
- MCP resource rejection for fragments and foreign resources
- CIMD admin approval path and URL policy use
- OAuth metadata surface policy
- idle/absolute session expiry and guarded touch
- active session listing, session metadata visibility, scheduled cleanup, scheduled `PRAGMA optimize`, and manual `VACUUM` compaction script
- Resend idempotency HTTP header
- permission catalog drift
- provider grant local consent boundary
- break-glass recovery separation from initial bootstrap

## Deployment

For the complete first-time deployment sequence, use [docs/trial-deploy.md](docs/trial-deploy.md).

Update `apps/mcp-worker/wrangler.jsonc` with real KV namespace IDs and production vars. Store secrets through Wrangler:

```powershell
wrangler secret put AUTH_TURSO_DATABASE_URL
wrangler secret put AUTH_TURSO_DATABASE_TOKEN
wrangler secret put RESEND_API_KEY
wrangler secret put OTP_EMAIL_FROM
wrangler secret put OTP_PEPPER_CURRENT
wrangler secret put OTP_PEPPER_CURRENT_VERSION
wrangler secret put OTP_SUBJECT_ENCRYPTION_KEY_CURRENT
wrangler secret put OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION
wrangler secret put EMAIL_HASH_KEY_CURRENT
```

Then deploy:

```powershell
pnpm run deploy
```

## Admin Operations

- Initial admin bootstrap uses `BOOTSTRAP_ADMIN_EMAILS` and email OTP.
- Additional admins are created from `/admin` after login and admin step-up OTP.
- The admin UI supports users, bulk user actions, global/per-user OAuth grant timeout, active sessions, consents, clients, CIMD approval, provider grant lookup/revoke, jobs, and audit browsing.
- Expired or revoked web sessions disappear from the active session list and are deleted by scheduled cleanup after retention.
- Recovery is an attempt-based break-glass flow separate from initial bootstrap. It requires recovery env, nonce, OTP, security contact notification, one-time consume, and audit.

See [docs/auth-setup.md](docs/auth-setup.md) for operational details.

## Documentation

- [docs/implementation-plan.md](docs/implementation-plan.md): design and completion criteria
- [docs/development-template.md](docs/development-template.md): how to extend the template with tools, scopes, and permissions
- [docs/auth-setup.md](docs/auth-setup.md): setup and operations
- [docs/dependency-decisions.md](docs/dependency-decisions.md): dependency version decisions
