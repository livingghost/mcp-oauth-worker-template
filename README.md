# MCP OAuth Worker

Reusable Cloudflare Workers template for an OAuth 2.1 protected remote MCP server.

The template provides email OTP login, OAuth authorization, admin operations, Turso-backed auth persistence, and a protected `/mcp` endpoint. Project-specific MCP tools live in `packages/mcp-tools`; the auth layer is reusable across MCP projects.

## Structure

```txt
apps/mcp-worker
  Deployable Cloudflare Worker assembly.

packages/auth-worker
  OAuth provider composition, login, admin UI, consent, token validation, scheduled jobs.

packages/auth-db
  Turso repository, clean initial migration, atomic transactions, maintenance scripts.

packages/mcp-tools
  MCP server factory, capability registry, tools, resources, prompts, tool descriptors, and output schemas.

packages/shared
  OAuth scopes, token props, AuthContext, permissions, shared utilities.
```

`packages/mcp-tools` must not depend on `packages/auth-db`. Tool authorization is injected through `AuthContext` and `AuthorizationRuntime`.

## Security Model

- Public OAuth clients only.
- PKCE S256 is required.
- OAuth implicit flow, plain PKCE, token exchange, and shared-secret confidential client auth are rejected.
- URL-based OAuth client metadata is fetched only from public HTTPS URLs and accepted only after redirect URI validation. ChatGPT connector metadata URLs are normalized to their matching redirect URI.
- OAuth token endpoint client authentication supports public clients and `private_key_jwt` clients with RS256 JWKS verification.
- `/authorize`, `/token`, and `/mcp` fail closed before and after provider handling.
- `/mcp` rechecks bearer token props against current Turso user, client, consent, scope, permission, and version state.
- `/mcp` retries token unwrap briefly after OAuth issue to tolerate provider-state visibility delay during connector setup.
- Email OTP is required for login, initial admin setup, admin step-up, recovery, and OAuth authorization confirmation.
- Login OTPs are issued only for existing active users, except initial admin setup and recovery flows.
- Web sessions have idle and absolute expiry. Session touch is allowed only through route policy after required checks.
- MCP refresh grants are non-expiring by default. Access tokens stay short-lived.
- MCP authorization expiration is controlled locally through admin global, per-user, and bulk policies.
- Revoking a local authorization deletes the local consent row. Provider grant cleanup is queued separately when applicable.
- `OAUTH_KV` stores provider internals only.
- `AUTH_FLOW_KV` stores short-lived authorization UI and reauth payloads only.
- Durable auth data is stored in the Turso database referenced by `AUTH_TURSO_DATABASE_URL`.

## Requirements

- Node.js compatible with the checked-in toolchain
- pnpm `11.3.0`
- Cloudflare Wrangler `4.94.0`
- Turso Cloud database
- Resend API key and verified sender
- Two Cloudflare KV namespaces

Dependency decisions are recorded in [docs/dependency-decisions.md](docs/dependency-decisions.md).

## Setup

Install dependencies:

```powershell
pnpm install
```

Create Cloudflare KV namespaces:

```powershell
pnpm exec wrangler kv namespace create OAUTH_KV
pnpm exec wrangler kv namespace create AUTH_FLOW_KV
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

Set these values:

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

Do not set `REFRESH_TOKEN_TTL_SECONDS` for the default MCP behavior. Provider refresh grants do not expire by time unless that variable is explicitly set.

## Database

Apply the clean initial auth migration before running or deploying:

```powershell
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db migrate
```

Runtime DDL is intentionally forbidden. The Worker fails closed when the expected schema version is missing.

Scheduled cleanup deletes expired short-lived auth data and old session rows. It also runs `PRAGMA optimize` as lightweight database maintenance.

Full compaction is explicit operator work:

```powershell
$env:AUTH_TURSO_DATABASE_URL="libsql://..."
$env:AUTH_TURSO_DATABASE_TOKEN="..."
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db run compact
```

The compact command runs `VACUUM` and then `PRAGMA optimize`.

## Development

Run the Worker locally:

```powershell
pnpm dev
```

By default, local Wrangler uses port `8788`.

## Verification

```powershell
pnpm build
pnpm test
pnpm verify:dependencies
pnpm --filter @mcp-auth/mcp-worker exec wrangler deploy --dry-run
```

The verification set covers package boundaries, OAuth provider integration, protected MCP routing, URL policy, login OTP reuse/resend behavior, OAuth reauth, session expiry, admin bulk operations, Turso transaction rollback, provider grant boundaries, initial admin setup, and scheduled maintenance behavior.

## Deployment

Use [docs/trial-deploy.md](docs/trial-deploy.md) for the complete empty-state deployment sequence.

Update `apps/mcp-worker/wrangler.jsonc` with real KV namespace IDs and production vars. Store secrets through Wrangler:

```powershell
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put AUTH_TURSO_DATABASE_URL
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put AUTH_TURSO_DATABASE_TOKEN
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put RESEND_API_KEY
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_EMAIL_FROM
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_PEPPER_CURRENT
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_PEPPER_CURRENT_VERSION
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_SUBJECT_ENCRYPTION_KEY_CURRENT
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put EMAIL_HASH_KEY_CURRENT
```

Deploy:

```powershell
pnpm run deploy
```

Open `/admin` after deployment. If no active admin exists, `/admin` shows the initial admin setup flow for `BOOTSTRAP_ADMIN_EMAILS`.

## Admin Operations

- Initial admin setup uses `BOOTSTRAP_ADMIN_EMAILS` and email OTP.
- Additional admins are created from `/admin` after admin login and step-up OTP.
- The admin UI supports users, bulk user actions, MCP authorization expiration, active sessions, user authorizations, OAuth client apps, provider grant lookup/revoke, jobs, and audit browsing.
- Active session rows show session fingerprint, IP prefix, user-agent hash, created time, last seen, last touched, active-until, and absolute-until.
- Recovery is separate from initial admin setup and uses recovery attempts, recovery consumes, OTP, security contact notification, one-time consume, and audit.

## Documentation

- [docs/implementation-plan.md](docs/implementation-plan.md): design and completion criteria
- [docs/development-template.md](docs/development-template.md): how to extend the template
- [docs/auth-setup.md](docs/auth-setup.md): setup and operations
- [docs/trial-deploy.md](docs/trial-deploy.md): first deployment checklist
- [docs/dependency-decisions.md](docs/dependency-decisions.md): dependency version decisions
