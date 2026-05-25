# Trial Deployment From Empty State

This checklist starts from an empty Cloudflare/Turso setup and ends with a deployed Worker that can send email OTPs.

## 1. Install And Login

```powershell
pnpm install
pnpm exec wrangler login
```

If you use the Turso CLI:

```powershell
turso auth login
```

## 2. Create Cloudflare KV Namespaces

Run from the repository root:

```powershell
pnpm exec wrangler kv namespace create OAUTH_KV
pnpm exec wrangler kv namespace create AUTH_FLOW_KV
```

Copy the two returned namespace IDs into `apps/mcp-worker/wrangler.jsonc`:

```jsonc
"kv_namespaces": [
  { "binding": "OAUTH_KV", "id": "<oauth-kv-id>" },
  { "binding": "AUTH_FLOW_KV", "id": "<auth-flow-kv-id>" }
]
```

## 3. Create Auth Turso Database

Using the Turso CLI:

```powershell
turso db create mcp-auth
turso db show --url mcp-auth
turso db tokens create mcp-auth
```

Keep these values:

```txt
AUTH_TURSO_DATABASE_URL=libsql://...
AUTH_TURSO_DATABASE_TOKEN=...
```

This database stores auth data: users, sessions, OTP state, OAuth clients, consents, jobs, and audit logs.

## 4. Prepare Resend

Create a Resend API key and choose a verified sender address for OTP email.

Keep these values:

```txt
RESEND_API_KEY=re_...
OTP_EMAIL_FROM=MCP Server <login@example.com>
OTP_EMAIL_REPLY_TO=support@example.com
```

`OTP_EMAIL_REPLY_TO` is optional.

## 5. Generate Auth Secrets

Run this from the repository root:

```powershell
node -e 'const c=require("node:crypto"); for (const n of ["OTP_PEPPER_CURRENT","OTP_SUBJECT_ENCRYPTION_KEY_CURRENT","EMAIL_HASH_KEY_CURRENT"]) console.log(n+"="+c.randomBytes(32).toString("base64url"))'
```

Use version labels for the OTP and encryption secrets:

```txt
OTP_PEPPER_CURRENT_VERSION=2026-05-24
OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION=2026-05-24
```

## 6. Set Worker Vars

Edit `apps/mcp-worker/wrangler.jsonc`.

For a workers.dev trial, set `MCP_RESOURCE_URI` to your deployed Worker URL plus `/mcp`:

```jsonc
"vars": {
  "MCP_RESOURCE_URI": "https://<your-worker>.<workers-dev-subdomain>.workers.dev/mcp",
  "ACCESS_TOKEN_TTL_SECONDS": "600",
  "SESSION_ABSOLUTE_TTL_SECONDS": "43200",
  "SESSION_IDLE_TTL_SECONDS": "1800",
  "SESSION_TOUCH_INTERVAL_SECONDS": "300",
  "BOOTSTRAP_ADMIN_EMAILS": "<your-admin-email@example.com>"
}
```

Do not set `REFRESH_TOKEN_TTL_SECONDS` for the default MCP behavior. Leaving it unset makes provider refresh grants non-expiring. Use the admin UI for global or per-user MCP OAuth authorization expiration, and use revoke actions as the cutoff mechanism.

## 7. Put Worker Secrets

Run these from the Worker package:

```powershell
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put AUTH_TURSO_DATABASE_URL
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put AUTH_TURSO_DATABASE_TOKEN
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put RESEND_API_KEY
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_EMAIL_FROM
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_EMAIL_REPLY_TO
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_PEPPER_CURRENT
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_PEPPER_CURRENT_VERSION
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_SUBJECT_ENCRYPTION_KEY_CURRENT
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION
pnpm --filter @mcp-auth/mcp-worker exec wrangler secret put EMAIL_HASH_KEY_CURRENT
```

Skip `OTP_EMAIL_REPLY_TO` if you do not want to set it.

## 8. Apply Database Migration

Set local shell env vars for the migration process:

```powershell
$env:AUTH_TURSO_DATABASE_URL="libsql://..."
$env:AUTH_TURSO_DATABASE_TOKEN="..."
```

Then run:

```powershell
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db migrate
```

## 9. Verify Before Deploy

```powershell
pnpm build
pnpm test
pnpm verify:dependencies
pnpm --filter @mcp-auth/mcp-worker exec wrangler deploy --dry-run
```

## 10. Optional Manual Compaction

For a fresh database this is not required. After large deletes in an operated environment, run explicit compaction from the repository root:

```powershell
$env:AUTH_TURSO_DATABASE_URL="libsql://..."
$env:AUTH_TURSO_DATABASE_TOKEN="..."
pnpm --filter @mcp-auth/auth-db run build
pnpm --filter @mcp-auth/auth-db run compact
```

Scheduled Worker cleanup runs lightweight `PRAGMA optimize`; full `VACUUM` stays manual.

## 11. Deploy

```powershell
pnpm run deploy
```

After deploy, open `/admin` on the Worker URL. If no active admin exists, `/admin` shows the initial admin setup flow for the emails in `BOOTSTRAP_ADMIN_EMAILS`. The first admin is created only after that email completes OTP verification.
