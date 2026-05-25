import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import { createAuthDbFromConnection } from "../packages/auth-db/dist/client.js";
import { isAllowedRedirectUri, isPublicHttpsUrl } from "../packages/auth-worker/dist/url-policy.js";
import { ADMIN_PERMISSION, USER_PERMISSIONS, requireMcpResource } from "../packages/shared/dist/index.js";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("auth-db package root does not export raw SQL client APIs", () => {
  const index = read("packages/auth-db/src/index.ts");
  assert.equal(index.includes('export * from "./client"'), false);
  assert.equal(index.includes("createAuthDb"), false);
  assert.equal(index.includes("createAuthRepositoryFromDb"), false);
});

test("auth-worker does not bypass repository with raw DB access", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.equal(worker.includes("runtime.repo.db"), false);
  assert.equal(worker.includes("repo.db"), false);
});

test("token endpoint preflight rejects shared-secret clients, validates client assertions, and requires MCP resource", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(worker, /params\.has\("client_secret"\)/);
  assert.match(worker, /return "confidential_client_not_allowed"/);
  assert.match(worker, /CLIENT_ASSERTION_TYPE/);
  assert.match(worker, /validatePrivateKeyJwtClientAssertion/);
  assert.match(worker, /tokenEndpointAuthMethod === "private_key_jwt"/);
  assert.match(worker, /return "resource_required"/);
  assert.match(worker, /resourceValues\.length > 1/);
  assert.match(worker, /requireMcpResource\(resourceValues\[0\]/);
});

test("pending authorization is fenced by a lease owner before OAuth completion", () => {
  const repository = read("packages/auth-db/src/repository.ts");
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(repository, /lease_id TEXT NOT NULL|lease_id/);
  assert.match(repository, /completePendingAuthorization\(pendingId, leaseId\)/);
  assert.match(repository, /status = 'processing' AND lease_id = \?/);
  assert.match(worker, /verifyPendingPayloadBinding\(runtime, payload\)/);
  assert.match(worker, /sha256Hex\(JSON\.stringify\(digestPayload\)\)/);
  assert.match(worker, /completePendingAuthorization\(pendingId, leaseId\)/);
  assert.match(worker, /completeAuthorization\(c\.env\.OAUTH_PROVIDER/);
  const preflight = worker.slice(worker.indexOf("async function preflightRequest"), worker.indexOf("async function validateAuthorizePreflight"));
  assert.match(preflight, /request\.method === "POST" && params\.has\("pending_id"\)/);
  assert.ok(preflight.indexOf('params.has("pending_id")') < preflight.indexOf("validateAuthorizePreflight"));
  assert.ok(
    worker.indexOf("completePendingAuthorization(pendingId, leaseId)") <
      worker.indexOf("completeAuthorization(c.env.OAUTH_PROVIDER")
  );
});

test("mcp-tools package has no auth-db dependency", () => {
  const manifest = read("packages/mcp-tools/package.json");
  const source = read("packages/mcp-tools/src/index.ts");
  assert.equal(manifest.includes("@mcp-auth/auth-db"), false);
  assert.equal(source.includes("@mcp-auth/auth-db"), false);
});

test("template MCP sample tool exposes connector-readable descriptors", () => {
  const source = read("packages/mcp-tools/src/index.ts");
  assert.match(source, /ListToolsRequestSchema/);
  assert.match(source, /name: "get_current_user"/);
  assert.match(source, /identifier types, result shape, side effects/);
  assert.match(source, /OAuth-authenticated user and authorization scope/);
  assert.match(source, /confirm which account is active/);
  assert.match(source, /outputSchema: currentUserOutputSchema/);
  assert.match(source, /securitySchemes: MCP_TOOL_SECURITY_SCHEMES/);
  assert.match(source, /structuredContent/);
  assert.match(source, /await import\("agents\/mcp"\)/);
});

test("redirect and client URL policy rejects ambiguous or internal hosts", () => {
  assert.equal(isAllowedRedirectUri("https://app.example.com/callback"), true);
  assert.equal(isAllowedRedirectUri("http://127.0.0.1:3000/callback"), true);
  assert.equal(isAllowedRedirectUri("http://localhost:3000/callback"), true);
  assert.equal(isAllowedRedirectUri("https://intranet/callback"), false);
  assert.equal(isAllowedRedirectUri("https://*.example.com/callback"), false);
  assert.equal(isAllowedRedirectUri("https://app.example.com./callback"), false);
  assert.equal(isAllowedRedirectUri("https://10.0.0.1/callback"), false);
  assert.equal(isAllowedRedirectUri("https://[::1]/callback"), false);
  assert.equal(isAllowedRedirectUri("https://[::ffff:127.0.0.1]/callback"), false);
  assert.equal(isAllowedRedirectUri("https://[::ffff:10.0.0.1]/callback"), false);
  assert.equal(isAllowedRedirectUri("https://[64:ff9b::0a00:0001]/callback"), false);
  assert.equal(isAllowedRedirectUri("https://[2002:0a00:0001::]/callback"), false);
  assert.equal(isAllowedRedirectUri("https://[2001::1]/callback"), false);
  assert.equal(isAllowedRedirectUri("https://service.internal/callback"), false);
  assert.equal(isPublicHttpsUrl("https://client.example.com/metadata.json"), true);
  assert.equal(isPublicHttpsUrl("https://client"), false);
  assert.equal(isPublicHttpsUrl("https://169.254.169.254/metadata.json"), false);
  assert.equal(isPublicHttpsUrl("https://[::ffff:192.168.1.1]/metadata.json"), false);
  assert.equal(isPublicHttpsUrl("https://[2001::ffff:192.0.2.1]/metadata.json"), false);
});

test("MCP resource validation rejects fragments and foreign resources", () => {
  const expected = "https://mcp.example.com/mcp";
  assert.equal(requireMcpResource("https://mcp.example.com/mcp", expected), expected);
  assert.throws(() => requireMcpResource("https://mcp.example.com/mcp#fragment", expected));
  assert.throws(() => requireMcpResource("https://other.example.com/mcp", expected));
});

test("OAuth client metadata URL clients are registered after shared URL policy validation", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(worker, /fetchClientMetadata\(clientId\)/);
  assert.match(worker, /createOrUpdateClientPolicy\(\{/);
  assert.match(worker, /putProviderUrlClient\(env\.OAUTH_KV, clientId/);
  assert.match(worker, /isPublicHttpsUrl\(clientId\)/);
  assert.match(worker, /isAllowedRedirectUri\(uri\)/);
  assert.match(worker, /redirect: "manual"/);
  assert.match(worker, /CLIENT_METADATA_FETCH_TIMEOUT_MS = 3_000/);
  assert.match(worker, /signal: AbortSignal\.timeout\(CLIENT_METADATA_FETCH_TIMEOUT_MS\)/);
  assert.match(worker, /response\.status >= 300 && response\.status < 400/);
  assert.match(worker, /CLIENT_METADATA_AUTH_METHODS = \["none", "private_key_jwt"\] as const/);
  assert.match(worker, /synthesizeKnownClientMetadata/);
  assert.match(worker, /url\.hostname !== "chatgpt\.com"/);
  assert.match(worker, /\/connector\/oauth\/\$\{connectorId\}/);
  assert.match(worker, /jwks_uri/);
});

test("OAuth provider exposes managed metadata", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const metadataEndpointKey = ["client", "Reg", "istration", "Endpoint"].join("");
  const publicClientCreationFlag = ["disallowPublicClient", "Reg", "istration"].join("");
  const publicClientCreationPath = ["/", "reg", "ister"].join("");
  assert.match(worker, new RegExp(`${publicClientCreationFlag}: true`));
  assert.match(worker, /clientIdMetadataDocumentEnabled: false/);
  assert.match(worker, /function renderOAuthServerMetadata/);
  assert.match(worker, /token_endpoint_auth_methods_supported: \["none", "private_key_jwt"\]/);
  assert.match(worker, /client_id_metadata_document_supported: true/);
  assert.equal(worker.includes(metadataEndpointKey), false);
  assert.match(worker, new RegExp(`url\\.pathname === "${publicClientCreationPath}"`));
  assert.match(worker, /status: request\.method === "GET" \? 404 : 405/);
});

test("MCP API handler tolerates freshly issued access token visibility delay", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const apiHandler = worker.slice(worker.indexOf("function createApiHandler"), worker.indexOf("function createDefaultHandler"));
  assert.match(worker, /const ACCESS_TOKEN_UNWRAP_RETRY_DELAYS_MS = \[100, 250, 500, 1000\] as const/);
  assert.match(worker, /async function unwrapOAuthTokenWithRetry<Props>/);
  assert.match(apiHandler, /unwrapOAuthTokenWithRetry<OAuthTokenProps>\(helpers, bearer\)/);
  assert.match(worker, /await sleep\(delayMs\)/);
  assert.match(worker, /helpers\.unwrapToken<Props>\(bearer\)/);
});

test("session uses idle and absolute expiry with guarded touch", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  const migrations = read("packages/auth-db/src/migrations.ts");
  const wrangler = read("apps/mcp-worker/wrangler.jsonc");
  const compact = read("packages/auth-db/src/compact.ts");
  assert.match(worker, /SESSION_IDLE_TTL_SECONDS/);
  assert.match(worker, /SESSION_ABSOLUTE_TTL_SECONDS/);
  assert.match(worker, /SESSION_TOUCH_INTERVAL_SECONDS/);
  assert.match(worker, /idleCandidate >= absolute/);
  assert.match(worker, /touch >= idleCandidate/);
  assert.match(worker, /TOUCH_POLICIES/);
  assert.match(repository, /absolute_expires_at/);
  assert.match(repository, /idle_expires_at/);
  assert.match(repository, /last_touched_at <= \?/);
  assert.match(repository, /getSessionByHash/);
  assert.match(repository, /WHERE login_sessions\.revoked_at IS NULL[\s\S]*login_sessions\.idle_expires_at > \?/);
  assert.match(repository, /DELETE FROM login_sessions/);
  assert.match(repository, /db\.pragma\("optimize"\)/);
  assert.match(worker, /runScheduledBestEffortTask\("auth\.optimize_storage"/);
  assert.doesNotMatch(worker, /runScheduledTask\(runtime, "auth\.optimize_storage"/);
  assert.doesNotMatch(worker, /VACUUM/);
  assert.match(compact, /VACUUM/);
  assert.match(compact, /db\.pragma\("optimize"\)/);
  assert.match(worker, /<th>IP prefix<\/th>/);
  assert.match(worker, /<th>User agent<\/th>/);
  assert.match(worker, /formatSessionActiveUntil/);
  assert.match(wrangler, /"crons": \["\*\/15 \* \* \* \*"\]/);
});

test("MCP refresh grants are non-expiring by default and access tokens stay short-lived", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const wrangler = read("apps/mcp-worker/wrangler.jsonc");
  const devVars = read("apps/mcp-worker/.dev.vars.example");
  assert.match(worker, /accessTokenTtlSeconds: parseTtlSeconds\(env\.ACCESS_TOKEN_TTL_SECONDS, 600, 3600\)/);
  assert.match(worker, /refreshTokenTtlSeconds: parseOptionalTtlSeconds\(env\.REFRESH_TOKEN_TTL_SECONDS, "REFRESH_TOKEN_TTL_SECONDS", MAX_GRANT_TTL_SECONDS\)/);
  assert.match(worker, /refreshTokenTTL: runtime\.config\.refreshTokenTtlSeconds as number/);
  assert.equal(wrangler.includes("REFRESH_TOKEN_TTL_SECONDS"), false);
  assert.equal(devVars.includes("REFRESH_TOKEN_TTL_SECONDS"), false);
});

test("admin UI supports bulk user operations", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  assert.match(worker, /app\.post\("\/admin\/users\/bulk"/);
  assert.match(worker, /app\.post\("\/admin\/oauth-policy"/);
  assert.match(worker, /app\.post\("\/admin\/users\/grant-timeout"/);
  assert.match(worker, /form="bulk-users-form"/);
  assert.match(worker, /Scope Guide/);
  assert.match(worker, /Web UI sessions/);
  assert.match(worker, /MCP OAuth user authorizations/);
  assert.match(worker, /MCP OAuth client apps/);
  assert.match(worker, /OAuth provider token grants/);
  assert.match(worker, /MCP OAuth Authorization Expiration/);
  assert.match(worker, /Default MCP OAuth expiration:/);
  assert.match(worker, /Set selected MCP OAuth expiration/);
  const adminHtml = worker.slice(worker.indexOf("<h2>Scope Guide</h2>"), worker.indexOf("<h2>MCP OAuth Client Apps</h2>"));
  assert.ok(adminHtml.indexOf("<h2>Scope Guide</h2>") < adminHtml.indexOf("<h2>MCP OAuth Authorization Expiration</h2>"));
  assert.ok(adminHtml.indexOf("<h2>MCP OAuth Authorization Expiration</h2>") < adminHtml.indexOf("<h2>Users</h2>"));
  assert.ok(adminHtml.indexOf("<h2>Users</h2>") < adminHtml.indexOf('action="/admin/users"'));
  const clientAppHtml = worker.slice(worker.indexOf("<h2>MCP OAuth Client Apps</h2>"), worker.indexOf("<h2>OAuth Provider Token Grants</h2>"));
  const providerGrantHtml = worker.slice(worker.indexOf("<h2>OAuth Provider Token Grants</h2>"), worker.indexOf("<h2>Active Web UI Sessions</h2>"));
  const sessionHtml = worker.slice(worker.indexOf("<h2>Active Web UI Sessions</h2>"), worker.indexOf("<h2>MCP OAuth User Authorizations</h2>"));
  const userAuthorizationHtml = worker.slice(worker.indexOf("<h2>MCP OAuth User Authorizations</h2>"), worker.indexOf("<h2>Jobs</h2>"));
  assert.match(clientAppHtml, /<th>Application<\/th><th>First seen<\/th><th>Last seen<\/th><th>Action<\/th>/);
  assert.match(providerGrantHtml, /provider token grants from a user row/);
  assert.match(sessionHtml, /<th>Session<\/th><th>User<\/th><th>Created<\/th><th>Last seen<\/th><th>Last touched<\/th><th>IP prefix<\/th><th>User agent<\/th><th>Active until<\/th><th>Absolute until<\/th><th>Action<\/th>/);
  assert.match(userAuthorizationHtml, /<th>User<\/th><th>Application<\/th><th>Scope<\/th><th>Expires<\/th><th>Action<\/th>/);
  assert.match(worker, /data-grant-timeout-control/);
  assert.match(worker, /data-grant-timeout-seconds/);
  assert.match(worker, /const secondsHidden = input\.selectedMode !== "custom"/);
  assert.match(worker, /data-bulk-grant-timeout-fields/);
  assert.match(worker, /bulkAction\.value === "set_grant_timeout"/);
  assert.match(worker, /Cannot disable every active admin/);
  assert.match(worker, /renderBulkUserConfirmation/);
  assert.match(worker, /bulkUpdateUsers\(\{/);
  assert.match(repository, /async function bulkUpdateUsers/);
  assert.match(repository, /await db\.withWriteTransaction\(async \(tx\) =>/);
  assert.match(repository, /event: "users\.bulk\.updated"/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS auth_settings/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS user_oauth_policies/);
  assert.match(migrationSql, /expires_at TEXT/);
});

test("verification includes OAuth provider to MCP integration coverage", () => {
  const integration = read("packages/auth-worker/test/oauth-mcp.integration.test.mjs");
  assert.match(integration, /completeAuthorization/);
  assert.match(integration, /grant_type: "authorization_code"/);
  assert.match(integration, /grant_type: "refresh_token"/);
  assert.match(integration, /new Request\(resource/);
  assert.match(integration, /Authorization: `Bearer/);
});

test("Resend idempotency key is sent as HTTP header and never in message body", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(worker, /function sendEmailViaResend/);
  assert.match(worker, /"Idempotency-Key": input\.idempotencyKey/);
  assert.equal(worker.includes('headers: { "Idempotency-Key"'), false);
  const resendFunction = worker.slice(
    worker.indexOf("async function sendEmailViaResend"),
    worker.indexOf("async function fetchClientMetadata")
  );
  assert.doesNotMatch(resendFunction.match(/body: JSON\.stringify\(\{[\s\S]*?\}\)/)?.[0] ?? "", /headers:/);
});

test("login OTP is issued only for existing active users", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const loginRoute = worker.slice(worker.indexOf('app.post("/login"'), worker.indexOf('app.post("/login/resend"'));
  assert.match(loginRoute, /const user = await runtime\.repo\.findUserByEmail\(email\)/);
  assert.match(loginRoute, /if \(!user \|\| user\.status !== "active"\) \{/);
  assert.match(loginRoute, /return renderLogin\(returnTo, "No active account exists for this email\."\)/);
  assert.ok(loginRoute.indexOf('if (!user || user.status !== "active")') < loginRoute.indexOf("createOrReuseLoginOtpChallenge"));
  assert.match(loginRoute, /createOrReuseLoginOtpChallenge\(\{/);
  assert.match(loginRoute, /if \(otp\.state === "existing"\) \{/);
  assert.match(loginRoute, /return renderOtp\(user\.email, otp\.id, returnTo, undefined, otp\.resendAfter\)/);
  assert.ok(loginRoute.indexOf('if (otp.state === "existing")') < loginRoute.indexOf("sendOtp"));
});

test("login OTP resend wait is enforced by Turso state and survives page transitions", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  assert.match(worker, /const LOGIN_OTP_RESEND_DELAY_SECONDS = 30/);
  assert.match(worker, /app\.post\("\/login\/resend"/);
  assert.match(worker, /name="resend_after"/);
  assert.match(worker, /data-resend-after/);
  assert.match(worker, /Date\.parse\(button\.dataset\.resendAfter/);
  assert.match(worker, /displayResendAfter\(form\.get\("resend_after"\)\)/);
  assert.match(repository, /createOrReuseLoginOtpChallenge/);
  assert.match(repository, /otp_challenges\.redeemed_at IS NULL/);
  assert.match(repository, /otp_challenges\.resend_after IS NOT NULL/);
  assert.match(repository, /state: "existing"/);
  assert.match(repository, /AND \(resend_after IS NULL OR resend_after <= \?\)/);
});

test("OAuth authorization requires fresh email OTP even with an existing web session", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  const authorizeGet = worker.slice(worker.indexOf('app.get("/authorize"'), worker.indexOf('app.post("/authorize"'));
  const reauthStart = worker.slice(worker.indexOf('app.post("/authorize/reauth"'), worker.indexOf('app.post("/authorize/reauth/resend"'));
  const reauthResend = worker.slice(worker.indexOf('app.post("/authorize/reauth/resend"'), worker.indexOf('app.post("/authorize/reauth/verify"'));
  const reauthVerify = worker.slice(worker.indexOf('app.post("/authorize/reauth/verify"'), worker.indexOf('app.get("/authorize"'));
  assert.match(worker, /const OAUTH_AUTHORIZE_OTP_PURPOSE = "oauth_authorize"/);
  assert.match(worker, /app\.post\("\/authorize\/reauth"/);
  assert.match(worker, /app\.post\("\/authorize\/reauth\/verify"/);
  assert.match(worker, /class CsrfError extends Error/);
  assert.match(worker, /app\.onError\(\(error\) =>/);
  assert.match(worker, /issueOAuthReauthMarker/);
  assert.match(worker, /consumeOAuthReauthMarker/);
  assert.match(authorizeGet, /if \(!reauth\.ok\) \{/);
  assert.match(authorizeGet, /return renderAuthorizeReauth\(runtime, session\.user\.email, returnTo\)/);
  assert.ok(authorizeGet.indexOf("consumeOAuthReauthMarker") < authorizeGet.indexOf("parseAuthRequest"));
  assert.match(reauthStart, /if \(isCsrfError\(error\)\)/);
  assert.match(reauthStart, /try \{\s*await sendOtp/);
  assert.match(reauthStart, /Could not send the code/);
  assert.match(reauthResend, /if \(isCsrfError\(error\)\)/);
  assert.match(reauthResend, /try \{\s*await sendOtp/);
  assert.match(reauthResend, /Could not resend the code/);
  assert.match(reauthVerify, /if \(isCsrfError\(error\)\)/);
  assert.match(repository, /createOrReuseUserOtpChallenge/);
  assert.match(repository, /otp_subjects\.purpose = \?/);
  assert.match(repository, /otp_challenges\.purpose = \?/);
});

test("OAuth authorization pages describe the configured MCP server", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(worker, /function renderMcpServerSummary\(description: string\)/);
  assert.match(worker, /function renderAuthorizeReauth<Env extends AuthWorkerEnv>\(\s*runtime: Runtime<Env>/);
  assert.match(worker, /function renderAuthorizeReauthOtp<Env extends AuthWorkerEnv>\(\s*runtime: Runtime<Env>/);
  assert.match(worker, /renderMcpServerSummary\(runtime\.config\.serverDescription\)/);
  const consent = worker.slice(worker.indexOf("function renderConsent"), worker.indexOf("function renderProviderGrants"));
  assert.match(consent, /renderMcpServerSummary\(runtime\.config\.serverDescription\)/);
});

test("permission catalog seed matches shared permissions and triggers use catalog lookup", () => {
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  const seedLine = migrationSql.match(/USER_PERMISSION_SEED:\s*([^\n]+)/);
  assert.ok(seedLine);
  const seed = seedLine[1].split(",").map((value) => value.trim()).sort();
  assert.deepEqual(seed, [...USER_PERMISSIONS].sort());
  assert.equal(USER_PERMISSIONS.includes(ADMIN_PERMISSION), true);
  assert.match(migrationSql, /CREATE TRIGGER IF NOT EXISTS user_permissions_known_insert/);
  assert.match(migrationSql, /SELECT 1 FROM user_permission_catalog WHERE permission = NEW\.permission/);
});

test("admin permission satisfies MCP capability permissions", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const tools = read("packages/mcp-tools/src/index.ts");
  assert.match(worker, /const isAdmin = permissionSet\.has\("admin"\)/);
  assert.match(worker, /isAdmin \|\| capability\.requiredPermissions\.every/);
  assert.match(tools, /name: "get_current_user"/);
  assert.match(tools, /requiredPermissions: \[\]/);
});

test("auth-db source uses Turso transaction API instead of raw transaction SQL", () => {
  for (const path of ["packages/auth-db/src/client.ts", "packages/auth-db/src/repository.ts"]) {
    const source = read(path);
    assert.doesNotMatch(source, /["'`]BEGIN\b/i, path);
    assert.doesNotMatch(source, /["'`]COMMIT\b/i, path);
    assert.doesNotMatch(source, /["'`]ROLLBACK\b/i, path);
    assert.doesNotMatch(source, /["'`]SAVEPOINT\b/i, path);
  }
  const client = read("packages/auth-db/src/client.ts");
  assert.match(client, /ctx\.transaction/);
  assert.match(client, /\.immediate\(\)/);
  assert.match(client, /Auth-db write transactions must not be nested/);
});

test("auth-db write transaction rolls back audit and job writes on error", async () => {
  const connection = createTransactionalFakeConnection();
  const db = createAuthDbFromConnection(connection);

  await assert.rejects(
    db.withWriteTransaction(async (tx) => {
      await tx.run("INSERT INTO auth_audit_logs (id) VALUES (?)", ["audit-1"]);
      await tx.run("INSERT INTO auth_jobs (job_id) VALUES (?)", ["job-1"]);
      throw new Error("forced rollback");
    }),
    /forced rollback/
  );

  assert.deepEqual(connection.tables.auth_audit_logs, []);
  assert.deepEqual(connection.tables.auth_jobs, []);

  await db.withWriteTransaction(async (tx) => {
    await assert.rejects(
      db.run("INSERT INTO auth_audit_logs (id) VALUES (?)", ["root-during-tx"]),
      /Root auth-db queries are not allowed/
    );
    await tx.run("INSERT INTO auth_audit_logs (id) VALUES (?)", ["audit-2"]);
    await tx.run("INSERT INTO auth_jobs (job_id) VALUES (?)", ["job-2"]);
  });

  assert.deepEqual(connection.tables.auth_audit_logs, ["audit-2"]);
  assert.deepEqual(connection.tables.auth_jobs, ["job-2"]);
});

test("runtime schema assertion enables SQLite foreign key enforcement fail-closed", () => {
  const migrations = read("packages/auth-db/src/migrations.ts");
  assert.match(migrations, /assertForeignKeysEnabled/);
  assert.match(migrations, /PRAGMA foreign_keys = ON/);
  assert.match(migrations, /SQLite foreign_keys must be enabled/);
});

test("OAuth client policy is a presence-only allow list", () => {
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  const table = migrationSql.slice(
    migrationSql.indexOf("CREATE TABLE IF NOT EXISTS oauth_client_policies"),
    migrationSql.indexOf("CREATE TABLE IF NOT EXISTS oauth_consents")
  );
  assert.match(table, /client_id TEXT PRIMARY KEY/);
  assert.match(table, /client_version INTEGER NOT NULL DEFAULT 1/);
  assert.match(table, /metadata_snapshot_json TEXT NOT NULL/);
  assert.match(table, /allowed_redirect_uris_json TEXT NOT NULL/);
  assert.match(table, /first_seen_at TEXT/);
  assert.match(table, /last_seen_at TEXT/);
});

test("auth schema uses one initial migration", () => {
  const migrations = read("packages/auth-db/src/migrations.ts");
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  const files = readdirSync(new URL("../packages/auth-db/migrations", import.meta.url)).sort();
  assert.deepEqual(files, ["0001_initial_auth.sql"]);
  assert.match(migrations, /AUTH_SCHEMA_VERSION = 1/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS oauth_client_policies/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS oauth_consents/);
  const consentTable = migrationSql.slice(
    migrationSql.indexOf("CREATE TABLE IF NOT EXISTS oauth_consents"),
    migrationSql.indexOf("CREATE INDEX IF NOT EXISTS oauth_consents_lookup_idx")
  );
  assert.match(consentTable, /expires_at TEXT/);
});

test("account deletion is local hard delete", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repo = read("packages/auth-db/src/repository.ts");
  const accountDeleteRoute = worker.slice(
    worker.indexOf('app.post("/account/delete"'),
    worker.indexOf('app.get("/admin/recovery"')
  );
  assert.match(worker, /app\.post\("\/account\/delete"/);
  assert.match(worker, /confirm\('Delete this account permanently\?/);
  assert.match(worker, /deleteUserAccount\(session\.user\.id\)/);
  assert.match(accountDeleteRoute, /clearCookie\(SESSION_COOKIE\)/);
  assert.match(accountDeleteRoute, /return redirect\("\/", headers, 303\)/);
  assert.match(repo, /deleteUserAccount\(userId\)/);
  assert.match(repo, /DELETE FROM users WHERE id = \?/);
});

test("deployable config does not publish localhost MCP resource", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const wrangler = read("apps/mcp-worker/wrangler.jsonc");
  const devVars = read("apps/mcp-worker/.dev.vars.example");
  assert.equal(wrangler.includes("localhost"), false);
  assert.match(devVars, /MCP_RESOURCE_URI="http:\/\/localhost:8788\/mcp"/);
  assert.match(devVars, /ALLOW_LOCAL_RESOURCE_URI="true"/);
  assert.match(worker, /assertDeployableResourceUri/);
  assert.match(worker, /MCP_RESOURCE_URI uses a local host/);
  assert.match(worker, /MCP_RESOURCE_URI must use https outside local development/);
});

test("auth job finish audits only successful running-row transitions", () => {
  const repository = read("packages/auth-db/src/repository.ts");
  const finishJob = repository.slice(repository.indexOf("async finishJob"), repository.indexOf("async consumeRateLimits"));
  const worker = read("packages/auth-worker/src/index.ts");
  const migrations = read("packages/auth-db/src/migrations.ts");
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  assert.match(migrations, /AUTH_SCHEMA_VERSION = 1/);
  assert.match(migrationSql, /VALUES \(1, 'initial-auth-schema'/);
  assert.match(migrationSql, /lease_id TEXT/);
  assert.match(repository, /lease_id: string \| null/);
  assert.match(repository, /lease_id = \?/);
  assert.match(worker, /const leaseId = job\.lease_id/);
  assert.match(worker, /repo\.finishJob\(job\.job_id, leaseId/);
  assert.match(finishJob, /WHERE job_id = \? AND status = 'running' AND lease_id = \?/);
  assert.match(finishJob, /if \(job\) \{/);
  assert.doesNotMatch(finishJob, /await tx\.run\([\s\S]*auth_job\.succeeded/);
});

test("provider grant revoke requires local consent boundary", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  assert.match(worker, /lookupGrantForRevoke/);
  assert.match(worker, /parseGrantMetadata/);
  assert.match(worker, /requireHighRiskAdmin\(c\.req\.raw, runtime, "admin\.provider_grant\.revoke"/);
  assert.match(repository, /revokeProviderGrantBackedConsent/);
  assert.match(repository, /DELETE FROM oauth_consents[\s\S]*RETURNING \*/);
  assert.match(repository, /type: "revoke_provider_grant"/);
});

test("break-glass recovery is separated from initial bootstrap state", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  assert.match(repository, /createRecoveryAttempt/);
  assert.match(repository, /recovery_attempts/);
  assert.match(repository, /recovery_consumes/);
  assert.match(worker, /recoveryAttemptId/);
  assert.match(worker, /recoveryConsumeId/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS recovery_attempts/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS recovery_consumes/);
  assert.match(migrationSql, /CHECK \(mode = 'initial'\)/);
});

test("initial admin setup is served from the admin entrypoint", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const adminGet = worker.slice(worker.indexOf('app.get("/admin"'), worker.indexOf('app.post("/admin"'));
  const adminPost = worker.slice(worker.indexOf('app.post("/admin"'), worker.indexOf('app.post("/admin/users"'));
  const renderInitialAdmin = worker.slice(worker.indexOf("function renderBootstrap"), worker.indexOf("function renderBootstrapVerify"));
  const renderInitialAdminVerify = worker.slice(
    worker.indexOf("function renderBootstrapVerify"),
    worker.indexOf("function renderRecovery")
  );
  assert.match(adminGet, /hasActiveAdmin\(\)/);
  assert.match(adminGet, /return renderBootstrap\(\)/);
  assert.match(adminPost, /handleInitialAdminPost\(c\.req\.raw, env, runtime\)/);
  assert.match(renderInitialAdmin, /"\/admin"/);
  assert.match(renderInitialAdminVerify, /"\/admin"/);
});

test("recovery OTP send failure invalidates pending consume before verification", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  assert.match(migrationSql, /otp_send_failed/);
  assert.match(repository, /markRecoveryOtpSendFailed/);
  assert.match(repository, /SET status = 'failed'/);
  assert.match(repository, /SET status = 'otp_send_failed'/);
  assert.match(worker, /markRecoveryOtpSendFailed\(attemptId, consumeId/);
});

test("high-risk admin routes require step-up before session touch", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(worker, /type ValidationCheck = "session" \| "csrf" \| "admin" \| "freshStepUp" \| "breakGlass"/);
  assert.match(worker, /const validation = addValidationCheck\(addValidationCheck\(admin\.validation, "csrf"\), "freshStepUp"\)/);
  assert.match(worker, /adminOutcomeResponse\("Client delete", outcome\)/);
  assert.match(worker, /const outcome = await runtime\.repo\.markStepUp/);
  assert.match(worker, /Admin step-up could not be completed/);
});

function createTransactionalFakeConnection() {
  const tables = {
    auth_audit_logs: [],
    auth_jobs: []
  };
  const connection = {
    inTransaction: false,
    tables,
    prepare(sql) {
      return {
        async all() {
          return [];
        },
        async get(args = []) {
          applyInsert(sql, args, tables);
          return null;
        },
        async run(args = []) {
          applyInsert(sql, args, tables);
        }
      };
    },
    transaction(fn) {
      return {
        async immediate() {
          const snapshot = structuredClone(tables);
          connection.inTransaction = true;
          try {
            const result = await fn();
            connection.inTransaction = false;
            return result;
          } catch (error) {
            tables.auth_audit_logs = snapshot.auth_audit_logs;
            tables.auth_jobs = snapshot.auth_jobs;
            connection.inTransaction = false;
            throw error;
          }
        }
      };
    }
  };
  return connection;
}

function applyInsert(sql, args, tables) {
  if (/INSERT INTO auth_audit_logs/i.test(sql)) {
    tables.auth_audit_logs.push(args[0]);
  }
  if (/INSERT INTO auth_jobs/i.test(sql)) {
    tables.auth_jobs.push(args[0]);
  }
}
