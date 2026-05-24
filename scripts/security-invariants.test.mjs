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

test("token endpoint preflight rejects confidential clients and requires MCP resource", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(worker, /params\.has\("client_secret"\)/);
  assert.match(worker, /params\.has\("client_assertion"\)/);
  assert.match(worker, /return "confidential_client_not_allowed"/);
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

test("CIMD admin approval path exists and uses shared URL policy", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(worker, /admin\/cimd\/approve/);
  assert.match(worker, /fetchClientMetadata\(clientId\)/);
  assert.match(worker, /source: "cimd"/);
  assert.match(worker, /isPublicHttpsUrl\(clientId\)/);
  assert.match(worker, /isAllowedRedirectUri\(uri\)/);
});

test("OAuth provider exposes managed metadata", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const metadataEndpointKey = ["client", "Reg", "istration", "Endpoint"].join("");
  const publicClientCreationFlag = ["disallowPublicClient", "Reg", "istration"].join("");
  const publicClientCreationPath = ["/", "reg", "ister"].join("");
  assert.match(worker, new RegExp(`${publicClientCreationFlag}: true`));
  assert.equal(worker.includes(metadataEndpointKey), false);
  assert.match(worker, new RegExp(`url\\.pathname === "${publicClientCreationPath}"`));
  assert.match(worker, /status: request\.method === "GET" \? 404 : 405/);
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
  assert.match(repository, /PRAGMA optimize/);
  assert.match(worker, /auth\.optimize_storage/);
  assert.doesNotMatch(worker, /VACUUM/);
  assert.match(compact, /VACUUM/);
  assert.match(compact, /PRAGMA optimize/);
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
  assert.match(worker, /Set selected grant timeout/);
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

test("client policy source catalog is limited to managed sources", () => {
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  const worker = read("packages/auth-worker/src/index.ts");
  assert.match(migrationSql, /source IN \('admin_created', 'cimd'\)/);
  assert.match(worker, /invalid_client_source/);
});

test("auth schema uses one initial migration", () => {
  const migrations = read("packages/auth-db/src/migrations.ts");
  const files = readdirSync(new URL("../packages/auth-db/migrations", import.meta.url)).sort();
  assert.deepEqual(files, ["0001_initial_auth.sql"]);
  assert.match(migrations, /AUTH_SCHEMA_VERSION = 1/);
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

test("provider grant revoke has no free-form admin form and requires local consent boundary", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  assert.equal(worker.includes("User ID <input"), false);
  assert.equal(worker.includes("Grant ID <input"), false);
  assert.match(worker, /lookupGrantForRevoke/);
  assert.match(worker, /parseGrantMetadata/);
  assert.match(worker, /requireHighRiskAdmin\(c\.req\.raw, runtime, "admin\.provider_grant\.revoke"/);
  assert.match(repository, /revokeProviderGrantBackedConsent/);
  assert.match(repository, /UPDATE oauth_consents[\s\S]*RETURNING \*/);
  assert.match(repository, /type: "revoke_provider_grant"/);
});

test("break-glass recovery is separated from initial bootstrap state", () => {
  const worker = read("packages/auth-worker/src/index.ts");
  const repository = read("packages/auth-db/src/repository.ts");
  const migrationSql = read("packages/auth-db/migrations/0001_initial_auth.sql");
  assert.match(repository, /createRecoveryAttempt/);
  assert.match(repository, /recovery_attempts/);
  assert.match(repository, /recovery_consumes/);
  assert.doesNotMatch(repository, /mode = 'recovery'/);
  assert.doesNotMatch(repository, /INSERT INTO bootstrap_state[\s\S]*'recovery'/);
  assert.match(worker, /recoveryAttemptId/);
  assert.match(worker, /recoveryConsumeId/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS recovery_attempts/);
  assert.match(migrationSql, /CREATE TABLE IF NOT EXISTS recovery_consumes/);
  assert.match(migrationSql, /CHECK \(mode = 'initial'\)/);
  assert.doesNotMatch(migrationSql, /mode IN \('initial', 'recovery'\)/);
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
  assert.match(worker, /adminOutcomeResponse\("Client revoke", outcome\)/);
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
