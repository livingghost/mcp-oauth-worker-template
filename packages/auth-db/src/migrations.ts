import { USER_PERMISSIONS } from "@mcp-auth/shared";
import type { AuthDb } from "./client.js";

export const AUTH_SCHEMA_VERSION = 1;

const permissionSeedSql = USER_PERMISSIONS.map((permission) => `('${permission}')`).join(", ");

export const AUTH_MIGRATIONS = [
  {
    version: 1,
    name: "initial-auth-schema",
    statements: [
      `CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
        authz_version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS user_permission_catalog (
        permission TEXT PRIMARY KEY
      )`,
      `CREATE TABLE IF NOT EXISTS auth_settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT
      )`,
      `INSERT OR IGNORE INTO auth_settings (key, value_json, updated_at, updated_by)
        VALUES ('default_grant_ttl_seconds', 'null', datetime('now'), NULL)`,
      `CREATE TABLE IF NOT EXISTS user_oauth_policies (
        user_id TEXT PRIMARY KEY,
        grant_ttl_seconds INTEGER,
        updated_at TEXT NOT NULL,
        updated_by TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,
      `INSERT OR IGNORE INTO user_permission_catalog (permission)
        VALUES ${permissionSeedSql}`,
      `CREATE TABLE IF NOT EXISTS user_permissions (
        user_id TEXT NOT NULL,
        permission TEXT NOT NULL,
        granted_at TEXT NOT NULL,
        granted_by TEXT,
        PRIMARY KEY (user_id, permission),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (permission) REFERENCES user_permission_catalog(permission)
      )`,
      `CREATE TRIGGER IF NOT EXISTS user_permissions_known_insert
        BEFORE INSERT ON user_permissions
        WHEN NOT EXISTS (SELECT 1 FROM user_permission_catalog WHERE permission = NEW.permission)
        BEGIN
          SELECT RAISE(ABORT, 'unknown user permission');
        END`,
      `CREATE TRIGGER IF NOT EXISTS user_permissions_known_update
        BEFORE UPDATE OF permission ON user_permissions
        WHEN NOT EXISTS (SELECT 1 FROM user_permission_catalog WHERE permission = NEW.permission)
        BEGIN
          SELECT RAISE(ABORT, 'unknown user permission');
        END`,
      `CREATE TABLE IF NOT EXISTS login_sessions (
        id_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        absolute_expires_at TEXT NOT NULL,
        idle_expires_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        last_touched_at TEXT NOT NULL,
        revoked_at TEXT,
        admin_step_up_at TEXT,
        ip_prefix TEXT,
        user_agent_hash TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS login_sessions_user_idx
        ON login_sessions(user_id, revoked_at, absolute_expires_at)`,
      `CREATE INDEX IF NOT EXISTS login_sessions_active_idx
        ON login_sessions(id_hash, revoked_at, idle_expires_at, absolute_expires_at)`,
      `CREATE TABLE IF NOT EXISTS oauth_client_policies (
        client_id TEXT PRIMARY KEY,
        source TEXT NOT NULL CHECK (source IN ('admin_created', 'cimd')),
        status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'blocked', 'revoked', 'failed')),
        client_version INTEGER NOT NULL DEFAULT 1,
        metadata_snapshot_json TEXT NOT NULL,
        allowed_redirect_uris_json TEXT NOT NULL,
        first_seen_at TEXT,
        approved_at TEXT,
        blocked_at TEXT,
        revoked_at TEXT,
        created_by TEXT,
        updated_by TEXT,
        last_seen_at TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS client_creation_requests (
        request_id TEXT PRIMARY KEY,
        actor_user_id TEXT NOT NULL,
        request_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed')),
        client_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS oauth_consents (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_version INTEGER NOT NULL,
        resource TEXT NOT NULL,
        canonical_scope TEXT NOT NULL,
        scope_hash TEXT NOT NULL,
        authz_version INTEGER NOT NULL,
        client_snapshot_json TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        granted_at TEXT NOT NULL,
        expires_at TEXT,
        revoked_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS oauth_consents_lookup_idx
        ON oauth_consents(user_id, client_id, resource, scope_hash, revoked_at)`,
`CREATE TABLE IF NOT EXISTS otp_subjects (
  subject_id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  user_id TEXT,
  encrypted_email TEXT,
  bootstrap_state_id TEXT,
  recovery_attempt_id TEXT,
        recovery_consume_id TEXT,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS otp_challenges (
        id TEXT PRIMARY KEY,
        subject_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        pepper_version TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL,
        redeemed_at TEXT,
        resend_after TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (subject_id) REFERENCES otp_subjects(subject_id) ON DELETE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS otp_challenges_subject_idx
        ON otp_challenges(subject_id, redeemed_at, expires_at)`,
      `CREATE TABLE IF NOT EXISTS rate_limit_counters (
        key TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        count INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        PRIMARY KEY (key, window_start)
      )`,
      `CREATE TABLE IF NOT EXISTS bootstrap_state (
        id TEXT PRIMARY KEY,
        mode TEXT NOT NULL CHECK (mode = 'initial'),
        status TEXT NOT NULL CHECK (status IN ('open', 'consumed', 'closed')),
        consumed_by TEXT,
        consumed_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
      `INSERT OR IGNORE INTO bootstrap_state (id, mode, status, created_at, updated_at)
        VALUES ('initial', 'initial', 'open', datetime('now'), datetime('now'))`,
      `CREATE TABLE IF NOT EXISTS pending_authorization_redeems (
        pending_id TEXT PRIMARY KEY,
        session_id_hash TEXT NOT NULL,
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        resource TEXT NOT NULL,
        scope_hash TEXT NOT NULL,
        csrf_hash TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('processing', 'completed', 'failed')),
        lease_id TEXT NOT NULL DEFAULT '',
        lease_expires_at TEXT NOT NULL,
        completed_at TEXT,
        failed_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS auth_jobs (
        job_id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
        target_user_id TEXT,
        target_client_id TEXT,
        payload_json TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        lease_expires_at TEXT,
        lease_id TEXT,
        request_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
      `CREATE INDEX IF NOT EXISTS auth_jobs_claim_idx
        ON auth_jobs(status, next_attempt_at, lease_expires_at)`,
      `CREATE TABLE IF NOT EXISTS recovery_attempts (
        attempt_id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
          status IN ('notification_pending', 'notification_succeeded', 'notification_failed', 'otp_send_failed', 'state_change_failed', 'completed')
        ),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        completed_at TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS recovery_consumes (
        consume_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'failed')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT,
        FOREIGN KEY (attempt_id) REFERENCES recovery_attempts(attempt_id) ON DELETE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS recovery_attempts_status_idx
        ON recovery_attempts(status, expires_at)`,
      `CREATE TABLE IF NOT EXISTS auth_audit_logs (
        id TEXT PRIMARY KEY,
        actor_user_id TEXT,
        target_user_id TEXT,
        event TEXT NOT NULL,
        result TEXT NOT NULL,
        before_json TEXT,
        after_json TEXT,
        request_id TEXT NOT NULL,
        ip_prefix TEXT,
        user_agent_hash TEXT,
        metadata_json TEXT,
        created_at TEXT NOT NULL
      )`,
      `INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
        VALUES (1, 'initial-auth-schema', datetime('now'))`
    ]
  }
] as const;

export async function assertAuthSchema(db: AuthDb): Promise<void> {
  await assertForeignKeysEnabled(db);
  const row = await db.get<{ version: number }>("SELECT MAX(version) AS version FROM schema_migrations");
  if (Number(row?.version ?? 0) < AUTH_SCHEMA_VERSION) {
    throw new Error("Auth schema is not migrated");
  }
}

async function assertForeignKeysEnabled(db: AuthDb): Promise<void> {
  await db.run("PRAGMA foreign_keys = ON");
  const row = await db.get<{ foreign_keys: number }>("PRAGMA foreign_keys");
  if (Number(row?.foreign_keys ?? 0) !== 1) {
    throw new Error("SQLite foreign_keys must be enabled for auth-db connections");
  }
}

export async function runAuthMigrations(db: AuthDb): Promise<void> {
  await db.run("PRAGMA foreign_keys = ON");
  await db.run(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
  )`);
  for (const migration of AUTH_MIGRATIONS) {
    const applied = await db.get<{ version: number }>("SELECT version FROM schema_migrations WHERE version = ?", [
      migration.version
    ]);
    if (applied) {
      continue;
    }
    await db.withWriteTransaction(async (tx) => {
      for (const statement of migration.statements) {
        await tx.run(statement);
      }
    });
  }
  await assertAuthSchema(db);
}
