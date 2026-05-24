import {
  ADMIN_PERMISSIONS,
  ADMIN_PERMISSION,
  assertKnownPermissions,
  base64UrlDecode,
  base64UrlEncode,
  formatCanonicalScope,
  hashScope,
  normalizeEmail,
  randomBase64Url,
  sha256Hex,
  timingSafeEqual,
  type AuthContext,
  type OAuthScope,
  type OAuthTokenProps
} from "@mcp-auth/shared";
import type { AuthDb, AuthTursoEnv, TxAuthDb } from "./client.js";
import { createAuthDb } from "./client.js";
import { assertAuthSchema } from "./migrations.js";

export interface UserRow {
  id: string;
  email: string;
  status: "active" | "disabled";
  authz_version: number;
  created_at: string;
  updated_at: string;
}

export interface ClientPolicyRow {
  client_id: string;
  client_version: number;
  metadata_snapshot_json: string;
  allowed_redirect_uris_json: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface ConsentRow {
  id: string;
  user_id: string;
  client_id: string;
  client_version: number;
  resource: string;
  canonical_scope: string;
  scope_hash: string;
  authz_version: number;
  expires_at: string | null;
}

export interface AdminUserRow extends UserRow {
  permissions: string[];
  grant_ttl_override: boolean;
  grant_ttl_seconds: number | null;
  effective_grant_ttl_seconds: number | null;
}

export interface SessionRow {
  id_hash: string;
  user_id: string;
  user_email: string;
  created_at: string;
  expires_at: string;
  absolute_expires_at: string | null;
  idle_expires_at: string | null;
  last_seen_at: string | null;
  last_touched_at: string | null;
  revoked_at: string | null;
  admin_step_up_at: string | null;
  ip_prefix: string | null;
  user_agent_hash: string | null;
}

export interface AdminConsentRow extends ConsentRow {
  user_email: string;
}

export interface AuditLogRow {
  id: string;
  actor_user_id: string | null;
  target_user_id: string | null;
  event: string;
  result: string;
  request_id: string;
  ip_prefix: string | null;
  user_agent_hash: string | null;
  metadata_json: string | null;
  created_at: string;
}

export interface AuthJobRow {
  job_id: string;
  type: string;
  idempotency_key: string;
  status: "pending" | "running" | "succeeded" | "failed";
  target_user_id: string | null;
  target_client_id: string | null;
  payload_json: string;
  attempts: number;
  next_attempt_at: string;
  lease_expires_at: string | null;
  lease_id: string | null;
  request_id: string;
  created_at: string;
  updated_at: string;
}

export type RevokeOutcome = "changed" | "already_revoked" | "not_found" | "mismatch" | "lookup_failed";
export type BulkRevokeOutcome = "changed" | "no_active_targets" | "not_found";
export type BulkUserOperationAction =
  | "disable"
  | "enable"
  | "revoke_sessions"
  | "revoke_grants"
  | "revoke_authorization"
  | "set_grant_timeout";

export interface BulkUserOperationInput {
  action: BulkUserOperationAction;
  actorUserId: string;
  grantTtlSeconds?: number | null;
  inheritGrantTtl?: boolean;
  requestId: string;
  userIds: readonly string[];
}

export interface BulkUserOperationResult {
  action: BulkUserOperationAction;
  changedCount: number;
  outcomes: Record<string, RevokeOutcome | BulkRevokeOutcome>;
  selectedCount: number;
}

export interface SessionContextRow {
  sessionIdHash: string;
  user: UserRow;
  adminStepUpAt: string | null;
  idleExpiresAt: string;
  absoluteExpiresAt: string;
}

export interface AuditInput {
  actorUserId?: string | null;
  targetUserId?: string | null;
  event: string;
  result: "success" | "failure" | "denied" | "queued";
  before?: unknown;
  after?: unknown;
  requestId: string;
  ipPrefix?: string | null;
  userAgentHash?: string | null;
  metadata?: unknown;
}

export interface AuthRepository {
  assertSchema(): Promise<void>;
  findUserByEmail(email: string): Promise<UserRow | null>;
  findUserById(userId: string): Promise<UserRow | null>;
  listUsers(): Promise<AdminUserRow[]>;
  getDefaultGrantTtlSeconds(): Promise<number | null>;
  getEffectiveGrantTtlSeconds(userId: string): Promise<number | null>;
  setDefaultGrantTtlSeconds(ttlSeconds: number | null, actorUserId: string, requestId: string): Promise<void>;
  setUserGrantTtlSeconds(
    userId: string,
    ttlSeconds: number | null,
    actorUserId: string,
    requestId: string
  ): Promise<RevokeOutcome>;
  clearUserGrantTtlSeconds(userId: string, actorUserId: string, requestId: string): Promise<RevokeOutcome>;
  listSessions(limit?: number): Promise<SessionRow[]>;
  listConsents(limit?: number): Promise<AdminConsentRow[]>;
  listAuditLogs(limit?: number): Promise<AuditLogRow[]>;
  listJobs(limit?: number): Promise<AuthJobRow[]>;
  deleteUserAccount(userId: string): Promise<boolean>;
  createUser(email: string, permissions: readonly string[], actorUserId: string | null, requestId: string): Promise<UserRow>;
  setUserState(
    userId: string,
    status: UserRow["status"],
    permissions: readonly string[],
    actorUserId: string,
    requestId: string
  ): Promise<void>;
  bulkUpdateUsers(input: BulkUserOperationInput): Promise<BulkUserOperationResult>;
  createSession(input: {
    userId: string;
    idleTtlSeconds: number;
    absoluteTtlSeconds: number;
    ipPrefix?: string | null;
    userAgentHash?: string | null;
  }): Promise<string>;
  getSession(token: string | null): Promise<SessionContextRow | null>;
  touchSessionAfterSafeValidation(
    sessionIdHash: string,
    idleTtlSeconds: number,
    touchIntervalSeconds: number
  ): Promise<SessionContextRow | null>;
  revokeSessionByHash(sessionIdHash: string, actorUserId: string | null, requestId: string): Promise<RevokeOutcome>;
  revokeUserSessions(userId: string, actorUserId: string | null, requestId: string): Promise<BulkRevokeOutcome>;
  markStepUp(sessionIdHash: string, actorUserId: string, requestId: string): Promise<RevokeOutcome>;
  listPermissions(userId: string): Promise<string[]>;
  hasActiveAdmin(): Promise<boolean>;
  consumeInitialBootstrap(userId: string, requestId: string): Promise<boolean>;
  consumeInitialBootstrapAndCreateAdmin(email: string, requestId: string): Promise<UserRow | null>;
  createRecoveryAttempt(email: string, ttlSeconds: number, requestId: string): Promise<{ attemptId: string; expiresAt: string }>;
  markRecoveryNotificationFailed(attemptId: string, requestId: string): Promise<void>;
  markRecoveryNotificationSucceeded(attemptId: string, requestId: string): Promise<{ consumeId: string; email: string } | null>;
  markRecoveryOtpSendFailed(attemptId: string, consumeId: string, requestId: string): Promise<void>;
  consumeRecoveryAttemptAndCreateAdminAndSession(
    email: string,
    attemptId: string,
    consumeId: string,
    idleTtlSeconds: number,
    absoluteTtlSeconds: number,
    requestId: string
  ): Promise<{ user: UserRow; sessionToken: string } | null>;
  markRecoveryStateChangeFailed(attemptId: string, requestId: string): Promise<void>;
  writeAudit(input: AuditInput): Promise<void>;
  createOrUpdateClientPolicy(input: {
    clientId: string;
    metadata: unknown;
    redirectUris: readonly string[];
    requestId: string;
  }): Promise<void>;
  getClientPolicy(clientId: string): Promise<ClientPolicyRow | null>;
  listClientPolicies(): Promise<ClientPolicyRow[]>;
  revokeClient(clientId: string, actorUserId: string, requestId: string): Promise<RevokeOutcome>;
  saveConsent(input: {
    userId: string;
    clientId: string;
    clientVersion: number;
    resource: string;
    scopes: readonly string[];
    authzVersion: number;
    clientSnapshot: unknown;
    redirectUri: string;
    expiresAt: string | null;
  }): Promise<ConsentRow>;
  getActiveConsent(input: {
    userId: string;
    clientId: string;
    resource: string;
    scopes: readonly string[];
  }): Promise<ConsentRow | null>;
  getConsentById(consentId: string): Promise<ConsentRow | null>;
  revokeConsent(consentId: string, actorUserId: string, requestId: string): Promise<RevokeOutcome>;
  revokeUserConsents(userId: string, actorUserId: string, requestId: string): Promise<BulkRevokeOutcome>;
  revokeProviderGrantBackedConsent(input: {
    userId: string;
    clientId: string;
    consentId: string;
    resource: string;
    scopeHash: string;
    grantId: string;
    actorUserId: string;
    requestId: string;
  }): Promise<RevokeOutcome>;
  revokeUserAuthorization(input: {
    userId: string;
    actorUserId: string;
    requestId: string;
  }): Promise<BulkRevokeOutcome>;
  verifyTokenProps(props: OAuthTokenProps, scopes: readonly string[]): Promise<AuthContext>;
  enqueueJob(input: {
    type: string;
    idempotencyKey: string;
    targetUserId?: string | null;
    targetClientId?: string | null;
    payload: unknown;
    requestId: string;
  }): Promise<void>;
  claimJobs(limit: number, leaseSeconds: number): Promise<AuthJobRow[]>;
  finishJob(jobId: string, leaseId: string, result: "succeeded" | "failed", maxAttempts: number): Promise<void>;
  consumeRateLimits(keys: readonly string[], limit: number, windowSeconds: number): Promise<boolean>;
  optimizeStorage(): Promise<void>;
  createOtpChallenge(input: CreateOtpInput): Promise<CreatedOtpChallenge>;
  createOrReuseLoginOtpChallenge(input: LoginOtpInput): Promise<LoginOtpChallengeResult>;
  createOrReuseUserOtpChallenge(input: UserOtpInput): Promise<LoginOtpChallengeResult>;
  resendOtpChallenge(input: {
    id: string;
    purpose: string;
    resendDelaySeconds: number;
    secrets: CryptoSecrets;
    ttlSeconds: number;
  }): Promise<ResendOtpResult>;
  verifyOtpChallenge(input: VerifyOtpInput): Promise<VerifiedOtp | null>;
  beginPendingAuthorization(input: PendingAuthorizationInput): Promise<PendingAuthorizationClaim>;
  completePendingAuthorization(pendingId: string, leaseId: string): Promise<boolean>;
  failPendingAuthorization(pendingId: string, leaseId: string): Promise<boolean>;
  cleanupExpired(): Promise<void>;
}

export interface CryptoSecrets {
  OTP_PEPPER_CURRENT: string;
  OTP_PEPPER_CURRENT_VERSION: string;
  OTP_SUBJECT_ENCRYPTION_KEY_CURRENT: string;
  OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION: string;
  EMAIL_HASH_KEY_CURRENT: string;
}

export interface CreateOtpInput {
  purpose: string;
  email: string;
  userId?: string | null;
  bootstrapStateId?: string | null;
  recoveryAttemptId?: string | null;
  recoveryConsumeId?: string | null;
  ttlSeconds: number;
  maxAttempts: number;
  resendDelaySeconds?: number;
  secrets: CryptoSecrets;
}

export interface LoginOtpInput {
  userId: string;
  ttlSeconds: number;
  maxAttempts: number;
  resendDelaySeconds: number;
  secrets: CryptoSecrets;
}

export interface UserOtpInput extends LoginOtpInput {
  purpose: string;
}

export interface CreatedOtpChallenge {
  id: string;
  code: string;
  resendAfter: string;
  subjectId: string;
  ttlSeconds: number;
}

export interface VerifyOtpInput {
  id: string;
  code: string;
  secrets: CryptoSecrets;
}

export interface VerifiedOtp {
  id: string;
  subjectId: string;
  purpose: string;
  email: string;
  userId: string | null;
  bootstrapStateId: string | null;
  recoveryAttemptId: string | null;
  recoveryConsumeId: string | null;
}

export type ResendOtpResult =
  | {
      state: "resent";
      id: string;
      code: string;
      email: string;
      resendAfter: string;
      ttlSeconds: number;
      userId: string | null;
    }
  | { state: "too_early"; retryAfterSeconds: number; resendAfter: string }
  | { state: "invalid" };

export type LoginOtpChallengeResult =
  | (CreatedOtpChallenge & { state: "created" })
  | {
      state: "existing";
      id: string;
      resendAfter: string;
      subjectId: string;
      ttlSeconds: number;
    };

export interface PendingAuthorizationInput {
  pendingId: string;
  sessionIdHash: string;
  userId: string;
  clientId: string;
  redirectUri: string;
  resource: string;
  scopeHash: string;
  csrfHash: string;
  payloadDigest: string;
  leaseSeconds: number;
}

export type PendingAuthorizationClaim =
  | { state: "acquired"; leaseId: string }
  | { state: "completed" | "busy"; leaseId: null };

export function createAuthRepository(env: AuthTursoEnv): AuthRepository {
  return createAuthRepositoryFromDb(createAuthDb(env));
}

async function createOrReuseUserOtpChallenge(db: AuthDb, input: UserOtpInput): Promise<LoginOtpChallengeResult> {
  const now = new Date();
  const nowIso = now.toISOString();
  let result: LoginOtpChallengeResult | null = null;
  await db.withWriteTransaction(async (tx) => {
    const existing = await tx.get<{
      id: string;
      subject_id: string;
      expires_at: string;
      resend_after: string;
    }>(
      `SELECT otp_challenges.id, otp_challenges.subject_id, otp_challenges.expires_at, otp_challenges.resend_after
       FROM otp_subjects
       JOIN otp_challenges ON otp_challenges.subject_id = otp_subjects.subject_id
       WHERE otp_subjects.user_id = ?
         AND otp_subjects.purpose = ?
         AND otp_challenges.purpose = ?
         AND otp_challenges.redeemed_at IS NULL
         AND otp_challenges.attempts < otp_challenges.max_attempts
         AND otp_challenges.expires_at > ?
         AND otp_subjects.expires_at > ?
         AND otp_challenges.resend_after IS NOT NULL
       ORDER BY otp_challenges.created_at DESC
       LIMIT 1`,
      [input.userId, input.purpose, input.purpose, nowIso, nowIso]
    );
    if (existing) {
      result = {
        id: existing.id,
        resendAfter: existing.resend_after,
        state: "existing",
        subjectId: existing.subject_id,
        ttlSeconds: Math.max(1, Math.ceil((Date.parse(existing.expires_at) - now.getTime()) / 1000))
      };
      return;
    }

    const code = generateOtpCode();
    const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000).toISOString();
    const resendAfter = new Date(now.getTime() + input.resendDelaySeconds * 1000).toISOString();
    const subjectId = crypto.randomUUID();
    const challengeId = crypto.randomUUID();
    const codeHash = await hmacHex(input.secrets.OTP_PEPPER_CURRENT, `${challengeId}:${code}`);
    await tx.run(
      `INSERT INTO otp_subjects
        (subject_id, purpose, user_id, encrypted_email,
         bootstrap_state_id, recovery_attempt_id, recovery_consume_id, expires_at, created_at)
       VALUES (?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)`,
      [subjectId, input.purpose, input.userId, expiresAt, nowIso]
    );
    await tx.run(
      `INSERT INTO otp_challenges
        (id, subject_id, purpose, code_hash, pepper_version, expires_at, attempts,
         max_attempts, redeemed_at, resend_after, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, NULL, ?, ?)`,
      [
        challengeId,
        subjectId,
        input.purpose,
        codeHash,
        input.secrets.OTP_PEPPER_CURRENT_VERSION,
        expiresAt,
        input.maxAttempts,
        resendAfter,
        nowIso
      ]
    );
    result = {
      code,
      id: challengeId,
      resendAfter,
      state: "created",
      subjectId,
      ttlSeconds: input.ttlSeconds
    };
  });
  if (!result) {
    throw new Error("User OTP challenge could not be created");
  }
  return result;
}

export function createAuthRepositoryFromDb(db: AuthDb): AuthRepository {
  return {
    assertSchema() {
      return assertAuthSchema(db);
    },
    async findUserByEmail(email) {
      return db.get<UserRow>("SELECT * FROM users WHERE email = ? LIMIT 1", [normalizeEmail(email)]);
    },
    async findUserById(userId) {
      return db.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
    },
    async listUsers() {
      const defaultGrantTtlSeconds = await getDefaultGrantTtlSecondsFromDb(db);
      const rows = await db.all<
        UserRow & {
          grant_ttl_override: number;
          grant_ttl_seconds: number | null;
          permission: string | null;
        }
      >(
        `SELECT users.*,
                CASE WHEN user_oauth_policies.user_id IS NULL THEN 0 ELSE 1 END AS grant_ttl_override,
                user_oauth_policies.grant_ttl_seconds,
                user_permissions.permission
         FROM users
         LEFT JOIN user_oauth_policies ON user_oauth_policies.user_id = users.id
         LEFT JOIN user_permissions ON user_permissions.user_id = users.id
         ORDER BY users.email, user_permissions.permission`
      );
      const users = new Map<string, AdminUserRow>();
      for (const row of rows) {
        let user = users.get(row.id);
        if (!user) {
          user = {
            authz_version: row.authz_version,
            created_at: row.created_at,
            effective_grant_ttl_seconds: row.grant_ttl_override ? row.grant_ttl_seconds : defaultGrantTtlSeconds,
            email: row.email,
            grant_ttl_override: row.grant_ttl_override === 1,
            grant_ttl_seconds: row.grant_ttl_seconds,
            id: row.id,
            permissions: [],
            status: row.status,
            updated_at: row.updated_at
          };
          users.set(row.id, user);
        }
        if (row.permission) {
          user.permissions.push(row.permission);
        }
      }
      return [...users.values()];
    },
    getDefaultGrantTtlSeconds() {
      return getDefaultGrantTtlSecondsFromDb(db);
    },
    getEffectiveGrantTtlSeconds(userId) {
      return getEffectiveGrantTtlSecondsFromDb(db, userId);
    },
    async setDefaultGrantTtlSeconds(ttlSeconds, actorUserId, requestId) {
      const now = new Date();
      const nowIso = now.toISOString();
      const expiresAt = expiresAtFromTtl(now, ttlSeconds);
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `INSERT INTO auth_settings (key, value_json, updated_at, updated_by)
           VALUES ('default_grant_ttl_seconds', ?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET
             value_json = excluded.value_json,
             updated_at = excluded.updated_at,
             updated_by = excluded.updated_by`,
          [JSON.stringify(ttlSeconds), nowIso, actorUserId]
        );
        await tx.run(
          `UPDATE oauth_consents
           SET expires_at = ?
           WHERE NOT EXISTS (
               SELECT 1 FROM user_oauth_policies WHERE user_oauth_policies.user_id = oauth_consents.user_id
             )`,
          [expiresAt]
        );
        await insertAudit(tx, {
          actorUserId,
          event: "oauth.default_grant_timeout.updated",
          metadata: { ttlSeconds },
          requestId,
          result: "success"
        });
      });
    },
    async setUserGrantTtlSeconds(userId, ttlSeconds, actorUserId, requestId) {
      return setUserGrantTimeoutOverride(db, userId, ttlSeconds, actorUserId, requestId);
    },
    async clearUserGrantTtlSeconds(userId, actorUserId, requestId) {
      const defaultGrantTtlSeconds = await getDefaultGrantTtlSecondsFromDb(db);
      const now = new Date();
      const nowIso = now.toISOString();
      const expiresAt = expiresAtFromTtl(now, defaultGrantTtlSeconds);
      let outcome: RevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const user = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
        if (user) {
          await tx.run("DELETE FROM user_oauth_policies WHERE user_id = ?", [userId]);
          await tx.run("UPDATE oauth_consents SET expires_at = ? WHERE user_id = ?", [expiresAt, userId]);
          outcome = "changed";
        }
        await insertAudit(tx, {
          actorUserId,
          event: "oauth.user_grant_timeout.cleared",
          metadata: { defaultGrantTtlSeconds, outcome },
          requestId,
          result: outcome === "changed" ? "success" : "failure",
          targetUserId: userId
        });
      });
      return outcome;
    },
    listSessions(limit = 100) {
      const now = new Date().toISOString();
      return db.all<SessionRow>(
        `SELECT
           login_sessions.id_hash,
           login_sessions.user_id,
           users.email AS user_email,
           login_sessions.created_at,
           login_sessions.expires_at,
           login_sessions.absolute_expires_at,
           login_sessions.idle_expires_at,
           login_sessions.last_seen_at,
           login_sessions.last_touched_at,
           login_sessions.revoked_at,
           login_sessions.admin_step_up_at,
           login_sessions.ip_prefix,
           login_sessions.user_agent_hash
          FROM login_sessions
          JOIN users ON users.id = login_sessions.user_id
          WHERE login_sessions.revoked_at IS NULL
            AND login_sessions.idle_expires_at > ?
            AND login_sessions.absolute_expires_at > ?
          ORDER BY login_sessions.created_at DESC
          LIMIT ?`,
        [now, now, boundedLimit(limit)]
      );
    },
    listConsents(limit = 100) {
      return db.all<AdminConsentRow>(
        `SELECT oauth_consents.*, users.email AS user_email
         FROM oauth_consents
         JOIN users ON users.id = oauth_consents.user_id
         ORDER BY oauth_consents.granted_at DESC
         LIMIT ?`,
        [boundedLimit(limit)]
      );
    },
    listAuditLogs(limit = 200) {
      return db.all<AuditLogRow>(
        `SELECT id, actor_user_id, target_user_id, event, result, request_id,
                ip_prefix, user_agent_hash, metadata_json, created_at
         FROM auth_audit_logs
         ORDER BY created_at DESC
         LIMIT ?`,
        [boundedLimit(limit)]
      );
    },
    listJobs(limit = 100) {
      return db.all<AuthJobRow>(
        `SELECT *
         FROM auth_jobs
         ORDER BY created_at DESC
         LIMIT ?`,
        [boundedLimit(limit)]
      );
    },
    async deleteUserAccount(userId) {
      let deleted = false;
      await db.withWriteTransaction(async (tx) => {
        const user = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
        if (!user) {
          return;
        }
        await tx.run("DELETE FROM pending_authorization_redeems WHERE user_id = ?", [userId]);
        await tx.run("DELETE FROM auth_jobs WHERE target_user_id = ?", [userId]);
        await tx.run("DELETE FROM auth_audit_logs WHERE actor_user_id = ? OR target_user_id = ?", [userId, userId]);
        await tx.run("UPDATE auth_settings SET updated_by = NULL WHERE updated_by = ?", [userId]);
        await tx.run("UPDATE bootstrap_state SET consumed_by = NULL WHERE consumed_by = ?", [userId]);
        await tx.run("DELETE FROM otp_subjects WHERE user_id = ?", [userId]);
        await tx.run("DELETE FROM recovery_consumes WHERE email = ?", [user.email]);
        await tx.run("DELETE FROM recovery_attempts WHERE email = ?", [user.email]);
        await tx.run("DELETE FROM oauth_consents WHERE user_id = ?", [userId]);
        await tx.run("DELETE FROM login_sessions WHERE user_id = ?", [userId]);
        await tx.run("DELETE FROM user_oauth_policies WHERE user_id = ?", [userId]);
        await tx.run("DELETE FROM user_permissions WHERE user_id = ?", [userId]);
        await tx.run("DELETE FROM users WHERE id = ?", [userId]);
        deleted = true;
      });
      return deleted;
    },
    async createUser(email, permissions, actorUserId, requestId) {
      const normalizedPermissions = assertKnownPermissions(permissions);
      const now = new Date().toISOString();
      const user: UserRow = {
        authz_version: 1,
        created_at: now,
        email: normalizeEmail(email),
        id: crypto.randomUUID(),
        status: "active",
        updated_at: now
      };
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `INSERT INTO users (id, email, status, authz_version, created_at, updated_at)
           VALUES (?, ?, 'active', 1, ?, ?)`,
          [user.id, user.email, now, now]
        );
        for (const permission of normalizedPermissions) {
          await tx.run(
            `INSERT INTO user_permissions (user_id, permission, granted_at, granted_by)
             VALUES (?, ?, ?, ?)`,
            [user.id, permission, now, actorUserId]
          );
        }
        await insertAudit(tx, {
          actorUserId,
          event: "user.created",
          result: "success",
          targetUserId: user.id,
          requestId,
          after: { email: user.email, permissions: normalizedPermissions }
        });
      });
      return user;
    },
    async setUserState(userId, status, permissions, actorUserId, requestId) {
      const normalized = assertKnownPermissions(permissions);
      const now = new Date().toISOString();
      await db.withWriteTransaction(async (tx) => {
        const before = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
        if (!before) {
          throw new Error("User not found");
        }
        const beforePermissions = await tx.all<{ permission: string }>(
          "SELECT permission FROM user_permissions WHERE user_id = ?",
          [userId]
        );
        const wasActiveAdmin =
          before.status === "active" && beforePermissions.some((row) => row.permission === ADMIN_PERMISSION);
        const willBeActiveAdmin = status === "active" && normalized.includes(ADMIN_PERMISSION);
        if (wasActiveAdmin && !willBeActiveAdmin) {
          const adminCount = await tx.get<{ count: number }>(
            `SELECT COUNT(*) AS count
             FROM users
             JOIN user_permissions ON user_permissions.user_id = users.id
             WHERE users.status = 'active'
               AND users.id <> ?
               AND user_permissions.permission = ?`,
            [userId, ADMIN_PERMISSION]
          );
          if (Number(adminCount?.count ?? 0) < 1) {
            throw new Error("Cannot remove the last active admin");
          }
        }
        await tx.run(
          `UPDATE users
           SET status = ?, authz_version = authz_version + 1, updated_at = ?
           WHERE id = ?`,
          [status, now, userId]
        );
        await tx.run("DELETE FROM user_permissions WHERE user_id = ?", [userId]);
        for (const permission of normalized) {
          await tx.run(
            `INSERT INTO user_permissions (user_id, permission, granted_at, granted_by)
             VALUES (?, ?, ?, ?)`,
            [userId, permission, now, actorUserId]
          );
        }
        await tx.run(
          `UPDATE login_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ?`,
          [now, userId]
        );
          await tx.run("DELETE FROM oauth_consents WHERE user_id = ?", [userId]);
        await tx.run(
            `INSERT OR IGNORE INTO auth_jobs
              (job_id, type, idempotency_key, status, target_user_id, target_client_id, payload_json,
               attempts, next_attempt_at, lease_expires_at, request_id, created_at, updated_at)
             VALUES (?, 'revoke_user_grants', ?, 'pending', ?, NULL, ?, 0, ?, NULL, ?, ?, ?)`,
          [
            crypto.randomUUID(),
            `revoke-user-grants:${userId}:${requestId}`,
            userId,
            JSON.stringify({ userId }),
            now,
            requestId,
            now,
            now
          ]
        );
        await insertAudit(tx, {
          actorUserId,
          event: "user.state.updated",
          result: "success",
          targetUserId: userId,
          requestId,
          before,
          after: { status, permissions: normalized }
        });
      });
    },
    bulkUpdateUsers(input) {
      return bulkUpdateUsers(db, input);
    },
    async createSession(input) {
      const token = randomBase64Url(32);
      const idHash = await sha256Hex(token);
      const now = new Date();
      const nowIso = now.toISOString();
      const absoluteExpiresAt = new Date(now.getTime() + input.absoluteTtlSeconds * 1000).toISOString();
      const idleExpiresAt = new Date(now.getTime() + input.idleTtlSeconds * 1000).toISOString();
      await db.run(
        `INSERT INTO login_sessions
          (id_hash, user_id, created_at, expires_at, absolute_expires_at, idle_expires_at,
           last_seen_at, last_touched_at, revoked_at, admin_step_up_at, ip_prefix, user_agent_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)`,
        [
          idHash,
          input.userId,
          nowIso,
          absoluteExpiresAt,
          absoluteExpiresAt,
          idleExpiresAt,
          nowIso,
          nowIso,
          input.ipPrefix ?? null,
          input.userAgentHash ?? null
        ]
      );
      return token;
    },
    async getSession(token) {
      if (!token) {
        return null;
      }
      return getSessionByHash(db, await sha256Hex(token));
    },
    async touchSessionAfterSafeValidation(sessionIdHash, idleTtlSeconds, touchIntervalSeconds) {
      const session = await getSessionByHash(db, sessionIdHash);
      if (!session) {
        return null;
      }
      const now = new Date();
      const nowIso = now.toISOString();
      const touchThreshold = new Date(now.getTime() - touchIntervalSeconds * 1000).toISOString();
      const nextIdle = new Date(now.getTime() + idleTtlSeconds * 1000);
      const absolute = new Date(session.absoluteExpiresAt);
      const nextIdleIso = new Date(Math.min(nextIdle.getTime(), absolute.getTime())).toISOString();
      const touched = await db.get<{ id_hash: string }>(
        `UPDATE login_sessions
         SET idle_expires_at = ?,
             last_seen_at = ?,
             last_touched_at = ?
         WHERE id_hash = ?
           AND revoked_at IS NULL
           AND idle_expires_at > ?
           AND absolute_expires_at > ?
           AND last_touched_at <= ?
         RETURNING id_hash`,
        [nextIdleIso, nowIso, nowIso, sessionIdHash, nowIso, nowIso, touchThreshold]
      );
      if (touched) {
        return getSessionByHash(db, sessionIdHash);
      }
      return getSessionByHash(db, sessionIdHash);
    },
    async revokeSessionByHash(sessionIdHash, actorUserId, requestId) {
      const now = new Date().toISOString();
      let outcome: RevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const before = await tx.get<SessionRow>("SELECT * FROM login_sessions WHERE id_hash = ? LIMIT 1", [sessionIdHash]);
        if (!before) {
          outcome = "not_found";
        } else if (before.revoked_at) {
          outcome = "already_revoked";
        } else {
          const updated = await tx.get<{ id_hash: string }>(
            `UPDATE login_sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL RETURNING id_hash`,
            [now, sessionIdHash]
          );
          outcome = updated ? "changed" : "already_revoked";
        }
        await insertAudit(tx, {
          actorUserId,
          event: "session.revoked",
          result: outcome === "changed" ? "success" : outcome === "not_found" ? "failure" : "denied",
          requestId,
          metadata: { outcome, sessionIdHash }
        });
      });
      return outcome;
    },
    async revokeUserSessions(userId, actorUserId, requestId) {
      const now = new Date().toISOString();
      let outcome: BulkRevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const user = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
        if (!user) {
          outcome = "not_found";
        } else {
          const active = await tx.get<{ count: number }>(
            "SELECT COUNT(*) AS count FROM login_sessions WHERE user_id = ? AND revoked_at IS NULL",
            [userId]
          );
          if (Number(active?.count ?? 0) < 1) {
            outcome = "no_active_targets";
          } else {
            await tx.run("UPDATE login_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", [
              now,
              userId
            ]);
            outcome = "changed";
          }
        }
        await insertAudit(tx, {
          actorUserId,
          event: "sessions.revoked",
          result: outcome === "changed" ? "success" : outcome === "not_found" ? "failure" : "denied",
          requestId,
          targetUserId: userId,
          metadata: { outcome }
        });
      });
      return outcome;
    },
    async markStepUp(sessionIdHash, actorUserId, requestId) {
      const now = new Date().toISOString();
      let outcome: RevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const session = await tx.get<SessionRow>("SELECT * FROM login_sessions WHERE id_hash = ? LIMIT 1", [sessionIdHash]);
        if (!session) {
          outcome = "not_found";
        } else if (session.revoked_at) {
          outcome = "already_revoked";
        } else {
          const updated = await tx.get<{ id_hash: string }>(
            "UPDATE login_sessions SET admin_step_up_at = ? WHERE id_hash = ? AND revoked_at IS NULL RETURNING id_hash",
            [now, sessionIdHash]
          );
          outcome = updated ? "changed" : "already_revoked";
        }
        await insertAudit(tx, {
          actorUserId,
          event: "admin.step_up",
          result: outcome === "changed" ? "success" : outcome === "not_found" ? "failure" : "denied",
          requestId,
          metadata: { outcome, sessionIdHash }
        });
      });
      return outcome;
    },
    async listPermissions(userId) {
      const rows = await db.all<{ permission: string }>(
        "SELECT permission FROM user_permissions WHERE user_id = ? ORDER BY permission",
        [userId]
      );
      return rows.map((row) => row.permission);
    },
    async hasActiveAdmin() {
      const row = await db.get<{ count: number }>(
        `SELECT COUNT(*) AS count
         FROM users
         JOIN user_permissions ON user_permissions.user_id = users.id
         WHERE users.status = 'active' AND user_permissions.permission = ?`,
        [ADMIN_PERMISSION]
      );
      return Number(row?.count ?? 0) > 0;
    },
    async consumeInitialBootstrap(userId, requestId) {
      const now = new Date().toISOString();
      let consumed = false;
      await db.withWriteTransaction(async (tx) => {
        const updated = await tx.get<{ id: string }>(
          `UPDATE bootstrap_state
           SET status = 'consumed', consumed_by = ?, consumed_at = ?, updated_at = ?
           WHERE id = 'initial' AND status = 'open'
           RETURNING id`,
          [userId, now, now]
        );
        consumed = Boolean(updated);
        if (consumed) {
          await insertAudit(tx, {
            actorUserId: userId,
            event: "bootstrap.initial.consumed",
            result: "success",
            requestId
          });
        }
      });
      return consumed;
    },
    async consumeInitialBootstrapAndCreateAdmin(email, requestId) {
      const normalizedEmail = normalizeEmail(email);
      const now = new Date().toISOString();
      let user: UserRow | null = null;
      await db.withWriteTransaction(async (tx) => {
        const locked = await tx.get<{ id: string }>(
          `UPDATE bootstrap_state
           SET status = 'consumed', updated_at = ?
           WHERE id = 'initial' AND mode = 'initial' AND status = 'open'
           RETURNING id`,
          [now]
        );
        if (!locked) {
          return;
        }
        user = await upsertAdminUser(tx, normalizedEmail, null, requestId, now);
        await tx.run(
          `UPDATE bootstrap_state
           SET consumed_by = ?, consumed_at = ?, updated_at = ?
           WHERE id = 'initial'`,
          [user.id, now, now]
        );
        await insertAudit(tx, {
          actorUserId: user.id,
          event: "bootstrap.initial.consumed",
          result: "success",
          requestId,
          targetUserId: user.id
        });
      });
      return user;
    },
    async createRecoveryAttempt(email, ttlSeconds, requestId) {
      const normalizedEmail = normalizeEmail(email);
      const now = new Date();
      const attemptId = `recovery_attempt:${crypto.randomUUID()}`;
      const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `INSERT INTO recovery_attempts
            (attempt_id, email, status, created_at, updated_at, expires_at, completed_at)
           VALUES (?, ?, 'notification_pending', ?, ?, ?, NULL)`,
          [attemptId, normalizedEmail, now.toISOString(), now.toISOString(), expiresAt]
        );
        await insertAudit(tx, {
          event: "recovery.attempt.created",
          metadata: { attemptId },
          requestId,
          result: "success"
        });
      });
      return { attemptId, expiresAt };
    },
    async markRecoveryNotificationFailed(attemptId, requestId) {
      const now = new Date().toISOString();
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `UPDATE recovery_attempts
           SET status = 'notification_failed', updated_at = ?
           WHERE attempt_id = ? AND status = 'notification_pending'`,
          [now, attemptId]
        );
        await insertAudit(tx, {
          event: "recovery.notification.failed",
          metadata: { attemptId },
          requestId,
          result: "failure"
        });
      });
    },
    async markRecoveryNotificationSucceeded(attemptId, requestId) {
      const now = new Date().toISOString();
      let result: { consumeId: string; email: string } | null = null;
      await db.withWriteTransaction(async (tx) => {
        const attempt = await tx.get<{ attempt_id: string; email: string; expires_at: string }>(
          `UPDATE recovery_attempts
           SET status = 'notification_succeeded', updated_at = ?
           WHERE attempt_id = ?
             AND status = 'notification_pending'
             AND expires_at > ?
           RETURNING attempt_id, email, expires_at`,
          [now, attemptId, now]
        );
        if (!attempt) {
          return;
        }
        const consumeId = `recovery_consume:${crypto.randomUUID()}`;
        await tx.run(
          `INSERT INTO recovery_consumes
            (consume_id, attempt_id, email, status, created_at, updated_at, expires_at, consumed_at)
           VALUES (?, ?, ?, 'pending', ?, ?, ?, NULL)`,
          [consumeId, attempt.attempt_id, attempt.email, now, now, attempt.expires_at]
        );
        await insertAudit(tx, {
          event: "recovery.notification.succeeded",
          metadata: { attemptId, consumeId },
          requestId,
          result: "success"
        });
        result = { consumeId, email: attempt.email };
      });
      return result;
    },
    async markRecoveryOtpSendFailed(attemptId, consumeId, requestId) {
      const now = new Date().toISOString();
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `UPDATE recovery_consumes
           SET status = 'failed', updated_at = ?
           WHERE consume_id = ? AND attempt_id = ? AND status = 'pending'`,
          [now, consumeId, attemptId]
        );
        await tx.run(
          `UPDATE recovery_attempts
           SET status = 'otp_send_failed', updated_at = ?
           WHERE attempt_id = ? AND status = 'notification_succeeded'`,
          [now, attemptId]
        );
        await insertAudit(tx, {
          event: "recovery.otp_send.failed",
          metadata: { attemptId, consumeId },
          requestId,
          result: "failure"
        });
      });
    },
    async consumeRecoveryAttemptAndCreateAdminAndSession(email, attemptId, consumeId, idleTtlSeconds, absoluteTtlSeconds, requestId) {
      const normalizedEmail = normalizeEmail(email);
      const nowDate = new Date();
      const now = nowDate.toISOString();
      const sessionToken = randomBase64Url(32);
      const sessionIdHash = await sha256Hex(sessionToken);
      const absoluteExpiresAt = new Date(nowDate.getTime() + absoluteTtlSeconds * 1000).toISOString();
      const idleExpiresAt = new Date(nowDate.getTime() + idleTtlSeconds * 1000).toISOString();
      let user: UserRow | null = null;
      await db.withWriteTransaction(async (tx) => {
        const locked = await tx.get<{ consume_id: string }>(
          `UPDATE recovery_consumes
           SET status = 'consumed', consumed_at = ?, updated_at = ?
           WHERE consume_id = ?
             AND attempt_id = ?
             AND email = ?
             AND status = 'pending'
             AND expires_at > ?
             AND EXISTS (
               SELECT 1
               FROM recovery_attempts
               WHERE recovery_attempts.attempt_id = recovery_consumes.attempt_id
                 AND recovery_attempts.status = 'notification_succeeded'
                 AND recovery_attempts.expires_at > ?
             )
           RETURNING consume_id`,
          [now, now, consumeId, attemptId, normalizedEmail, now, now]
        );
        if (!locked) {
          return;
        }
        user = await upsertAdminUser(tx, normalizedEmail, null, requestId, now);
        await tx.run(
          `INSERT INTO login_sessions
            (id_hash, user_id, created_at, expires_at, absolute_expires_at, idle_expires_at,
             last_seen_at, last_touched_at, revoked_at, admin_step_up_at, ip_prefix, user_agent_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)`,
          [sessionIdHash, user.id, now, absoluteExpiresAt, absoluteExpiresAt, idleExpiresAt, now, now]
        );
        await tx.run(
          `UPDATE recovery_attempts
           SET status = 'completed', completed_at = ?, updated_at = ?
           WHERE attempt_id = ?`,
          [now, now, attemptId]
        );
        await insertAudit(tx, {
          actorUserId: user.id,
          event: "recovery.consumed",
          metadata: { attemptId, consumeId },
          requestId,
          result: "success",
          targetUserId: user.id
        });
      });
      return user ? { sessionToken, user } : null;
    },
    async markRecoveryStateChangeFailed(attemptId, requestId) {
      const now = new Date().toISOString();
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `UPDATE recovery_attempts
           SET status = 'state_change_failed', updated_at = ?
           WHERE attempt_id = ?`,
          [now, attemptId]
        );
        await insertAudit(tx, {
          event: "recovery.state_change.failed",
          metadata: { attemptId },
          requestId,
          result: "failure"
        });
      });
    },
    writeAudit(input) {
      return insertAudit(db, input);
    },
    async createOrUpdateClientPolicy(input) {
      const now = new Date().toISOString();
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `INSERT INTO oauth_client_policies
            (client_id, client_version, metadata_snapshot_json, allowed_redirect_uris_json,
             first_seen_at, last_seen_at)
           VALUES (?, 1, ?, ?, ?, ?)
           ON CONFLICT(client_id) DO UPDATE SET
             client_version = oauth_client_policies.client_version + 1,
             metadata_snapshot_json = excluded.metadata_snapshot_json,
             allowed_redirect_uris_json = excluded.allowed_redirect_uris_json,
             last_seen_at = excluded.last_seen_at`,
          [
            input.clientId,
            JSON.stringify(input.metadata),
            JSON.stringify(input.redirectUris),
            now,
            now
          ]
        );
        await insertAudit(tx, {
          actorUserId: null,
          event: "client.policy.upserted",
          result: "success",
          requestId: input.requestId,
          metadata: { clientId: input.clientId }
        });
      });
    },
    getClientPolicy(clientId) {
      return db.get<ClientPolicyRow>("SELECT * FROM oauth_client_policies WHERE client_id = ? LIMIT 1", [clientId]);
    },
    listClientPolicies() {
      return db.all<ClientPolicyRow>("SELECT * FROM oauth_client_policies ORDER BY client_id");
    },
    async revokeClient(clientId, actorUserId, requestId) {
      const now = new Date().toISOString();
      let outcome: RevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const policy = await tx.get<ClientPolicyRow>("SELECT * FROM oauth_client_policies WHERE client_id = ? LIMIT 1", [
          clientId
        ]);
        if (!policy) {
          outcome = "not_found";
        } else {
          await tx.run("DELETE FROM oauth_consents WHERE client_id = ?", [clientId]);
          await tx.run("DELETE FROM oauth_client_policies WHERE client_id = ?", [clientId]);
          await enqueueJobInTx(tx, {
            idempotencyKey: `delete-provider-client:${clientId}:${requestId}`,
            payload: { clientId },
            requestId,
            targetClientId: clientId,
            type: "delete_provider_client"
          });
          outcome = "changed";
        }
        await insertAudit(tx, {
          actorUserId,
          event: "client.deleted",
          result: outcome === "changed" ? "success" : outcome === "not_found" ? "failure" : "denied",
          requestId,
          metadata: { clientId, outcome }
        });
      });
      return outcome;
    },
    async saveConsent(input) {
      const now = new Date().toISOString();
      const canonicalScope = formatCanonicalScope(input.scopes);
      const scopeHash = await hashScope(input.scopes);
      const id = crypto.randomUUID();
      await db.run(
        `INSERT INTO oauth_consents
          (id, user_id, client_id, client_version, resource, canonical_scope, scope_hash,
           authz_version, client_snapshot_json, redirect_uri, granted_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          input.userId,
          input.clientId,
          input.clientVersion,
          input.resource,
          canonicalScope,
          scopeHash,
          input.authzVersion,
          JSON.stringify(input.clientSnapshot),
          input.redirectUri,
          now,
          input.expiresAt
        ]
      );
      const row = await db.get<ConsentRow>("SELECT * FROM oauth_consents WHERE id = ? LIMIT 1", [id]);
      if (!row) {
        throw new Error("Consent insert failed");
      }
      return row;
    },
    async getActiveConsent(input) {
      const scopeHash = await hashScope(input.scopes);
      return db.get<ConsentRow>(
        `SELECT * FROM oauth_consents
         WHERE user_id = ? AND client_id = ? AND resource = ? AND scope_hash = ?
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY granted_at DESC
         LIMIT 1`,
        [input.userId, input.clientId, input.resource, scopeHash, new Date().toISOString()]
      );
    },
    getConsentById(consentId) {
      return db.get<ConsentRow>("SELECT * FROM oauth_consents WHERE id = ? LIMIT 1", [consentId]);
    },
    async revokeConsent(consentId, actorUserId, requestId) {
      let outcome: RevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const before = await tx.get<ConsentRow>("SELECT * FROM oauth_consents WHERE id = ? LIMIT 1", [consentId]);
        if (!before) {
          outcome = "not_found";
        } else {
          await tx.run("DELETE FROM oauth_consents WHERE id = ?", [consentId]);
          outcome = "changed";
        }
        await insertAudit(tx, {
          actorUserId,
          event: "consent.deleted",
          result: outcome === "changed" ? "success" : outcome === "not_found" ? "failure" : "denied",
          requestId,
          metadata: { consentId, outcome }
        });
      });
      return outcome;
    },
    async revokeUserConsents(userId, actorUserId, requestId) {
      let outcome: BulkRevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const user = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
        if (!user) {
          outcome = "not_found";
        } else {
          const active = await tx.get<{ count: number }>("SELECT COUNT(*) AS count FROM oauth_consents WHERE user_id = ?", [
            userId
          ]);
          if (Number(active?.count ?? 0) < 1) {
            outcome = "no_active_targets";
          } else {
            await tx.run("DELETE FROM oauth_consents WHERE user_id = ?", [userId]);
            await enqueueJobInTx(tx, {
              idempotencyKey: `revoke-user-grants:${userId}:${requestId}`,
              payload: { userId },
              requestId,
              targetUserId: userId,
              type: "revoke_user_grants"
            });
            outcome = "changed";
          }
        }
        await insertAudit(tx, {
          actorUserId,
          event: "user.consents.deleted",
          requestId,
          result: outcome === "changed" ? "success" : outcome === "not_found" ? "failure" : "denied",
          targetUserId: userId,
          metadata: { outcome }
        });
      });
      return outcome;
    },
    async revokeProviderGrantBackedConsent(input) {
      let outcome: RevokeOutcome = "mismatch";
      await db.withWriteTransaction(async (tx) => {
        const existing = await tx.get<ConsentRow>("SELECT * FROM oauth_consents WHERE id = ? LIMIT 1", [
          input.consentId
        ]);
        if (!existing) {
          outcome = "not_found";
        } else {
          const deleted = await tx.get<ConsentRow>(
            `DELETE FROM oauth_consents
             WHERE id = ?
               AND user_id = ?
               AND client_id = ?
               AND resource = ?
               AND scope_hash = ?
             RETURNING *`,
            [input.consentId, input.userId, input.clientId, input.resource, input.scopeHash]
          );
          if (deleted) {
            await enqueueJobInTx(tx, {
              idempotencyKey: `revoke-provider-grant:${input.userId}:${input.grantId}:${input.requestId}`,
              payload: { grantId: input.grantId, userId: input.userId },
              requestId: input.requestId,
              targetClientId: input.clientId,
              targetUserId: input.userId,
              type: "revoke_provider_grant"
            });
            outcome = "changed";
          } else {
            outcome = "mismatch";
          }
        }
        await insertAudit(tx, {
          actorUserId: input.actorUserId,
          event: "provider.grant.revoke.requested",
          requestId: input.requestId,
          result: outcome === "changed" ? "queued" : outcome === "not_found" ? "failure" : "denied",
          targetUserId: input.userId,
          metadata: {
            clientId: input.clientId,
            consentId: input.consentId,
            grantId: input.grantId,
            outcome,
            resource: input.resource,
            scopeHash: input.scopeHash
          }
        });
      });
      return outcome;
    },
    async revokeUserAuthorization(input) {
      const now = new Date().toISOString();
      let outcome: BulkRevokeOutcome = "not_found";
      await db.withWriteTransaction(async (tx) => {
        const user = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [input.userId]);
        if (!user) {
          outcome = "not_found";
        } else {
          await tx.run(
            `UPDATE users
             SET authz_version = authz_version + 1, updated_at = ?
             WHERE id = ?`,
            [now, input.userId]
          );
          await tx.run("DELETE FROM oauth_consents WHERE user_id = ?", [input.userId]);
          await enqueueJobInTx(tx, {
            idempotencyKey: `revoke-user-authorization:${input.userId}:${input.requestId}`,
            payload: { userId: input.userId },
            requestId: input.requestId,
            targetUserId: input.userId,
            type: "revoke_user_grants"
          });
          outcome = "changed";
        }
        await insertAudit(tx, {
          actorUserId: input.actorUserId,
          event: "user.authorization.revoked",
          metadata: { outcome },
          requestId: input.requestId,
          result: outcome === "not_found" ? "failure" : outcome === "changed" ? "success" : "denied",
          targetUserId: input.userId
        });
      });
      return outcome;
    },
    async verifyTokenProps(props, scopes) {
      const user = await db.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [props.user_id]);
      if (!user || user.status !== "active" || user.authz_version !== props.authz_version) {
        throw new Error("User authorization state is no longer current");
      }
      const client = await db.get<ClientPolicyRow>(
        "SELECT * FROM oauth_client_policies WHERE client_id = ? LIMIT 1",
        [props.client_id]
      );
      if (!client || client.client_version !== props.client_version) {
        throw new Error("Client authorization state is no longer current");
      }
      const consent = await db.get<ConsentRow>("SELECT * FROM oauth_consents WHERE id = ? LIMIT 1", [
        props.consent_id
      ]);
      if (
        !consent ||
        consent.resource !== props.resource ||
        consent.client_id !== props.client_id ||
        consent.client_version !== props.client_version ||
        consent.authz_version !== props.authz_version ||
        consent.scope_hash !== props.scope_hash ||
        (consent.expires_at !== null && Date.parse(consent.expires_at) <= Date.now())
      ) {
        throw new Error("Consent authorization state is no longer current");
      }
      const permissionRows = await db.all<{ permission: string }>(
        "SELECT permission FROM user_permissions WHERE user_id = ? ORDER BY permission",
        [user.id]
      );
      const permissions = permissionRows.map((row) => row.permission);
      return {
        client: {
          id: client.client_id,
          version: client.client_version
        },
        consentId: consent.id,
        resource: props.resource,
        scopeHash: props.scope_hash,
        scopes: scopes as OAuthScope[],
        user: {
          authzVersion: user.authz_version,
          email: user.email,
          id: user.id,
          status: user.status
        },
        permissions
      } as AuthContext & { permissions: string[] };
    },
    async enqueueJob(input) {
      const now = new Date().toISOString();
      await db.run(
        `INSERT OR IGNORE INTO auth_jobs
          (job_id, type, idempotency_key, status, target_user_id, target_client_id, payload_json,
           attempts, next_attempt_at, lease_expires_at, request_id, created_at, updated_at)
         VALUES (?, ?, ?, 'pending', ?, ?, ?, 0, ?, NULL, ?, ?, ?)`,
        [
          crypto.randomUUID(),
          input.type,
          input.idempotencyKey,
          input.targetUserId ?? null,
          input.targetClientId ?? null,
          JSON.stringify(input.payload),
          now,
          input.requestId,
          now,
          now
        ]
      );
    },
    async claimJobs(limit, leaseSeconds) {
      const now = new Date();
      const nowIso = now.toISOString();
      const lease = new Date(now.getTime() + leaseSeconds * 1000).toISOString();
      const jobs: AuthJobRow[] = [];
      await db.withWriteTransaction(async (tx) => {
        const candidates = await tx.all<{ job_id: string }>(
          `SELECT job_id
           FROM auth_jobs
           WHERE (status = 'pending' AND next_attempt_at <= ?)
              OR (status = 'running' AND lease_expires_at <= ?)
           ORDER BY created_at
           LIMIT ?`,
          [nowIso, nowIso, boundedLimit(limit)]
        );
        for (const candidate of candidates) {
          const leaseId = crypto.randomUUID();
          const claimed = await tx.get<AuthJobRow>(
            `UPDATE auth_jobs
             SET status = 'running',
                 attempts = attempts + 1,
                 lease_expires_at = ?,
                 lease_id = ?,
                 updated_at = ?
             WHERE job_id = ?
               AND (
                 status = 'pending'
                 OR (status = 'running' AND lease_expires_at <= ?)
               )
             RETURNING *`,
            [lease, leaseId, nowIso, candidate.job_id, nowIso]
          );
          if (claimed) {
            jobs.push(claimed);
          }
        }
      });
      return jobs;
    },
    async finishJob(jobId, leaseId, result, maxAttempts) {
      const now = new Date();
      const nowIso = now.toISOString();
      if (result === "succeeded") {
        await db.withWriteTransaction(async (tx) => {
          const job = await tx.get<AuthJobRow>(
            `UPDATE auth_jobs
             SET status = 'succeeded',
                 lease_expires_at = NULL,
                 lease_id = NULL,
                 updated_at = ?
             WHERE job_id = ? AND status = 'running' AND lease_id = ?
             RETURNING *`,
            [nowIso, jobId, leaseId]
          );
          if (job) {
            await insertAudit(tx, {
              event: "auth_job.succeeded",
              metadata: { jobId, type: job.type },
              requestId: job.request_id,
              result: "success",
              targetUserId: job.target_user_id
            });
          }
        });
        return;
      }
      const existing = await db.get<{ attempts: number }>("SELECT attempts FROM auth_jobs WHERE job_id = ? AND lease_id = ? LIMIT 1", [
        jobId,
        leaseId
      ]);
      const attempts = Number(existing?.attempts ?? 1);
      const backoffSeconds = Math.min(3600, 30 * 2 ** Math.max(0, Math.min(attempts - 1, 6)));
      const jitter = crypto.getRandomValues(new Uint16Array(1));
      const jitterSeconds = (jitter[0] ?? 0) % 30;
      const nextAttempt = new Date(now.getTime() + (backoffSeconds + jitterSeconds) * 1000).toISOString();
      await db.withWriteTransaction(async (tx) => {
        const job = await tx.get<AuthJobRow>(
          `UPDATE auth_jobs
           SET status = CASE WHEN attempts >= ? THEN 'failed' ELSE 'pending' END,
               lease_expires_at = NULL,
               lease_id = NULL,
               next_attempt_at = ?,
               updated_at = ?
           WHERE job_id = ? AND status = 'running' AND lease_id = ?
           RETURNING *`,
          [Math.max(1, maxAttempts), nextAttempt, nowIso, jobId, leaseId]
        );
        if (job) {
          await insertAudit(tx, {
            event: job.status === "failed" ? "auth_job.failed" : "auth_job.retry_scheduled",
            metadata: { attempts: job.attempts, jobId, type: job.type },
            requestId: job.request_id,
            result: job.status === "failed" ? "failure" : "queued",
            targetUserId: job.target_user_id
          });
        }
      });
    },
    async consumeRateLimits(keys, limit, windowSeconds) {
      const nowSeconds = Math.floor(Date.now() / 1000);
      const windowStart = Math.floor(nowSeconds / windowSeconds) * windowSeconds;
      const expiresAt = new Date((windowStart + windowSeconds * 2) * 1000).toISOString();
      let allowed = true;
      await db.withWriteTransaction(async (tx) => {
        for (const key of keys) {
          await tx.run(
            `INSERT OR IGNORE INTO rate_limit_counters (key, window_start, count, expires_at)
             VALUES (?, ?, 0, ?)`,
            [key, windowStart, expiresAt]
          );
          const row = await tx.get<{ count: number }>(
            "SELECT count FROM rate_limit_counters WHERE key = ? AND window_start = ?",
            [key, windowStart]
          );
          if (Number(row?.count ?? 0) >= limit) {
            allowed = false;
            continue;
          }
          const consumed = await tx.get<{ key: string }>(
            `UPDATE rate_limit_counters
             SET count = count + 1, expires_at = ?
             WHERE key = ? AND window_start = ? AND count < ?
             RETURNING key`,
            [expiresAt, key, windowStart, limit]
          );
          if (!consumed) {
            allowed = false;
          }
        }
      });
      return allowed;
    },
    async createOtpChallenge(input) {
      const email = normalizeEmail(input.email);
      const code = generateOtpCode();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000).toISOString();
      const resendAfter = new Date(now.getTime() + (input.resendDelaySeconds ?? 60) * 1000).toISOString();
      const subjectId = crypto.randomUUID();
      const challengeId = crypto.randomUUID();
      const encryptedEmail = input.userId ? null : await encryptEmail(input.secrets, input.purpose, subjectId, email);
      const codeHash = await hmacHex(input.secrets.OTP_PEPPER_CURRENT, `${challengeId}:${code}`);
      await db.withWriteTransaction(async (tx) => {
        await tx.run(
          `INSERT INTO otp_subjects
            (subject_id, purpose, user_id, encrypted_email,
             bootstrap_state_id, recovery_attempt_id, recovery_consume_id, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            subjectId,
            input.purpose,
            input.userId ?? null,
            encryptedEmail,
            input.bootstrapStateId ?? null,
            input.recoveryAttemptId ?? null,
            input.recoveryConsumeId ?? null,
            expiresAt,
            now.toISOString()
          ]
        );
        await tx.run(
          `INSERT INTO otp_challenges
            (id, subject_id, purpose, code_hash, pepper_version, expires_at, attempts,
             max_attempts, redeemed_at, resend_after, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, ?, NULL, ?, ?)`,
          [
            challengeId,
            subjectId,
            input.purpose,
            codeHash,
            input.secrets.OTP_PEPPER_CURRENT_VERSION,
            expiresAt,
            input.maxAttempts,
            resendAfter,
            now.toISOString()
          ]
        );
      });
      return { code, id: challengeId, resendAfter, subjectId, ttlSeconds: input.ttlSeconds };
    },
    async createOrReuseLoginOtpChallenge(input) {
      return createOrReuseUserOtpChallenge(db, { ...input, purpose: "login" });
    },
    async createOrReuseUserOtpChallenge(input) {
      return createOrReuseUserOtpChallenge(db, input);
    },
    async resendOtpChallenge(input) {
      const row = await db.get<{
        id: string;
        subject_id: string;
        purpose: string;
        attempts: number;
        max_attempts: number;
        expires_at: string;
        redeemed_at: string | null;
        resend_after: string | null;
        user_id: string | null;
        encrypted_email: string | null;
        user_email: string | null;
        user_status: UserRow["status"] | null;
      }>(
        `SELECT otp_challenges.id, otp_challenges.subject_id, otp_challenges.purpose,
                otp_challenges.attempts, otp_challenges.max_attempts, otp_challenges.expires_at,
                otp_challenges.redeemed_at, otp_challenges.resend_after,
                otp_subjects.user_id, otp_subjects.encrypted_email,
                users.email AS user_email, users.status AS user_status
         FROM otp_challenges
         JOIN otp_subjects ON otp_subjects.subject_id = otp_challenges.subject_id
         LEFT JOIN users ON users.id = otp_subjects.user_id
         WHERE otp_challenges.id = ?
         LIMIT 1`,
        [input.id]
      );
      if (
        !row ||
        row.purpose !== input.purpose ||
        row.redeemed_at ||
        row.attempts >= row.max_attempts ||
        Date.parse(row.expires_at) <= Date.now()
      ) {
        return { state: "invalid" };
      }
      if (row.user_id && (row.user_status !== "active" || !row.user_email)) {
        return { state: "invalid" };
      }
      const resendAtMs = row.resend_after ? Date.parse(row.resend_after) : 0;
      if (Number.isFinite(resendAtMs) && resendAtMs > Date.now()) {
        return {
          resendAfter: row.resend_after as string,
          retryAfterSeconds: Math.max(1, Math.ceil((resendAtMs - Date.now()) / 1000)),
          state: "too_early"
        };
      }
      const email = row.user_id ? row.user_email : await decryptEmail(input.secrets, row.purpose, row.subject_id, row.encrypted_email);
      if (!email) {
        return { state: "invalid" };
      }
      const now = new Date();
      const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000).toISOString();
      const resendAfter = new Date(now.getTime() + input.resendDelaySeconds * 1000).toISOString();
      const code = generateOtpCode();
      const codeHash = await hmacHex(input.secrets.OTP_PEPPER_CURRENT, `${row.id}:${code}`);
      let updated = false;
      await db.withWriteTransaction(async (tx) => {
        const challenge = await tx.get<{ id: string }>(
          `UPDATE otp_challenges
           SET code_hash = ?, pepper_version = ?, expires_at = ?, attempts = 0, resend_after = ?
           WHERE id = ?
             AND redeemed_at IS NULL
             AND attempts < max_attempts
             AND expires_at > ?
             AND (resend_after IS NULL OR resend_after <= ?)
           RETURNING id`,
          [
            codeHash,
            input.secrets.OTP_PEPPER_CURRENT_VERSION,
            expiresAt,
            resendAfter,
            row.id,
            now.toISOString(),
            now.toISOString()
          ]
        );
        if (!challenge) {
          return;
        }
        await tx.run("UPDATE otp_subjects SET expires_at = ? WHERE subject_id = ?", [expiresAt, row.subject_id]);
        updated = true;
      });
      if (!updated) {
        return { state: "invalid" };
      }
      return {
        code,
        email,
        id: row.id,
        resendAfter,
        state: "resent",
        ttlSeconds: input.ttlSeconds,
        userId: row.user_id
      };
    },
    async verifyOtpChallenge(input) {
      const row = await db.get<{
        id: string;
        subject_id: string;
        purpose: string;
        code_hash: string;
        pepper_version: string;
        attempts: number;
        max_attempts: number;
        expires_at: string;
        redeemed_at: string | null;
        user_id: string | null;
        encrypted_email: string | null;
        bootstrap_state_id: string | null;
        recovery_attempt_id: string | null;
        recovery_consume_id: string | null;
      }>(
        `SELECT otp_challenges.*, otp_subjects.user_id, otp_subjects.encrypted_email, otp_subjects.bootstrap_state_id,
                otp_subjects.recovery_attempt_id, otp_subjects.recovery_consume_id
         FROM otp_challenges
         JOIN otp_subjects ON otp_subjects.subject_id = otp_challenges.subject_id
         WHERE otp_challenges.id = ?
         LIMIT 1`,
        [input.id]
      );
      if (
        !row ||
        row.redeemed_at ||
        row.attempts >= row.max_attempts ||
        Date.parse(row.expires_at) <= Date.now()
      ) {
        return null;
      }
      const pepper = selectCurrentSecret(
        row.pepper_version,
        input.secrets.OTP_PEPPER_CURRENT_VERSION,
        input.secrets.OTP_PEPPER_CURRENT
      );
      const expected = await hmacHex(pepper, `${row.id}:${input.code}`);
      const matched = timingSafeEqual(expected, row.code_hash);
      if (matched) {
        const now = new Date().toISOString();
        const redeemed = await db.get<{ id: string }>(
          `UPDATE otp_challenges
           SET redeemed_at = ?, attempts = attempts + 1
           WHERE id = ? AND redeemed_at IS NULL AND attempts = ? AND attempts < max_attempts
           RETURNING id`,
          [now, row.id, row.attempts]
        );
        if (!redeemed) {
          return null;
        }
        const email = row.user_id
          ? (await db.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [row.user_id]))?.email
          : await decryptEmail(input.secrets, row.purpose, row.subject_id, row.encrypted_email);
        if (!email) {
          return null;
        }
        return {
          bootstrapStateId: row.bootstrap_state_id,
          email,
          id: row.id,
          purpose: row.purpose,
          recoveryAttemptId: row.recovery_attempt_id,
          recoveryConsumeId: row.recovery_consume_id,
          subjectId: row.subject_id,
          userId: row.user_id
        };
      }
      await db.run(
        `UPDATE otp_challenges
         SET attempts = attempts + 1
         WHERE id = ? AND redeemed_at IS NULL AND attempts = ? AND attempts < max_attempts`,
        [row.id, row.attempts]
      );
      return null;
    },
    async beginPendingAuthorization(input) {
      const now = new Date().toISOString();
      const lease = new Date(Date.now() + input.leaseSeconds * 1000).toISOString();
      const leaseId = randomBase64Url(32);
      let result: PendingAuthorizationClaim = { leaseId: null, state: "busy" };
      await db.withWriteTransaction(async (tx) => {
        const inserted = await tx.get<{ pending_id: string }>(
          `INSERT INTO pending_authorization_redeems
            (pending_id, session_id_hash, user_id, client_id, redirect_uri, resource, scope_hash,
             csrf_hash, payload_digest, status, lease_id, lease_expires_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing', ?, ?, ?, ?)
           ON CONFLICT(pending_id) DO NOTHING
           RETURNING pending_id`,
          [
            input.pendingId,
            input.sessionIdHash,
            input.userId,
            input.clientId,
            input.redirectUri,
            input.resource,
            input.scopeHash,
            input.csrfHash,
            input.payloadDigest,
            leaseId,
            lease,
            now,
            now
          ]
        );
        if (inserted) {
          result = { leaseId, state: "acquired" };
          return;
        }
        const row = await tx.get<{
          status: string;
          lease_id: string;
          lease_expires_at: string;
          session_id_hash: string;
          user_id: string;
          client_id: string;
          redirect_uri: string;
          resource: string;
          scope_hash: string;
          csrf_hash: string;
          payload_digest: string;
        }>("SELECT * FROM pending_authorization_redeems WHERE pending_id = ? LIMIT 1", [input.pendingId]);
        if (!row || row.status === "failed") {
          result = { leaseId: null, state: "busy" };
          return;
        }
        if (
          row.session_id_hash !== input.sessionIdHash ||
          row.user_id !== input.userId ||
          row.client_id !== input.clientId ||
          row.redirect_uri !== input.redirectUri ||
          row.resource !== input.resource ||
          row.scope_hash !== input.scopeHash ||
          row.csrf_hash !== input.csrfHash ||
          row.payload_digest !== input.payloadDigest
        ) {
          result = { leaseId: null, state: "busy" };
          return;
        }
        if (row.status === "completed") {
          result = { leaseId: null, state: "completed" };
          return;
        }
        if (Date.parse(row.lease_expires_at) > Date.now()) {
          result = { leaseId: null, state: "busy" };
          return;
        }
        const claimed = await tx.get<{ pending_id: string }>(
          `UPDATE pending_authorization_redeems
           SET status = 'processing', lease_id = ?, lease_expires_at = ?, updated_at = ?
           WHERE pending_id = ?
             AND status = 'processing'
             AND lease_id = ?
             AND lease_expires_at = ?
           RETURNING pending_id`,
          [leaseId, lease, now, input.pendingId, row.lease_id, row.lease_expires_at]
        );
        result = claimed ? { leaseId, state: "acquired" } : { leaseId: null, state: "busy" };
      });
      return result;
    },
    async completePendingAuthorization(pendingId, leaseId) {
      const now = new Date().toISOString();
      const updated = await db.get<{ pending_id: string }>(
        `UPDATE pending_authorization_redeems
         SET status = 'completed', completed_at = ?, updated_at = ?
         WHERE pending_id = ? AND status = 'processing' AND lease_id = ? AND lease_expires_at > ?
         RETURNING pending_id`,
        [now, now, pendingId, leaseId, now]
      );
      return Boolean(updated);
    },
    async failPendingAuthorization(pendingId, leaseId) {
      const now = new Date().toISOString();
      const updated = await db.get<{ pending_id: string }>(
        `UPDATE pending_authorization_redeems
         SET status = 'failed', failed_at = ?, updated_at = ?
         WHERE pending_id = ? AND status = 'processing' AND lease_id = ?
         RETURNING pending_id`,
        [now, now, pendingId, leaseId]
      );
      return Boolean(updated);
    },
    async cleanupExpired() {
      const now = new Date().toISOString();
      const stalePending = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const staleSession = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      await db.run("DELETE FROM otp_challenges WHERE expires_at <= ?", [now]);
      await db.run("DELETE FROM otp_subjects WHERE expires_at <= ?", [now]);
      await db.run("DELETE FROM rate_limit_counters WHERE expires_at <= ?", [now]);
      await db.run(
        `DELETE FROM login_sessions
         WHERE (revoked_at IS NOT NULL AND revoked_at <= ?)
            OR (revoked_at IS NULL AND (idle_expires_at <= ? OR absolute_expires_at <= ?))`,
        [staleSession, staleSession, staleSession]
      );
      await db.run("DELETE FROM recovery_consumes WHERE expires_at <= ? OR (status = 'consumed' AND updated_at <= ?)", [
        now,
        stalePending
      ]);
      await db.run("DELETE FROM recovery_attempts WHERE expires_at <= ? OR (status = 'completed' AND updated_at <= ?)", [
        now,
        stalePending
      ]);
      await db.run(
        `DELETE FROM pending_authorization_redeems
         WHERE status IN ('completed', 'failed') AND updated_at <= ?`,
        [stalePending]
      );
      await db.run(
        `DELETE FROM pending_authorization_redeems
         WHERE status = 'processing' AND lease_expires_at <= ? AND updated_at <= ?`,
        [now, stalePending]
      );
      await db.run(
        `UPDATE auth_jobs
         SET status = 'pending', lease_expires_at = NULL, lease_id = NULL, updated_at = ?
         WHERE status = 'running' AND lease_expires_at <= ?`,
        [now, now]
      );
    },
    async optimizeStorage() {
      await db.pragma("optimize");
    }
  };
}

function boundedLimit(value: number): number {
  if (!Number.isFinite(value)) {
    return 100;
  }
  return Math.max(1, Math.min(Math.floor(value), 500));
}

async function upsertAdminUser(
  tx: TxAuthDb,
  email: string,
  actorUserId: string | null,
  requestId: string,
  now: string
): Promise<UserRow> {
  let user = await tx.get<UserRow>("SELECT * FROM users WHERE email = ? LIMIT 1", [email]);
  if (!user) {
    user = {
      authz_version: 1,
      created_at: now,
      email,
      id: crypto.randomUUID(),
      status: "active",
      updated_at: now
    };
    await tx.run(
      `INSERT INTO users (id, email, status, authz_version, created_at, updated_at)
       VALUES (?, ?, 'active', 1, ?, ?)`,
      [user.id, user.email, now, now]
    );
  } else {
    await tx.run(
      `UPDATE users
       SET status = 'active', authz_version = authz_version + 1, updated_at = ?
       WHERE id = ?`,
      [now, user.id]
    );
    user = { ...user, authz_version: user.authz_version + 1, status: "active", updated_at: now };
  }
  await tx.run("DELETE FROM user_permissions WHERE user_id = ?", [user.id]);
  for (const permission of ADMIN_PERMISSIONS) {
  await tx.run(
    `INSERT INTO user_permissions (user_id, permission, granted_at, granted_by)
       VALUES (?, ?, ?, ?)`,
      [user.id, permission, now, actorUserId]
    );
  }
  await insertAudit(tx, {
    actorUserId,
    event: "user.admin.upserted",
    requestId,
    result: "success",
    targetUserId: user.id,
    after: { email: user.email, permissions: ADMIN_PERMISSIONS }
  });
  return user;
}

async function bulkUpdateUsers(db: AuthDb, input: BulkUserOperationInput): Promise<BulkUserOperationResult> {
  const userIds = [...new Set(input.userIds.map((userId) => userId.trim()).filter(Boolean))];
  if (userIds.length === 0) {
    throw new Error("Select at least one user");
  }

  const outcomes: Record<string, RevokeOutcome | BulkRevokeOutcome> = {};
  const now = new Date();
  const nowIso = now.toISOString();

  await db.withWriteTransaction(async (tx) => {
    const users = await getUsersWithPermissionsById(tx, userIds);
    if (userIds.some((userId) => !users.has(userId))) {
      throw new Error("Unknown user selected");
    }

    if (input.action === "disable") {
      await assertBulkLeavesActiveAdmin(tx, userIds);
    }

    for (const userId of userIds) {
      const user = users.get(userId);
      if (!user) {
        outcomes[userId] = "not_found";
        continue;
      }

      if (input.action === "disable" || input.action === "enable") {
        await setUserStateInTx(tx, {
          actorUserId: input.actorUserId,
          nowIso,
          permissions: user.permissions,
          requestId: input.requestId,
          status: input.action === "disable" ? "disabled" : "active",
          userId
        });
        outcomes[userId] = "changed";
      } else if (input.action === "revoke_sessions") {
        outcomes[userId] = await revokeUserSessionsInTx(tx, userId, input.actorUserId, input.requestId, nowIso);
      } else if (input.action === "revoke_grants") {
        outcomes[userId] = await revokeUserConsentsInTx(tx, userId, input.actorUserId, input.requestId, nowIso);
      } else if (input.action === "revoke_authorization") {
        outcomes[userId] = await revokeUserAuthorizationInTx(tx, userId, input.actorUserId, input.requestId, nowIso);
      } else if (input.action === "set_grant_timeout") {
        outcomes[userId] = input.inheritGrantTtl
          ? await clearUserGrantTimeoutInTx(tx, userId, input.actorUserId, input.requestId, now)
          : await setUserGrantTimeoutInTx(
              tx,
              userId,
              input.grantTtlSeconds === undefined ? null : input.grantTtlSeconds,
              input.actorUserId,
              input.requestId,
              now
            );
      }
    }

    await insertAudit(tx, {
      actorUserId: input.actorUserId,
      event: "users.bulk.updated",
      metadata: { action: input.action, outcomes },
      requestId: input.requestId,
      result: "success"
    });
  });

  return {
    action: input.action,
    changedCount: Object.values(outcomes).filter((outcome) => outcome === "changed").length,
    outcomes,
    selectedCount: userIds.length
  };
}

interface UserWithPermissions extends UserRow {
  permissions: string[];
}

async function getUsersWithPermissionsById(
  db: AuthDb | TxAuthDb,
  userIds: readonly string[]
): Promise<Map<string, UserWithPermissions>> {
  const placeholders = userIds.map(() => "?").join(", ");
  const rows = await db.all<UserRow & { permission: string | null }>(
    `SELECT users.*, user_permissions.permission
     FROM users
     LEFT JOIN user_permissions ON user_permissions.user_id = users.id
     WHERE users.id IN (${placeholders})
     ORDER BY users.email, user_permissions.permission`,
    [...userIds]
  );
  const users = new Map<string, UserWithPermissions>();
  for (const row of rows) {
    let user = users.get(row.id);
    if (!user) {
      user = {
        authz_version: row.authz_version,
        created_at: row.created_at,
        email: row.email,
        id: row.id,
        permissions: [],
        status: row.status,
        updated_at: row.updated_at
      };
      users.set(row.id, user);
    }
    if (row.permission) {
      user.permissions.push(row.permission);
    }
  }
  return users;
}

async function assertBulkLeavesActiveAdmin(tx: TxAuthDb, selectedUserIds: readonly string[]): Promise<void> {
  const total = await tx.get<{ count: number }>(
    `SELECT COUNT(DISTINCT users.id) AS count
     FROM users
     JOIN user_permissions ON user_permissions.user_id = users.id
     WHERE users.status = 'active'
       AND user_permissions.permission = ?`,
    [ADMIN_PERMISSION]
  );
  if (Number(total?.count ?? 0) < 1) {
    return;
  }
  const placeholders = selectedUserIds.map(() => "?").join(", ");
  const remaining = await tx.get<{ count: number }>(
    `SELECT COUNT(DISTINCT users.id) AS count
     FROM users
     JOIN user_permissions ON user_permissions.user_id = users.id
     WHERE users.status = 'active'
       AND user_permissions.permission = ?
       AND users.id NOT IN (${placeholders})`,
    [ADMIN_PERMISSION, ...selectedUserIds]
  );
  if (Number(remaining?.count ?? 0) < 1) {
    throw new Error("Cannot disable every active admin");
  }
}

async function setUserStateInTx(
  tx: TxAuthDb,
  input: {
    actorUserId: string;
    nowIso: string;
    permissions: readonly string[];
    requestId: string;
    status: UserRow["status"];
    userId: string;
  }
): Promise<void> {
  const normalized = assertKnownPermissions(input.permissions);
  const before = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [input.userId]);
  if (!before) {
    throw new Error("User not found");
  }
  const beforePermissions = await tx.all<{ permission: string }>(
    "SELECT permission FROM user_permissions WHERE user_id = ?",
    [input.userId]
  );
  const wasActiveAdmin = before.status === "active" && beforePermissions.some((row) => row.permission === ADMIN_PERMISSION);
  const willBeActiveAdmin = input.status === "active" && normalized.includes(ADMIN_PERMISSION);
  if (wasActiveAdmin && !willBeActiveAdmin) {
    const adminCount = await tx.get<{ count: number }>(
      `SELECT COUNT(*) AS count
       FROM users
       JOIN user_permissions ON user_permissions.user_id = users.id
       WHERE users.status = 'active'
         AND users.id <> ?
         AND user_permissions.permission = ?`,
      [input.userId, ADMIN_PERMISSION]
    );
    if (Number(adminCount?.count ?? 0) < 1) {
      throw new Error("Cannot remove the last active admin");
    }
  }
  await tx.run(
    `UPDATE users
     SET status = ?, authz_version = authz_version + 1, updated_at = ?
     WHERE id = ?`,
    [input.status, input.nowIso, input.userId]
  );
  await tx.run("DELETE FROM user_permissions WHERE user_id = ?", [input.userId]);
  for (const permission of normalized) {
    await tx.run(
      `INSERT INTO user_permissions (user_id, permission, granted_at, granted_by)
       VALUES (?, ?, ?, ?)`,
      [input.userId, permission, input.nowIso, input.actorUserId]
    );
  }
  await tx.run("UPDATE login_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ?", [
    input.nowIso,
    input.userId
  ]);
  await tx.run("DELETE FROM oauth_consents WHERE user_id = ?", [input.userId]);
  await enqueueJobInTx(tx, {
    idempotencyKey: `revoke-user-grants:${input.userId}:${input.requestId}`,
    payload: { userId: input.userId },
    requestId: input.requestId,
    targetUserId: input.userId,
    type: "revoke_user_grants"
  });
  await insertAudit(tx, {
    actorUserId: input.actorUserId,
    event: "user.state.updated",
    result: "success",
    targetUserId: input.userId,
    requestId: input.requestId,
    before,
    after: { status: input.status, permissions: normalized }
  });
}

async function revokeUserSessionsInTx(
  tx: TxAuthDb,
  userId: string,
  actorUserId: string | null,
  requestId: string,
  nowIso: string
): Promise<BulkRevokeOutcome> {
  const active = await tx.get<{ count: number }>(
    "SELECT COUNT(*) AS count FROM login_sessions WHERE user_id = ? AND revoked_at IS NULL",
    [userId]
  );
  const outcome: BulkRevokeOutcome = Number(active?.count ?? 0) < 1 ? "no_active_targets" : "changed";
  if (outcome === "changed") {
    await tx.run("UPDATE login_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", [nowIso, userId]);
  }
  await insertAudit(tx, {
    actorUserId,
    event: "sessions.revoked",
    result: outcome === "changed" ? "success" : "denied",
    requestId,
    targetUserId: userId,
    metadata: { outcome }
  });
  return outcome;
}

async function revokeUserConsentsInTx(
  tx: TxAuthDb,
  userId: string,
  actorUserId: string,
  requestId: string,
  nowIso: string
): Promise<BulkRevokeOutcome> {
  const active = await tx.get<{ count: number }>("SELECT COUNT(*) AS count FROM oauth_consents WHERE user_id = ?", [userId]);
  const outcome: BulkRevokeOutcome = Number(active?.count ?? 0) < 1 ? "no_active_targets" : "changed";
  if (outcome === "changed") {
    await tx.run("DELETE FROM oauth_consents WHERE user_id = ?", [userId]);
    await enqueueJobInTx(tx, {
      idempotencyKey: `revoke-user-grants:${userId}:${requestId}`,
      payload: { userId },
      requestId,
      targetUserId: userId,
      type: "revoke_user_grants"
    });
  }
  await insertAudit(tx, {
    actorUserId,
    event: "user.consents.revoked",
    requestId,
    result: outcome === "changed" ? "success" : "denied",
    targetUserId: userId,
    metadata: { outcome }
  });
  return outcome;
}

async function revokeUserAuthorizationInTx(
  tx: TxAuthDb,
  userId: string,
  actorUserId: string,
  requestId: string,
  nowIso: string
): Promise<BulkRevokeOutcome> {
  await tx.run(
    `UPDATE users
     SET authz_version = authz_version + 1, updated_at = ?
     WHERE id = ?`,
    [nowIso, userId]
  );
  await tx.run("DELETE FROM oauth_consents WHERE user_id = ?", [userId]);
  await enqueueJobInTx(tx, {
    idempotencyKey: `revoke-user-authorization:${userId}:${requestId}`,
    payload: { userId },
    requestId,
    targetUserId: userId,
    type: "revoke_user_grants"
  });
  await insertAudit(tx, {
    actorUserId,
    event: "user.authorization.revoked",
    metadata: { outcome: "changed" },
    requestId,
    result: "success",
    targetUserId: userId
  });
  return "changed";
}

async function setUserGrantTimeoutInTx(
  tx: TxAuthDb,
  userId: string,
  ttlSeconds: number | null,
  actorUserId: string,
  requestId: string,
  now: Date
): Promise<RevokeOutcome> {
  const nowIso = now.toISOString();
  const expiresAt = expiresAtFromTtl(now, ttlSeconds);
  await tx.run(
    `INSERT INTO user_oauth_policies (user_id, grant_ttl_seconds, updated_at, updated_by)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       grant_ttl_seconds = excluded.grant_ttl_seconds,
       updated_at = excluded.updated_at,
       updated_by = excluded.updated_by`,
    [userId, ttlSeconds, nowIso, actorUserId]
  );
  await tx.run("UPDATE oauth_consents SET expires_at = ? WHERE user_id = ?", [expiresAt, userId]);
  await insertAudit(tx, {
    actorUserId,
    event: "oauth.user_grant_timeout.updated",
    metadata: { outcome: "changed", ttlSeconds },
    requestId,
    result: "success",
    targetUserId: userId
  });
  return "changed";
}

async function clearUserGrantTimeoutInTx(
  tx: TxAuthDb,
  userId: string,
  actorUserId: string,
  requestId: string,
  now: Date
): Promise<RevokeOutcome> {
  const defaultGrantTtlSeconds = await getDefaultGrantTtlSecondsFromDb(tx);
  const expiresAt = expiresAtFromTtl(now, defaultGrantTtlSeconds);
  await tx.run("DELETE FROM user_oauth_policies WHERE user_id = ?", [userId]);
  await tx.run("UPDATE oauth_consents SET expires_at = ? WHERE user_id = ?", [expiresAt, userId]);
  await insertAudit(tx, {
    actorUserId,
    event: "oauth.user_grant_timeout.cleared",
    metadata: { defaultGrantTtlSeconds, outcome: "changed" },
    requestId,
    result: "success",
    targetUserId: userId
  });
  return "changed";
}

async function insertAudit(db: AuthDb | TxAuthDb, input: AuditInput): Promise<void> {
  await db.run(
    `INSERT INTO auth_audit_logs
      (id, actor_user_id, target_user_id, event, result, before_json, after_json,
       request_id, ip_prefix, user_agent_hash, metadata_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      crypto.randomUUID(),
      input.actorUserId ?? null,
      input.targetUserId ?? null,
      input.event,
      input.result,
      input.before === undefined ? null : JSON.stringify(input.before),
      input.after === undefined ? null : JSON.stringify(input.after),
      input.requestId,
      input.ipPrefix ?? null,
      input.userAgentHash ?? null,
      input.metadata === undefined ? null : JSON.stringify(input.metadata),
      new Date().toISOString()
    ]
  );
}

async function enqueueJobInTx(
  tx: TxAuthDb,
  input: {
    type: string;
    idempotencyKey: string;
    targetUserId?: string | null;
    targetClientId?: string | null;
    payload: unknown;
    requestId: string;
  }
): Promise<void> {
  const now = new Date().toISOString();
  await tx.run(
    `INSERT OR IGNORE INTO auth_jobs
      (job_id, type, idempotency_key, status, target_user_id, target_client_id, payload_json,
       attempts, next_attempt_at, lease_expires_at, request_id, created_at, updated_at)
     VALUES (?, ?, ?, 'pending', ?, ?, ?, 0, ?, NULL, ?, ?, ?)`,
    [
      crypto.randomUUID(),
      input.type,
      input.idempotencyKey,
      input.targetUserId ?? null,
      input.targetClientId ?? null,
      JSON.stringify(input.payload),
      now,
      input.requestId,
      now,
      now
    ]
  );
}

async function getSessionByHash(db: AuthDb | TxAuthDb, idHash: string): Promise<SessionContextRow | null> {
  const row = await db.get<
    UserRow & {
      admin_step_up_at: string | null;
      absolute_expires_at: string | null;
      idle_expires_at: string | null;
      last_seen_at: string | null;
      last_touched_at: string | null;
      revoked_at: string | null;
    }
  >(
    `SELECT users.*, login_sessions.admin_step_up_at, login_sessions.absolute_expires_at,
            login_sessions.idle_expires_at, login_sessions.last_seen_at,
            login_sessions.last_touched_at, login_sessions.revoked_at
     FROM login_sessions
     JOIN users ON users.id = login_sessions.user_id
     WHERE login_sessions.id_hash = ?
     LIMIT 1`,
    [idHash]
  );
  if (
    !row ||
    row.revoked_at ||
    row.status !== "active" ||
    !row.absolute_expires_at ||
    !row.idle_expires_at ||
    !row.last_seen_at ||
    !row.last_touched_at ||
    Date.parse(row.absolute_expires_at) <= Date.now() ||
    Date.parse(row.idle_expires_at) <= Date.now()
  ) {
    return null;
  }
  return {
    adminStepUpAt: row.admin_step_up_at,
    absoluteExpiresAt: row.absolute_expires_at,
    idleExpiresAt: row.idle_expires_at,
    sessionIdHash: idHash,
    user: row
  };
}

async function hmacHex(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function encryptEmail(
  secrets: CryptoSecrets,
  purpose: string,
  subjectId: string,
  email: string
): Promise<string> {
  const key = await importAesKey(secrets.OTP_SUBJECT_ENCRYPTION_KEY_CURRENT);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`${purpose}:${subjectId}`);
  const encrypted = await crypto.subtle.encrypt(
    { additionalData: aad, iv: nonce, name: "AES-GCM" },
    key,
    new TextEncoder().encode(email)
  );
  return JSON.stringify({
    ciphertext_b64url: base64UrlEncode(new Uint8Array(encrypted)),
    key_version: secrets.OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION,
    nonce_b64url: base64UrlEncode(nonce)
  });
}

async function decryptEmail(
  secrets: CryptoSecrets,
  purpose: string,
  subjectId: string,
  encryptedEmail: string | null
): Promise<string | null> {
  if (!encryptedEmail) {
    return null;
  }
  const envelope = JSON.parse(encryptedEmail) as {
    key_version: string;
    nonce_b64url: string;
    ciphertext_b64url: string;
  };
  const secret = selectCurrentSecret(
    envelope.key_version,
    secrets.OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION,
    secrets.OTP_SUBJECT_ENCRYPTION_KEY_CURRENT
  );
  const key = await importAesKey(secret);
  const aad = new TextEncoder().encode(`${purpose}:${subjectId}`);
  const decrypted = await crypto.subtle.decrypt(
    { additionalData: aad, iv: toArrayBuffer(base64UrlDecode(envelope.nonce_b64url)), name: "AES-GCM" },
    key,
    toArrayBuffer(base64UrlDecode(envelope.ciphertext_b64url))
  );
  return new TextDecoder().decode(decrypted);
}

async function importAesKey(base64UrlKey: string): Promise<CryptoKey> {
  const bytes = base64UrlDecode(base64UrlKey);
  if (bytes.byteLength !== 32) {
    throw new Error("AES-GCM key must be a base64url encoded 256-bit key");
  }
  return crypto.subtle.importKey("raw", toArrayBuffer(bytes), "AES-GCM", false, ["encrypt", "decrypt"]);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function selectCurrentSecret(
  version: string,
  currentVersion: string,
  currentSecret: string
): string {
  if (version === currentVersion) {
    return currentSecret;
  }
  throw new Error("Unknown secret version");
}

async function getDefaultGrantTtlSecondsFromDb(db: AuthDb | TxAuthDb): Promise<number | null> {
  const row = await db.get<{ value_json: string }>(
    "SELECT value_json FROM auth_settings WHERE key = 'default_grant_ttl_seconds' LIMIT 1"
  );
  if (!row) {
    return null;
  }
  const parsed = JSON.parse(row.value_json) as unknown;
  return typeof parsed === "number" && Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : null;
}

async function getEffectiveGrantTtlSecondsFromDb(db: AuthDb | TxAuthDb, userId: string): Promise<number | null> {
  const row = await db.get<{ grant_ttl_seconds: number | null }>(
    "SELECT grant_ttl_seconds FROM user_oauth_policies WHERE user_id = ? LIMIT 1",
    [userId]
  );
  if (row) {
    return row.grant_ttl_seconds === null ? null : Number(row.grant_ttl_seconds);
  }
  return getDefaultGrantTtlSecondsFromDb(db);
}

function expiresAtFromTtl(now: Date, ttlSeconds: number | null): string | null {
  return ttlSeconds === null ? null : new Date(now.getTime() + ttlSeconds * 1000).toISOString();
}

async function setUserGrantTimeoutOverride(
  db: AuthDb,
  userId: string,
  ttlSeconds: number | null,
  actorUserId: string,
  requestId: string
): Promise<RevokeOutcome> {
  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = expiresAtFromTtl(now, ttlSeconds);
  let outcome: RevokeOutcome = "not_found";
  await db.withWriteTransaction(async (tx) => {
    const user = await tx.get<UserRow>("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
    if (user) {
      await tx.run(
        `INSERT INTO user_oauth_policies (user_id, grant_ttl_seconds, updated_at, updated_by)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
           grant_ttl_seconds = excluded.grant_ttl_seconds,
           updated_at = excluded.updated_at,
           updated_by = excluded.updated_by`,
        [userId, ttlSeconds, nowIso, actorUserId]
      );
      await tx.run("UPDATE oauth_consents SET expires_at = ? WHERE user_id = ?", [expiresAt, userId]);
      outcome = "changed";
    }
    await insertAudit(tx, {
      actorUserId,
      event: "oauth.user_grant_timeout.updated",
      metadata: { outcome, ttlSeconds },
      requestId,
      result: outcome === "changed" ? "success" : "failure",
      targetUserId: userId
    });
  });
  return outcome;
}

function generateOtpCode(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const value = new DataView(bytes.buffer).getUint32(0) % 1_000_000;
  return value.toString().padStart(6, "0");
}

export async function hashUserAgent(userAgent: string | undefined | null): Promise<string | null> {
  return userAgent ? sha256Hex(userAgent) : null;
}

export function ipPrefix(ip: string | undefined | null): string | null {
  if (!ip) {
    return null;
  }
  if (ip.includes(":")) {
    return ip.split(":").slice(0, 4).join(":");
  }
  return ip.split(".").slice(0, 3).join(".");
}
