export { AUTH_SCHEMA_VERSION, runAuthMigrations } from "./migrations.js";
export {
  createAuthRepository,
  hashUserAgent,
  ipPrefix,
  type AdminUserRow,
  type AdminConsentRow,
  type AuditInput,
  type AuditLogRow,
  type AuthJobRow,
  type AuthRepository,
  type BulkUserOperationAction,
  type BulkUserOperationInput,
  type BulkUserOperationResult,
  type BulkRevokeOutcome,
  type ClientPolicyRow,
  type ConsentRow,
  type CreateOtpInput,
  type CryptoSecrets,
  type PendingAuthorizationClaim,
  type PendingAuthorizationInput,
  type RevokeOutcome,
  type SessionRow,
  type UserRow,
  type VerifiedOtp,
  type VerifyOtpInput
} from "./repository.js";
export type { AuthTursoEnv } from "./client.js";
