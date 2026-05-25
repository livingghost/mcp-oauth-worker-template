import OAuthProvider, {
  OAuthError,
  getOAuthApi,
  type AuthRequest,
  type GrantSummary,
  type OAuthHelpers,
  type OAuthProviderOptions,
  type TokenExchangeCallbackOptions,
  type TokenSummary
} from "@cloudflare/workers-oauth-provider";
import {
  createAuthRepository,
  hashUserAgent,
  ipPrefix,
  type AdminConsentRow,
  type AdminUserRow,
  type AuthRepository,
  type AuditLogRow,
  type AuthJobRow,
  type BulkRevokeOutcome,
  type BulkUserOperationAction,
  type ClientPolicyRow,
  type CryptoSecrets,
  type RevokeOutcome,
  type SessionRow,
  type AuthTursoEnv
} from "@mcp-auth/auth-db";
import {
  OAUTH_SCOPES,
  USER_PERMISSIONS,
  assertKnownScopes,
  formatCanonicalScope,
  hashScope,
  isScopeSubset,
  normalizeEmail,
  normalizeResourceUri,
  parseTtlSeconds,
  randomBase64Url,
  requireMcpResource,
  sha256Hex,
  type AuthContext,
  type AuthorizationRuntime,
  type CapabilityRequirement,
  type OAuthTokenProps
} from "@mcp-auth/shared";
import { Hono } from "hono";
import { z } from "zod";
import { isAllowedRedirectUri, isPublicHttpsUrl, isUrlClientId } from "./url-policy.js";

export interface AuthWorkerEnv extends AuthTursoEnv {
  OAUTH_KV: KVNamespace;
  AUTH_FLOW_KV: KVNamespace;
  RESEND_API_KEY: string;
  OTP_EMAIL_FROM: string;
  OTP_EMAIL_REPLY_TO?: string;
  MCP_RESOURCE_URI: string;
  ALLOW_LOCAL_RESOURCE_URI?: string;
  ALLOWED_MCP_ORIGINS?: string;
  ACCESS_TOKEN_TTL_SECONDS?: string;
  REFRESH_TOKEN_TTL_SECONDS?: string;
  SESSION_IDLE_TTL_SECONDS?: string;
  SESSION_ABSOLUTE_TTL_SECONDS?: string;
  SESSION_TOUCH_INTERVAL_SECONDS?: string;
  ADMIN_STEP_UP_TTL_SECONDS?: string;
  OTP_TTL_SECONDS?: string;
  PENDING_AUTHORIZATION_TTL_SECONDS?: string;
  AUTH_JOB_BATCH_SIZE?: string;
  AUTH_JOB_MAX_ATTEMPTS?: string;
  AUTH_JOB_DEADLINE_MS?: string;
  GRANT_LOOKUP_MAX_PAGES?: string;
  GRANT_LOOKUP_DEADLINE_MS?: string;
  BOOTSTRAP_ADMIN_EMAILS?: string;
  RECOVERY_BOOTSTRAP_EMAILS?: string;
  RECOVERY_BOOTSTRAP_ENABLED_UNTIL?: string;
  RECOVERY_BOOTSTRAP_NONCE_HASH?: string;
  SECURITY_CONTACT_EMAILS?: string;
  OTP_PEPPER_CURRENT: string;
  OTP_PEPPER_CURRENT_VERSION: string;
  OTP_SUBJECT_ENCRYPTION_KEY_CURRENT: string;
  OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION: string;
  EMAIL_HASH_KEY_CURRENT: string;
  MCP_SERVER_NAME?: string;
  MCP_SERVER_DESCRIPTION?: string;
}

export interface McpRuntimeOptions<Env> {
  authContext: AuthContext;
  authorizationRuntime: AuthorizationRuntime;
  env: Env;
  ctx: ExecutionContext;
  request: Request;
}

export interface CreateProtectedOAuthMcpWorkerOptions<Env extends AuthWorkerEnv> {
  createMcpServer: (options: McpRuntimeOptions<Env>) => unknown;
  handleMcpRequest: (request: Request, env: Env, ctx: ExecutionContext, server: unknown) => Promise<Response>;
  serverName?: string;
  serverDescription?: string;
}

interface RuntimeConfig {
  serverName: string;
  serverDescription: string;
  resource: string;
  allowedOrigins: Set<string>;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number | undefined;
  sessionIdleTtlSeconds: number;
  sessionAbsoluteTtlSeconds: number;
  sessionTouchIntervalSeconds: number;
  adminStepUpTtlSeconds: number;
  otpTtlSeconds: number;
  pendingAuthorizationTtlSeconds: number;
  authJobBatchSize: number;
  authJobMaxAttempts: number;
  authJobDeadlineMs: number;
  grantLookupMaxPages: number;
  grantLookupDeadlineMs: number;
  bootstrapAdminEmails: Set<string>;
  recoveryBootstrapEmails: Set<string>;
  securityContactEmails: string[];
  recoveryEnabledUntil: number | null;
  recoveryNonceHash: string | null;
}

interface Runtime<Env extends AuthWorkerEnv> {
  config: RuntimeConfig;
  repo: AuthRepository;
  workerOptions: CreateProtectedOAuthMcpWorkerOptions<Env>;
  requestId: string;
}

type ValidationCheck = "session" | "csrf" | "admin" | "freshStepUp" | "breakGlass";
type RouteId =
  | "user.home"
  | "account.delete"
  | "admin.home"
  | "authorize.get"
  | "admin.user.create"
  | "admin.user.update"
  | "admin.users.bulk"
  | "admin.oauth_policy.update"
  | "admin.user_grant_timeout.update"
  | "admin.client.revoke"
  | "admin.session.revoke"
  | "admin.user.sessions.revoke"
  | "admin.consent.revoke"
  | "admin.user.consents.revoke"
  | "admin.provider_grant.revoke"
  | "admin.user.authorization.revoke"
  | "recovery.start"
  | "recovery.verify";

interface ValidatedSessionContext {
  readonly routeId: RouteId;
  readonly session: { sessionIdHash: string; user: { id: string; email: string }; adminStepUpAt: string | null };
  readonly satisfiedChecks: ReadonlySet<ValidationCheck>;
  readonly sealed: symbol;
}

interface AdminSession {
  user: { id: string; email: string };
  sessionIdHash: string;
  adminStepUpAt: string | null;
  validation: ValidatedSessionContext;
}

const VALIDATED_SESSION_CONTEXT = Symbol("validated-session-context");

interface TouchPolicy {
  touch: boolean;
  required: readonly ValidationCheck[];
}

const TOUCH_POLICIES: Record<RouteId, TouchPolicy> = {
  "user.home": { required: ["session"], touch: true },
  "account.delete": { required: ["session", "csrf"], touch: false },
  "admin.home": { required: ["session", "admin"], touch: true },
  "authorize.get": { required: ["session"], touch: true },
  "admin.user.create": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.user.update": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.users.bulk": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.oauth_policy.update": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.user_grant_timeout.update": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.client.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.session.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.user.sessions.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.consent.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.user.consents.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.provider_grant.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.user.authorization.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "recovery.start": { required: ["breakGlass", "csrf"], touch: false },
  "recovery.verify": { required: ["breakGlass", "csrf"], touch: false }
};

interface PendingAuthorizationPayload {
  pending_id: string;
  session_id_hash: string;
  user_id: string;
  client_id: string;
  redirect_uri: string;
  resource: string;
  scope_hash: string;
  csrf_hash: string;
  request_json: AuthRequest;
  expires_at: string;
  payload_digest: string;
}

const SESSION_COOKIE = "__Host-auth_session";
const CSRF_COOKIE = "__Host-auth_csrf";
const OAUTH_REAUTH_COOKIE = "__Host-oauth_reauth";
const OAUTH_REAUTH_PREFIX = "oauth-reauth:";
const OAUTH_AUTHORIZE_OTP_PURPOSE = "oauth_authorize";
const LOGIN_OTP_RESEND_DELAY_SECONDS = 30;
const MAX_GRANT_TTL_SECONDS = 7_776_000;
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const CLIENT_METADATA_MAX_BYTES = 32_768;
const CLIENT_METADATA_FETCH_TIMEOUT_MS = 3_000;
const ACCESS_TOKEN_UNWRAP_RETRY_DELAYS_MS = [100, 250, 500, 1000] as const;
const CLIENT_METADATA_AUTH_METHODS = ["none", "private_key_jwt"] as const;
const CLIENT_METADATA_FETCH_HEADERS = {
  Accept: "application/json",
  "User-Agent": "McpOAuthWorkerTemplate/0.1"
};
const PENDING_PREFIX = "pending:";
const SAFE_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "text/html; charset=utf-8",
  "Referrer-Policy": "no-referrer"
};

class CsrfError extends Error {
  constructor() {
    super("Invalid CSRF token");
    this.name = "CsrfError";
  }
}

type ClientMetadataAuthMethod = (typeof CLIENT_METADATA_AUTH_METHODS)[number];

type ClientJsonWebKey = JsonWebKey & {
  alg?: string;
  kid?: string;
  kty?: string;
  use?: string;
};

interface ClientJsonWebKeySet {
  keys: ClientJsonWebKey[];
}

interface ClientMetadataDocument {
  raw: Record<string, unknown>;
  redirectUris: string[];
  tokenEndpointAuthMethod: ClientMetadataAuthMethod;
  grantTypes: string[];
  responseTypes: string[];
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  policyUri?: string;
  tosUri?: string;
  jwksUri?: string;
  jwks?: ClientJsonWebKeySet;
  contacts?: string[];
}

interface ProviderClientRecord {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  policyUri?: string;
  tosUri?: string;
  jwksUri?: string;
  contacts?: string[];
  grantTypes: string[];
  responseTypes: string[];
  registrationDate: number;
  tokenEndpointAuthMethod: "none";
}

const pendingAuthorizationPayloadSchema = z.object({
  client_id: z.string().min(1),
  csrf_hash: z.string().min(32),
  expires_at: z.string().min(1),
  pending_id: z.string().min(1),
  payload_digest: z.string().min(32),
  redirect_uri: z.string().url(),
  request_json: z.custom<AuthRequest>(
    (value) =>
      typeof value === "object" &&
      value !== null &&
      typeof (value as { clientId?: unknown }).clientId === "string" &&
      typeof (value as { redirectUri?: unknown }).redirectUri === "string"
  ),
  resource: z.string().url(),
  scope_hash: z.string().min(32),
  session_id_hash: z.string().min(32),
  user_id: z.string().min(1)
});

const oauthReauthPayloadSchema = z.object({
  expires_at: z.string().min(1),
  return_to_hash: z.string().min(32),
  session_id_hash: z.string().min(32),
  user_id: z.string().min(1)
});

export function createProtectedOAuthMcpWorker<Env extends AuthWorkerEnv>(
  workerOptions: CreateProtectedOAuthMcpWorkerOptions<Env>
): ExportedHandler<Env> {
  return {
    async fetch(request, env, ctx) {
      const runtime = createRuntime(env, workerOptions);
      await runtime.repo.assertSchema();
      const preflight = await preflightRequest(request, env, ctx, runtime);
      if (preflight) {
        return preflight;
      }
      const providerOptions = buildOAuthProviderOptions(env, runtime);
      const provider = new OAuthProvider<Env>(providerOptions);
      return provider.fetch(request, env, ctx);
    },
    async scheduled(_event, env, ctx) {
      const runtime = createRuntime(env, workerOptions);
      const options = buildOAuthProviderOptions(env, runtime);
      const provider = new OAuthProvider<Env>(options);
      ctx.waitUntil(
        (async () => {
          const schemaOk = await runScheduledTask(runtime, "schema.assert", () => runtime.repo.assertSchema());
          if (!schemaOk) {
            return;
          }
          await runScheduledTask(runtime, "provider.purge_expired", () => provider.purgeExpiredData(env));
          await runScheduledTask(runtime, "auth.cleanup_expired", () => runtime.repo.cleanupExpired());
          await runScheduledBestEffortTask("auth.optimize_storage", () => runtime.repo.optimizeStorage());
          await runScheduledTask(runtime, "provider.cleanup_orphans", () => cleanupOrphanProviderClients(runtime.repo, getOAuthApi(options, env)));
          await runScheduledTask(runtime, "auth.run_jobs", () => runAuthJobs(runtime.repo, getOAuthApi(options, env), runtime.config));
        })().catch((error) => console.error(error))
      );
    }
  };
}

export function buildOAuthProviderOptions<Env extends AuthWorkerEnv>(
  env: Env,
  runtime: Runtime<Env>
): OAuthProviderOptions<Env> {
  const options: OAuthProviderOptions<Env> = {
    accessTokenTTL: runtime.config.accessTokenTtlSeconds,
    allowImplicitFlow: false,
    allowPlainPKCE: false,
    allowTokenExchangeGrant: false,
    apiHandler: createApiHandler(env, runtime) as NonNullable<OAuthProviderOptions<Env>["apiHandler"]>,
    apiRoute: "/mcp",
    authorizeEndpoint: "/authorize",
    clientIdMetadataDocumentEnabled: false,
    defaultHandler: createDefaultHandler(env, runtime),
    disallowPublicClientRegistration: true,
    refreshTokenTTL: runtime.config.refreshTokenTtlSeconds as number,
    resourceMatchOriginOnly: false,
    resourceMetadata: {
      bearer_methods_supported: ["header"],
      resource: runtime.config.resource,
      resource_name: runtime.config.serverName,
      scopes_supported: [...OAUTH_SCOPES]
    },
    scopesSupported: [...OAUTH_SCOPES],
    tokenEndpoint: "/token",
    tokenExchangeCallback: (input) => validateTokenExchange(runtime, input),
    onError({ code, description, status }) {
      console.warn(`OAuth error response: ${status} ${code} - ${description}`);
    }
  };
  return options;
}

function createRuntime<Env extends AuthWorkerEnv>(
  env: Env,
  workerOptions: CreateProtectedOAuthMcpWorkerOptions<Env>
): Runtime<Env> {
  return {
    config: loadConfig(env, workerOptions),
    repo: createAuthRepository(env),
    requestId: crypto.randomUUID(),
    workerOptions
  };
}

function loadConfig<Env extends AuthWorkerEnv>(
  env: Env,
  options: CreateProtectedOAuthMcpWorkerOptions<Env>
): RuntimeConfig {
  const resource = normalizeResourceUri(requiredEnv(env.MCP_RESOURCE_URI, "MCP_RESOURCE_URI"));
  assertDeployableResourceUri(resource, env.ALLOW_LOCAL_RESOURCE_URI === "true");
  const sessionConfig = parseSessionConfig(env);
  return {
    accessTokenTtlSeconds: parseTtlSeconds(env.ACCESS_TOKEN_TTL_SECONDS, 600, 3600),
    adminStepUpTtlSeconds: parseTtlSeconds(env.ADMIN_STEP_UP_TTL_SECONDS, 300, 900),
    allowedOrigins: splitSet(env.ALLOWED_MCP_ORIGINS),
    authJobBatchSize: parseBoundedInteger(env.AUTH_JOB_BATCH_SIZE, 10, 1, 100),
    authJobDeadlineMs: parseBoundedInteger(env.AUTH_JOB_DEADLINE_MS, 20_000, 1_000, 300_000),
    authJobMaxAttempts: parseBoundedInteger(env.AUTH_JOB_MAX_ATTEMPTS, 5, 1, 20),
    bootstrapAdminEmails: splitSet(env.BOOTSTRAP_ADMIN_EMAILS),
    grantLookupDeadlineMs: parseBoundedInteger(env.GRANT_LOOKUP_DEADLINE_MS, 5_000, 500, 30_000),
    grantLookupMaxPages: parseBoundedInteger(env.GRANT_LOOKUP_MAX_PAGES, 3, 1, 10),
    otpTtlSeconds: parseTtlSeconds(env.OTP_TTL_SECONDS, 600, 900),
    pendingAuthorizationTtlSeconds: parseTtlSeconds(env.PENDING_AUTHORIZATION_TTL_SECONDS, 600, 900),
    recoveryBootstrapEmails: splitSet(env.RECOVERY_BOOTSTRAP_EMAILS),
    recoveryEnabledUntil: env.RECOVERY_BOOTSTRAP_ENABLED_UNTIL
      ? Date.parse(env.RECOVERY_BOOTSTRAP_ENABLED_UNTIL)
      : null,
    recoveryNonceHash: env.RECOVERY_BOOTSTRAP_NONCE_HASH || null,
    refreshTokenTtlSeconds: parseOptionalTtlSeconds(env.REFRESH_TOKEN_TTL_SECONDS, "REFRESH_TOKEN_TTL_SECONDS", MAX_GRANT_TTL_SECONDS),
    resource,
    securityContactEmails: [...splitSet(env.SECURITY_CONTACT_EMAILS)],
    serverDescription: options.serverDescription ?? env.MCP_SERVER_DESCRIPTION ?? "OAuth-protected MCP server",
    serverName: options.serverName ?? env.MCP_SERVER_NAME ?? "MCP Server",
    sessionAbsoluteTtlSeconds: sessionConfig.absolute,
    sessionIdleTtlSeconds: sessionConfig.idle,
    sessionTouchIntervalSeconds: sessionConfig.touch
  };
}

async function preflightRequest<Env extends AuthWorkerEnv>(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  runtime: Runtime<Env>
): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname === "/.well-known/oauth-authorization-server") {
    return addCorsHeaders(renderOAuthServerMetadata(url), request);
  }
  if (url.pathname === "/mcp") {
    const origin = request.headers.get("Origin");
    if (origin && runtime.config.allowedOrigins.size > 0 && !runtime.config.allowedOrigins.has(origin)) {
      return json({ error: "origin_not_allowed" }, 403);
    }
    return null;
  }
  if (url.pathname === "/authorize") {
    if (!(await consumeRequestRateLimit(runtime, env, request, "authorize", [], 120, 60))) {
      return oauthError("rate_limited", 429);
    }
    const params = request.method === "GET" ? url.searchParams : await request.clone().formData().then(formToParams);
    if (request.method === "POST" && params.has("pending_id")) {
      return null;
    }
    const error = await validateAuthorizePreflight(params, env, runtime).catch((validationError) => {
      console.warn(validationError);
      return "temporarily_unavailable";
    });
    return error ? oauthError(error, error === "temporarily_unavailable" ? 503 : 400) : null;
  }
  if (url.pathname === "/token") {
    const params = await request.clone().text().then((body) => new URLSearchParams(body));
    const basicClientId = parseBasicClientId(request.headers.get("Authorization"));
    const rateSubject = basicClientId ?? params.get("client_id") ?? "anonymous";
    if (!(await consumeRequestRateLimit(runtime, env, request, "token", [rateSubject], 120, 60))) {
      return oauthError("rate_limited", 429);
    }
    const error = await validateTokenPreflight(params, basicClientId, request.url, env, runtime).catch((validationError) => {
      console.warn(validationError);
      return "temporarily_unavailable";
    });
    return error ? oauthError(error, error === "temporarily_unavailable" ? 503 : 400) : null;
  }
  if (url.pathname === "/register") {
    return new Response("Not found", { status: request.method === "GET" ? 404 : 405 });
  }
  return null;
}

async function validateAuthorizePreflight<Env extends AuthWorkerEnv>(
  params: URLSearchParams,
  env: Env,
  runtime: Runtime<Env>
): Promise<string | null> {
  if (params.get("response_type") !== "code") {
    return "authorization_code_flow_required";
  }
  if (!params.get("code_challenge") || params.get("code_challenge_method") !== "S256") {
    return "pkce_s256_required";
  }
  const resourceValues = params.getAll("resource");
  if (resourceValues.length !== 1) {
    return "single_resource_required";
  }
  try {
    requireMcpResource(resourceValues[0], runtime.config.resource);
  } catch {
    return "invalid_resource";
  }
  const clientId = params.get("client_id");
  if (!clientId) {
    return "client_id_required";
  }
  const redirectUri = params.get("redirect_uri");
  if (!redirectUri) {
    return "redirect_uri_required";
  }
  const clientError = await validateClientPreflight(clientId, env, runtime, redirectUri);
  if (clientError) {
    return clientError;
  }
  const policy = await runtime.repo.getClientPolicy(clientId);
  if (policy) {
    const allowed = parseJsonStringArray(policy.allowed_redirect_uris_json);
    if (!allowed.includes(redirectUri)) {
      return "redirect_uri_not_registered";
    }
  }
  return null;
}

async function validateTokenPreflight<Env extends AuthWorkerEnv>(
  params: URLSearchParams,
  basicClientId: string | null,
  tokenEndpointUrl: string,
  env: Env,
  runtime: Runtime<Env>
): Promise<string | null> {
  const grantType = params.get("grant_type");
  const clientId = basicClientId ?? params.get("client_id");
  if (basicClientId || params.has("client_secret")) {
    return "confidential_client_not_allowed";
  }
  if (!clientId) {
    return "client_id_required";
  }
  if ((grantType === "authorization_code" || grantType === "refresh_token") && !params.get("resource")) {
    return "resource_required";
  }
  const resourceValues = params.getAll("resource");
  if (resourceValues.length > 1) {
    return "single_resource_required";
  }
  if (resourceValues.length === 1) {
    try {
      requireMcpResource(resourceValues[0], runtime.config.resource);
    } catch {
      return "invalid_resource";
    }
  }
  if (grantType === "authorization_code" && !params.get("code_verifier")) {
    return "pkce_verifier_required";
  }
  const clientError = await validateClientPreflight(clientId, env, runtime, params.get("redirect_uri") ?? undefined);
  if (clientError) {
    return clientError;
  }
  const policy = await runtime.repo.getClientPolicy(clientId);
  const metadata = policy ? clientMetadataFromPolicy(policy) : null;
  if (metadata?.tokenEndpointAuthMethod === "private_key_jwt") {
    const assertionError = await validatePrivateKeyJwtClientAssertion(
      params,
      clientId,
      metadata,
      tokenEndpointUrl,
      env.AUTH_FLOW_KV
    );
    if (assertionError) {
      return assertionError;
    }
  }
  if (grantType === "authorization_code") {
    const redirectUri = params.get("redirect_uri");
    if (!redirectUri) {
      return "redirect_uri_required";
    }
    if (policy && !parseJsonStringArray(policy.allowed_redirect_uris_json).includes(redirectUri)) {
      return "redirect_uri_not_registered";
    }
  }
  return null;
}

async function validateClientPreflight<Env extends AuthWorkerEnv>(
  clientId: string,
  env: Env,
  runtime: Runtime<Env>,
  expectedRedirectUri?: string
): Promise<string | null> {
  let policy = await runtime.repo.getClientPolicy(clientId);
  if (isUrlClientId(clientId)) {
    if (!isPublicHttpsUrl(clientId)) {
      return "invalid_client_id_url";
    }
    if (!policy) {
      const knownMetadata = synthesizeKnownClientMetadata(clientId, expectedRedirectUri);
      const metadata =
        knownMetadata ??
        (await fetchClientMetadata(clientId).catch((error) => {
          console.warn(error);
          return null;
        }));
      if (!metadata || metadata.redirectUris.length === 0 || metadata.redirectUris.some((uri) => !isAllowedRedirectUri(uri))) {
        return "invalid_client_metadata";
      }
      await runtime.repo.createOrUpdateClientPolicy({
        clientId,
        metadata: metadata.raw,
        redirectUris: metadata.redirectUris,
        requestId: runtime.requestId
      });
      policy = await runtime.repo.getClientPolicy(clientId);
      await putProviderUrlClient(env.OAUTH_KV, clientId, metadata, policy?.first_seen_at ?? null);
      return null;
    }
    await putProviderUrlClient(env.OAUTH_KV, clientId, clientMetadataFromPolicy(policy), policy.first_seen_at);
  }
  if (!policy) {
    return "client_not_allowed";
  }
  return null;
}

function createApiHandler<Env extends AuthWorkerEnv>(
  env: Env,
  runtime: Runtime<Env>
): ExportedHandler<Env> {
  return {
    async fetch(request, requestEnv, ctx) {
      const bearer = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") ?? "";
      const helpers = getOAuthApi(buildOAuthProviderOptions(env, runtime), requestEnv);
      const token = await unwrapOAuthTokenWithRetry<OAuthTokenProps>(helpers, bearer);
      if (!token) {
        return json({ error: "invalid_token" }, 401);
      }
      const props = token.grant.props;
      if (!props) {
        return json({ error: "invalid_token_props" }, 401);
      }
      const audience = Array.isArray(token.audience) ? token.audience : [token.audience].filter(Boolean);
      if (!audience.includes(runtime.config.resource) || props.resource !== runtime.config.resource) {
        return json({ error: "invalid_resource" }, 401);
      }
      let authContext: AuthContext;
      try {
        authContext = await runtime.repo.verifyTokenProps(props, token.scope ?? []);
      } catch (error) {
        console.warn(error);
        return authorizationStateErrorResponse(error);
      }
      const authorizationRuntime: AuthorizationRuntime = {
        serverName: runtime.config.serverName,
        canUseCapability(context, capability) {
          return canUseCapability(context, capability);
        }
      };
      const server = runtime.workerOptions.createMcpServer({
        authContext,
        authorizationRuntime,
        ctx,
        env: requestEnv,
        request
      });
      return runtime.workerOptions.handleMcpRequest(request, requestEnv, ctx, server);
    }
  };
}

async function unwrapOAuthTokenWithRetry<Props>(
  helpers: OAuthHelpers,
  bearer: string
): Promise<TokenSummary<Props> | null> {
  if (!bearer) {
    return null;
  }
  let token = await helpers.unwrapToken<Props>(bearer);
  if (token) {
    return token;
  }
  let waitedMs = 0;
  for (const delayMs of ACCESS_TOKEN_UNWRAP_RETRY_DELAYS_MS) {
    waitedMs += delayMs;
    await sleep(delayMs);
    token = await helpers.unwrapToken<Props>(bearer);
    if (token) {
      console.info(`OAuth access token became readable after ${waitedMs}ms`);
      return token;
    }
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createDefaultHandler<Env extends AuthWorkerEnv>(
  env: Env,
  runtime: Runtime<Env>
): ExportedHandler<Env> {
  const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

  app.onError((error) => {
    console.warn(error);
    if (isCsrfError(error)) {
      return new Response("Form expired. Reload and try again.", { headers: SAFE_HEADERS, status: 400 });
    }
    return new Response("Internal Server Error", { status: 500 });
  });

  app.get("/", async (c) => {
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (!session) {
      return renderHome(runtime);
    }
    const validation = makeValidatedSessionContext("user.home", session, ["session"]);
    await touchSessionAfterSafeValidation(runtime, "user.home", validation);
    return renderHome(runtime, session.user.email);
  });

  app.get("/login", (c) => renderLogin(c.req.query("return_to") ?? "/"));
  app.post("/login", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const email = normalizeEmail(String(form.get("email") ?? ""));
    const returnTo = sanitizeReturnTo(String(form.get("return_to") ?? "/"));
    const ip = ipPrefix(c.req.header("CF-Connecting-IP"));
    const userAgent = await hashUserAgent(c.req.header("User-Agent"));
    const emailKey = await emailRateKey(env, "login", email);
    if (!(await runtime.repo.consumeRateLimits([`login:ip:${ip ?? "unknown"}`, emailKey], 5, 600))) {
      return renderLogin(returnTo, "Too many sign-in attempts. Try again later.");
    }
    const user = await runtime.repo.findUserByEmail(email);
    if (!user || user.status !== "active") {
      return renderLogin(returnTo, "No active account exists for this email.");
    }
    const otp = await runtime.repo.createOrReuseLoginOtpChallenge({
      maxAttempts: 6,
      resendDelaySeconds: LOGIN_OTP_RESEND_DELAY_SECONDS,
      secrets: secrets(env),
      ttlSeconds: runtime.config.otpTtlSeconds,
      userId: user.id
    });
    if (otp.state === "existing") {
      return renderOtp(user.email, otp.id, returnTo, undefined, otp.resendAfter);
    }
    try {
      await sendOtp(env, user.email, otp.code, otp.ttlSeconds, runtime.config.serverName, otp.id);
      await runtime.repo.writeAudit({
        actorUserId: user.id,
        event: "login.otp.sent",
        ipPrefix: ip,
        metadata: { email_hash_only: true },
        requestId: runtime.requestId,
        result: "success",
        userAgentHash: userAgent
      });
    } catch (error) {
      console.warn(error);
      await runtime.repo.writeAudit({
        actorUserId: user.id,
        event: "login.otp.send_failed",
        ipPrefix: ip,
        metadata: { email_hash_only: true },
        requestId: runtime.requestId,
        result: "failure",
        userAgentHash: userAgent
      });
    }
    return renderOtp(user.email, otp.id, returnTo, undefined, otp.resendAfter);
  });

  app.post("/login/resend", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const otpId = String(form.get("otp_id") ?? "");
    const returnTo = sanitizeReturnTo(String(form.get("return_to") ?? "/"));
    const email = String(form.get("email") ?? "");
    const resendAfter = displayResendAfter(form.get("resend_after"));
    if (
      !(await runtime.repo.consumeRateLimits(
        [`login-resend:ip:${ipPrefix(c.req.header("CF-Connecting-IP")) ?? "unknown"}`, `login-resend:otp:${otpId}`],
        6,
        600
      ))
    ) {
      return renderOtp(email, otpId, returnTo, "Too many resend attempts. Try again later.", resendAfter);
    }
    const result = await runtime.repo.resendOtpChallenge({
      id: otpId,
      purpose: "login",
      resendDelaySeconds: LOGIN_OTP_RESEND_DELAY_SECONDS,
      secrets: secrets(env),
      ttlSeconds: runtime.config.otpTtlSeconds
    });
    if (result.state === "too_early") {
      return renderOtp(
        email,
        otpId,
        returnTo,
        `You can resend a code in ${result.retryAfterSeconds} seconds.`,
        result.resendAfter
      );
    }
    if (result.state === "invalid" || !result.userId) {
      return renderLogin(returnTo, "No active sign-in code exists. Start sign-in again.");
    }
    try {
      await sendOtp(env, result.email, result.code, result.ttlSeconds, runtime.config.serverName, result.id);
      await runtime.repo.writeAudit({
        actorUserId: result.userId,
        event: "login.otp.resent",
        ipPrefix: ipPrefix(c.req.header("CF-Connecting-IP")),
        metadata: { email_hash_only: true },
        requestId: runtime.requestId,
        result: "success",
        userAgentHash: await hashUserAgent(c.req.header("User-Agent"))
      });
    } catch (error) {
      console.warn(error);
      await runtime.repo.writeAudit({
        actorUserId: result.userId,
        event: "login.otp.resend_failed",
        ipPrefix: ipPrefix(c.req.header("CF-Connecting-IP")),
        metadata: { email_hash_only: true },
        requestId: runtime.requestId,
        result: "failure",
        userAgentHash: await hashUserAgent(c.req.header("User-Agent"))
      });
      return renderOtp(result.email, result.id, returnTo, "Could not resend the code. Try again later.", result.resendAfter);
    }
    return renderOtp(result.email, result.id, returnTo, "A new code has been sent.", result.resendAfter);
  });

  app.post("/login/verify", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const otpId = String(form.get("otp_id") ?? "");
    const resendAfter = displayResendAfter(form.get("resend_after"));
    if (
      !(await runtime.repo.consumeRateLimits(
        [`login-verify:ip:${ipPrefix(c.req.header("CF-Connecting-IP")) ?? "unknown"}`, `login-verify:otp:${otpId}`],
        12,
        600
      ))
    ) {
      return renderOtp(
        String(form.get("email") ?? ""),
        otpId,
        sanitizeReturnTo(String(form.get("return_to") ?? "/")),
        "Too many verification attempts. Try again later.",
        resendAfter
      );
    }
    const verified = await runtime.repo.verifyOtpChallenge({
      code: String(form.get("code") ?? ""),
      id: otpId,
      secrets: secrets(env)
    });
    if (!verified || verified.purpose !== "login" || !verified.userId) {
      return renderOtp(
        String(form.get("email") ?? ""),
        String(form.get("otp_id") ?? ""),
        sanitizeReturnTo(String(form.get("return_to") ?? "/")),
        "Invalid or expired code.",
        resendAfter
      );
    }
    const session = await runtime.repo.createSession({
      ipPrefix: ipPrefix(c.req.header("CF-Connecting-IP")),
      absoluteTtlSeconds: runtime.config.sessionAbsoluteTtlSeconds,
      idleTtlSeconds: runtime.config.sessionIdleTtlSeconds,
      userAgentHash: await hashUserAgent(c.req.header("User-Agent")),
      userId: verified.userId
    });
    const headers = new Headers();
    headers.append("Set-Cookie", clearCookie(CSRF_COOKIE));
    headers.append("Set-Cookie", sessionCookie(session, runtime.config.sessionAbsoluteTtlSeconds));
    const returnTo = sanitizeReturnTo(String(form.get("return_to") ?? "/"));
    if (isAuthorizeReturnTo(returnTo)) {
      await issueOAuthReauthMarker(c.env.AUTH_FLOW_KV, runtime, headers, {
        returnTo,
        sessionIdHash: await sha256Hex(session),
        userId: verified.userId
      });
    }
    return redirect(returnTo, headers);
  });

  app.post("/logout", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (session) {
      await runtime.repo.revokeSessionByHash(session.sessionIdHash, session.user.id, runtime.requestId);
    }
    const headers = new Headers();
    headers.append("Set-Cookie", clearCookie(SESSION_COOKIE));
    headers.append("Set-Cookie", clearCookie(OAUTH_REAUTH_COOKIE));
    return redirect("/", headers, 303);
  });

  app.post("/account/delete", async (c) => {
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (!session) {
      return renderLogin("/");
    }
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    makeValidatedSessionContext("account.delete", session, ["session", "csrf"]);
    await runtime.repo.deleteUserAccount(session.user.id);
    const headers = new Headers();
    headers.append("Set-Cookie", clearCookie(SESSION_COOKIE));
    headers.append("Set-Cookie", clearCookie(CSRF_COOKIE));
    headers.append("Set-Cookie", clearCookie(OAUTH_REAUTH_COOKIE));
    return redirect("/", headers, 303);
  });

  app.get("/admin/recovery", async (c) => {
    if (!(await recoveryAllowed(runtime, c.req.query("nonce") ?? ""))) {
      return new Response("Not found", { status: 404 });
    }
    return renderRecovery(c.req.query("nonce") ?? "");
  });

  app.post("/admin/recovery", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const nonce = String(form.get("nonce") ?? "");
    if (!(await recoveryAllowed(runtime, nonce))) {
      return new Response("Not found", { status: 404 });
    }
    const email = normalizeEmail(String(form.get("email") ?? ""));
    const emailKey = await emailRateKey(env, "recovery", email);
    if (!(await runtime.repo.consumeRateLimits([emailKey], 3, 900))) {
      return renderRecovery(nonce, "Too many recovery attempts. Try again later.");
    }
    let attemptId = `recovery_attempt:${crypto.randomUUID()}`;
    let consumeId = `recovery_consume:${crypto.randomUUID()}`;
    let otpId: string = crypto.randomUUID();
    if (runtime.config.recoveryBootstrapEmails.has(email)) {
      const attempt = await runtime.repo.createRecoveryAttempt(email, runtime.config.otpTtlSeconds, runtime.requestId);
      attemptId = attempt.attemptId;
      try {
        await notifyRecoveryContacts(env, runtime, `Recovery bootstrap requested for ${email}.`, attemptId, "start");
      } catch (error) {
        console.warn(error);
        await runtime.repo.markRecoveryNotificationFailed(attemptId, runtime.requestId);
        throw error;
      }
      const consume = await runtime.repo.markRecoveryNotificationSucceeded(attemptId, runtime.requestId);
      if (!consume) {
        return new Response("Recovery bootstrap is no longer available", { status: 409 });
      }
      consumeId = consume.consumeId;
      try {
        const otp = await runtime.repo.createOtpChallenge({
          email,
          maxAttempts: 6,
          purpose: "recovery_bootstrap",
          recoveryAttemptId: attemptId,
          recoveryConsumeId: consumeId,
          secrets: secrets(env),
          ttlSeconds: runtime.config.otpTtlSeconds
        });
        otpId = otp.id;
        await sendOtp(env, email, otp.code, otp.ttlSeconds, runtime.config.serverName, otp.id);
      } catch (error) {
        console.warn(error);
        await runtime.repo.markRecoveryOtpSendFailed(attemptId, consumeId, runtime.requestId);
        throw error;
      }
    }
    return renderRecoveryVerify(nonce, email, otpId, attemptId, consumeId);
  });

  app.post("/admin/recovery/verify", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const nonce = String(form.get("nonce") ?? "");
    if (!(await recoveryAllowed(runtime, nonce))) {
      return new Response("Not found", { status: 404 });
    }
    const attemptId = String(form.get("recovery_attempt_id") ?? "");
    const consumeId = String(form.get("recovery_consume_id") ?? "");
    const verified = await runtime.repo.verifyOtpChallenge({
      code: String(form.get("code") ?? ""),
      id: String(form.get("otp_id") ?? ""),
      secrets: secrets(env)
    });
    if (
      !verified ||
      verified.purpose !== "recovery_bootstrap" ||
      verified.recoveryAttemptId !== attemptId ||
      verified.recoveryConsumeId !== consumeId ||
      !runtime.config.recoveryBootstrapEmails.has(verified.email)
    ) {
      return renderRecoveryVerify(
        nonce,
        String(form.get("email") ?? ""),
        String(form.get("otp_id") ?? ""),
        attemptId,
        consumeId,
        "Invalid or expired code."
      );
    }
    let recovered;
    try {
      await notifyRecoveryContacts(env, runtime, `Recovery bootstrap completion requested for ${verified.email}.`, attemptId, "completion-requested");
      recovered = await runtime.repo.consumeRecoveryAttemptAndCreateAdminAndSession(
        verified.email,
        attemptId,
        consumeId,
        runtime.config.sessionIdleTtlSeconds,
        runtime.config.sessionAbsoluteTtlSeconds,
        runtime.requestId
      );
    } catch (error) {
      console.warn(error);
      await runtime.repo.markRecoveryStateChangeFailed(attemptId, runtime.requestId);
      throw error;
    }
    if (!recovered) {
      return new Response("Recovery bootstrap is no longer available", { status: 409 });
    }
    const headers = new Headers();
    headers.append("Set-Cookie", clearCookie(CSRF_COOKIE));
    headers.append("Set-Cookie", sessionCookie(recovered.sessionToken, runtime.config.sessionAbsoluteTtlSeconds));
    return redirect("/admin", headers);
  });

  app.get("/admin", async (c) => {
    if (!(await runtime.repo.hasActiveAdmin()) && runtime.config.bootstrapAdminEmails.size > 0) {
      return renderBootstrap();
    }
    const admin = await requireAdmin(c.req.raw, runtime, "admin.home");
    if (admin instanceof Response) {
      return admin;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.home", admin.validation);
    return renderAdmin(
      runtime,
      admin.user.email,
      await runtime.repo.listUsers(),
      await runtime.repo.getDefaultGrantTtlSeconds(),
      await runtime.repo.listClientPolicies(),
      await runtime.repo.listSessions(),
      await runtime.repo.listConsents(),
      await runtime.repo.listJobs(),
      await runtime.repo.listAuditLogs()
    );
  });

  app.post("/admin", async (c) => {
    return handleInitialAdminPost(c.req.raw, env, runtime);
  });

  app.post("/admin/users", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.user.create");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    await runtime.repo.createUser(
      String(form.get("email") ?? ""),
      form.getAll("permissions").map(String),
      admin.user.id,
      runtime.requestId
    );
    await touchSessionAfterSafeValidation(runtime, "admin.user.create", validation);
    return redirect("/admin");
  });

  app.post("/admin/users/update", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.user.update");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    await runtime.repo.setUserState(
      String(form.get("user_id") ?? ""),
      String(form.get("status") ?? "") === "disabled" ? "disabled" : "active",
      form.getAll("permissions").map(String),
      admin.user.id,
      runtime.requestId
    );
    await touchSessionAfterSafeValidation(runtime, "admin.user.update", validation);
    return redirect("/admin");
  });

  app.post("/admin/oauth-policy", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.oauth_policy.update");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const parsed = parseGrantTimeoutForm(
      String(form.get("default_grant_timeout_mode") ?? ""),
      String(form.get("default_grant_ttl_seconds") ?? ""),
      false
    );
    if (parsed instanceof Response) {
      return parsed;
    }
    await runtime.repo.setDefaultGrantTtlSeconds(parsed.ttlSeconds, admin.user.id, runtime.requestId);
    await touchSessionAfterSafeValidation(runtime, "admin.oauth_policy.update", validation);
    return redirect("/admin");
  });

  app.post("/admin/users/grant-timeout", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.user_grant_timeout.update");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const userId = String(form.get("user_id") ?? "");
    const parsed = parseGrantTimeoutForm(
      String(form.get("grant_timeout_mode") ?? ""),
      String(form.get("grant_ttl_seconds") ?? ""),
      true
    );
    if (parsed instanceof Response) {
      return parsed;
    }
    const outcome = parsed.inherit
      ? await runtime.repo.clearUserGrantTtlSeconds(userId, admin.user.id, runtime.requestId)
      : await runtime.repo.setUserGrantTtlSeconds(userId, parsed.ttlSeconds, admin.user.id, runtime.requestId);
    const failed = adminOutcomeResponse("User MCP OAuth expiration update", outcome);
    if (failed) {
      return failed;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.user_grant_timeout.update", validation);
    return redirect("/admin");
  });

  app.post("/admin/users/bulk", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.users.bulk");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const userIds = [...new Set(form.getAll("user_id").map(String).filter(Boolean))];
    if (userIds.length === 0) {
      return new Response("Select at least one user", { status: 400 });
    }
    const users = await runtime.repo.listUsers();
    const usersById = new Map(users.map((user) => [user.id, user]));
    if (userIds.some((userId) => !usersById.has(userId))) {
      return new Response("Unknown user selected", { status: 400 });
    }
    const action = parseBulkUserOperationAction(String(form.get("action") ?? ""));
    if (!action) {
      return new Response("Unknown bulk action", { status: 400 });
    }
    let grantTtlSeconds: number | null | undefined;
    let inheritGrantTtl = false;
    if (action === "set_grant_timeout") {
      const parsed = parseGrantTimeoutForm(
        String(form.get("bulk_grant_timeout_mode") ?? ""),
        String(form.get("bulk_grant_ttl_seconds") ?? ""),
        true
      );
      if (parsed instanceof Response) {
        return parsed;
      }
      inheritGrantTtl = parsed.inherit;
      grantTtlSeconds = parsed.ttlSeconds;
    }
    if (action === "disable") {
      const activeAdmins = users.filter((user) => user.status === "active" && user.permissions.includes("admin"));
      const selected = new Set(userIds);
      if (activeAdmins.length > 0 && activeAdmins.every((user) => selected.has(user.id))) {
        return new Response("Cannot disable every active admin", { status: 409 });
      }
    }
    if (String(form.get("confirmed") ?? "") !== "yes") {
      await touchSessionAfterSafeValidation(runtime, "admin.users.bulk", validation);
      return renderBulkUserConfirmation(
        runtime,
        admin.user.email,
        String(form.get("csrf_token") ?? ""),
        action,
        userIds.map((userId) => usersById.get(userId)).filter((user): user is AdminUserRow => Boolean(user)),
        String(form.get("bulk_grant_timeout_mode") ?? ""),
        String(form.get("bulk_grant_ttl_seconds") ?? "")
      );
    }
    try {
      await runtime.repo.bulkUpdateUsers({
        action,
        actorUserId: admin.user.id,
        inheritGrantTtl,
        ...(grantTtlSeconds === undefined ? {} : { grantTtlSeconds }),
        requestId: runtime.requestId,
        userIds
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message === "Cannot disable every active admin" || message === "Cannot remove the last active admin") {
        return new Response("Cannot disable every active admin", { status: 409 });
      }
      if (message === "Unknown user selected" || message === "Select at least one user") {
        return new Response(message, { status: 400 });
      }
      throw error;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.users.bulk", validation);
    return redirect("/admin");
  });

  app.post("/admin/clients/revoke", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.client.revoke");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const clientId = String(form.get("client_id") ?? "");
    const outcome = await runtime.repo.revokeClient(clientId, admin.user.id, runtime.requestId);
    const failed = adminOutcomeResponse("Client delete", outcome);
    if (failed) {
      return failed;
    }
    await c.env.OAUTH_PROVIDER.deleteClient(clientId).catch(async (error) => {
      await runtime.repo.enqueueJob({
        idempotencyKey: `delete-client:${clientId}`,
        payload: { clientId },
        requestId: runtime.requestId,
        targetClientId: clientId,
        type: "delete_provider_client"
      });
      console.warn(error);
    });
    await touchSessionAfterSafeValidation(runtime, "admin.client.revoke", validation);
    return redirect("/admin");
  });

  app.post("/admin/sessions/revoke", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.session.revoke");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const outcome = await runtime.repo.revokeSessionByHash(
      String(form.get("session_id_hash") ?? ""),
      admin.user.id,
      runtime.requestId
    );
    const failed = adminOutcomeResponse("Session revoke", outcome);
    if (failed) {
      return failed;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.session.revoke", validation);
    return redirect("/admin");
  });

  app.post("/admin/users/sessions/revoke", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.user.sessions.revoke");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const outcome = await runtime.repo.revokeUserSessions(String(form.get("user_id") ?? ""), admin.user.id, runtime.requestId);
    const failed = adminOutcomeResponse("User sessions revoke", outcome);
    if (failed) {
      return failed;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.user.sessions.revoke", validation);
    return redirect("/admin");
  });

  app.post("/admin/consents/revoke", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.consent.revoke");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const outcome = await runtime.repo.revokeConsent(String(form.get("consent_id") ?? ""), admin.user.id, runtime.requestId);
    const failed = adminOutcomeResponse("Consent revoke", outcome);
    if (failed) {
      return failed;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.consent.revoke", validation);
    return redirect("/admin");
  });

  app.post("/admin/users/consents/revoke", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.user.consents.revoke");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const outcome = await runtime.repo.revokeUserConsents(String(form.get("user_id") ?? ""), admin.user.id, runtime.requestId);
    const failed = adminOutcomeResponse("User consents revoke", outcome);
    if (failed) {
      return failed;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.user.consents.revoke", validation);
    return redirect("/admin");
  });

  app.get("/admin/provider-grants", async (c) => {
    const admin = await requireAdmin(c.req.raw, runtime, "admin.home");
    if (admin instanceof Response) {
      return admin;
    }
    const userId = String(c.req.query("user_id") ?? "");
    if (!userId) {
      return new Response("user_id is required", { status: 400 });
    }
    const cursor = c.req.query("cursor") || undefined;
    const result = await c.env.OAUTH_PROVIDER.listUserGrants(userId, cursor ? { cursor, limit: 50 } : { limit: 50 });
    return renderProviderGrants(
      runtime,
      admin.user.email,
      userId,
      result.items,
      result.cursor,
      await annotateProviderGrants(runtime, userId, result.items)
    );
  });

  app.post("/admin/grants/revoke", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.provider_grant.revoke");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const userId = String(form.get("user_id") ?? "");
    const grantId = String(form.get("grant_id") ?? "");
    const found = await lookupGrantForRevoke(c.env.OAUTH_PROVIDER, userId, grantId, runtime.config);
    if (found.outcome !== "found") {
      await runtime.repo.writeAudit({
        actorUserId: admin.user.id,
        event: "provider.grant.revoke.lookup_failed",
        metadata: { grantId, outcome: found.outcome },
        requestId: runtime.requestId,
        result: found.outcome === "not_found" ? "failure" : "denied",
        targetUserId: userId
      });
      return new Response("Provider grant could not be verified", { status: 409 });
    }
    const metadata = parseGrantMetadata(found.grant);
    const consent = metadata ? await runtime.repo.getConsentById(metadata.consent_id) : null;
    if (!metadata || !consent || !grantMatchesConsent(found.grant, metadata, consent)) {
      await runtime.repo.writeAudit({
        actorUserId: admin.user.id,
        event: "provider.grant.revoke.denied",
        metadata: { cause: "metadata_mismatch", grantId },
        requestId: runtime.requestId,
        result: "denied",
        targetUserId: userId
      });
      return new Response("Provider grant metadata is stale or incomplete", { status: 409 });
    }
    const outcome = await runtime.repo.revokeProviderGrantBackedConsent({
      actorUserId: admin.user.id,
      clientId: metadata.client_id,
      consentId: metadata.consent_id,
      grantId,
      requestId: runtime.requestId,
      resource: metadata.resource,
      scopeHash: metadata.scope_hash,
      userId
    });
    const failed = adminOutcomeResponse("Provider grant revoke", outcome);
    if (failed) {
      return failed;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.provider_grant.revoke", validation);
    return redirect(`/admin/provider-grants?user_id=${encodeURIComponent(userId)}`);
  });

  app.post("/admin/users/authorization/revoke", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.user.authorization.revoke");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const outcome = await runtime.repo.revokeUserAuthorization({
      actorUserId: admin.user.id,
      requestId: runtime.requestId,
      userId: String(form.get("user_id") ?? "")
    });
    const failed = adminOutcomeResponse("User authorization revoke", outcome);
    if (failed) {
      return failed;
    }
    await touchSessionAfterSafeValidation(runtime, "admin.user.authorization.revoke", validation);
    return redirect("/admin");
  });

  app.get("/admin/step-up", (c) => renderStepUp(sanitizeReturnTo(c.req.query("return_to") ?? "/admin")));
  app.post("/admin/step-up", async (c) => {
    const admin = await requireAdmin(c.req.raw, runtime);
    if (admin instanceof Response) {
      return admin;
    }
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    if (
      !(await runtime.repo.consumeRateLimits(
        [`admin-step-up:user:${admin.user.id}`, `admin-step-up:ip:${ipPrefix(c.req.header("CF-Connecting-IP")) ?? "unknown"}`],
        5,
        600
      ))
    ) {
      return renderStepUp(sanitizeReturnTo(String(form.get("return_to") ?? "/admin")), "Too many admin code requests.");
    }
    const otp = await runtime.repo.createOtpChallenge({
      email: admin.user.email,
      maxAttempts: 6,
      purpose: "admin_step_up",
      secrets: secrets(env),
      ttlSeconds: runtime.config.otpTtlSeconds,
      userId: admin.user.id
    });
    await sendOtp(env, admin.user.email, otp.code, otp.ttlSeconds, runtime.config.serverName, otp.id);
    return renderStepUpVerify(otp.id, sanitizeReturnTo(String(form.get("return_to") ?? "/admin")));
  });
  app.post("/admin/step-up/verify", async (c) => {
    const admin = await requireAdmin(c.req.raw, runtime);
    if (admin instanceof Response) {
      return admin;
    }
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const otpId = String(form.get("otp_id") ?? "");
    if (
      !(await runtime.repo.consumeRateLimits(
        [`admin-step-up-verify:user:${admin.user.id}`, `admin-step-up-verify:otp:${otpId}`],
        8,
        600
      ))
    ) {
      return renderStepUpVerify(
        otpId,
        sanitizeReturnTo(String(form.get("return_to") ?? "/admin")),
        "Too many verification attempts."
      );
    }
    const verified = await runtime.repo.verifyOtpChallenge({
      code: String(form.get("code") ?? ""),
      id: otpId,
      secrets: secrets(env)
    });
    if (!verified || verified.purpose !== "admin_step_up" || verified.userId !== admin.user.id) {
      return renderStepUpVerify(String(form.get("otp_id") ?? ""), sanitizeReturnTo(String(form.get("return_to") ?? "/admin")), "Invalid or expired code.");
    }
    const outcome = await runtime.repo.markStepUp(admin.sessionIdHash, admin.user.id, runtime.requestId);
    if (outcome !== "changed") {
      return new Response("Admin step-up could not be completed", { status: 409 });
    }
    return redirect(sanitizeReturnTo(String(form.get("return_to") ?? "/admin")));
  });

  app.post("/authorize/reauth", async (c) => {
    const form = await c.req.raw.formData();
    const returnTo = sanitizeAuthorizeReturnTo(String(form.get("return_to") ?? "/"));
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (!session) {
      return renderLogin(returnTo);
    }
    try {
      assertCsrf(c.req.raw, form);
    } catch (error) {
      if (isCsrfError(error)) {
        return renderAuthorizeReauth(runtime, session.user.email, returnTo, "Authorization form expired. Try again.");
      }
      throw error;
    }
    const email = normalizeEmail(String(form.get("email") ?? ""));
    if (email !== session.user.email) {
      return renderAuthorizeReauth(runtime, session.user.email, returnTo, "Use the signed-in account email.");
    }
    if (
      !(await runtime.repo.consumeRateLimits(
        [`oauth-reauth:user:${session.user.id}`, `oauth-reauth:ip:${ipPrefix(c.req.header("CF-Connecting-IP")) ?? "unknown"}`],
        5,
        600
      ))
    ) {
      return renderAuthorizeReauth(runtime, session.user.email, returnTo, "Too many authorization code requests.");
    }
    const otp = await runtime.repo.createOrReuseUserOtpChallenge({
      maxAttempts: 6,
      purpose: OAUTH_AUTHORIZE_OTP_PURPOSE,
      resendDelaySeconds: LOGIN_OTP_RESEND_DELAY_SECONDS,
      secrets: secrets(env),
      ttlSeconds: runtime.config.otpTtlSeconds,
      userId: session.user.id
    });
    if (otp.state === "existing") {
      return renderAuthorizeReauthOtp(runtime, session.user.email, otp.id, returnTo, undefined, otp.resendAfter);
    }
    try {
      await sendOtp(env, session.user.email, otp.code, otp.ttlSeconds, runtime.config.serverName, otp.id);
    } catch (error) {
      console.warn(error);
      return renderAuthorizeReauthOtp(
        runtime,
        session.user.email,
        otp.id,
        returnTo,
        "Could not send the code. Use resend after the countdown.",
        otp.resendAfter
      );
    }
    return renderAuthorizeReauthOtp(runtime, session.user.email, otp.id, returnTo, undefined, otp.resendAfter);
  });

  app.post("/authorize/reauth/resend", async (c) => {
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (!session) {
      return new Response("Sign-in required", { status: 401 });
    }
    const form = await c.req.raw.formData();
    const otpId = String(form.get("otp_id") ?? "");
    const returnTo = sanitizeAuthorizeReturnTo(String(form.get("return_to") ?? "/"));
    const resendAfter = displayResendAfter(form.get("resend_after"));
    try {
      assertCsrf(c.req.raw, form);
    } catch (error) {
      if (isCsrfError(error)) {
        return renderAuthorizeReauthOtp(runtime, session.user.email, otpId, returnTo, "Authorization form expired. Try again.", resendAfter);
      }
      throw error;
    }
    if (
      !(await runtime.repo.consumeRateLimits(
        [`oauth-reauth-resend:user:${session.user.id}`, `oauth-reauth-resend:otp:${otpId}`],
        6,
        600
      ))
    ) {
      return renderAuthorizeReauthOtp(runtime, session.user.email, otpId, returnTo, "Too many resend attempts.", resendAfter);
    }
    const result = await runtime.repo.resendOtpChallenge({
      id: otpId,
      purpose: OAUTH_AUTHORIZE_OTP_PURPOSE,
      resendDelaySeconds: LOGIN_OTP_RESEND_DELAY_SECONDS,
      secrets: secrets(env),
      ttlSeconds: runtime.config.otpTtlSeconds
    });
    if (result.state === "too_early") {
      return renderAuthorizeReauthOtp(
        runtime,
        session.user.email,
        otpId,
        returnTo,
        `You can resend a code in ${result.retryAfterSeconds} seconds.`,
        result.resendAfter
      );
    }
    if (result.state === "invalid" || result.userId !== session.user.id) {
      return renderAuthorizeReauth(runtime, session.user.email, returnTo, "No active authorization code exists.");
    }
    try {
      await sendOtp(env, session.user.email, result.code, result.ttlSeconds, runtime.config.serverName, result.id);
    } catch (error) {
      console.warn(error);
      return renderAuthorizeReauthOtp(
        runtime,
        session.user.email,
        result.id,
        returnTo,
        "Could not resend the code. Try again later.",
        result.resendAfter
      );
    }
    return renderAuthorizeReauthOtp(runtime, session.user.email, result.id, returnTo, "A new code has been sent.", result.resendAfter);
  });

  app.post("/authorize/reauth/verify", async (c) => {
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (!session) {
      return new Response("Sign-in required", { status: 401 });
    }
    const form = await c.req.raw.formData();
    const otpId = String(form.get("otp_id") ?? "");
    const returnTo = sanitizeAuthorizeReturnTo(String(form.get("return_to") ?? "/"));
    const resendAfter = displayResendAfter(form.get("resend_after"));
    try {
      assertCsrf(c.req.raw, form);
    } catch (error) {
      if (isCsrfError(error)) {
        return renderAuthorizeReauthOtp(runtime, session.user.email, otpId, returnTo, "Authorization form expired. Try again.", resendAfter);
      }
      throw error;
    }
    if (
      !(await runtime.repo.consumeRateLimits(
        [`oauth-reauth-verify:user:${session.user.id}`, `oauth-reauth-verify:otp:${otpId}`],
        12,
        600
      ))
    ) {
      return renderAuthorizeReauthOtp(runtime, session.user.email, otpId, returnTo, "Too many verification attempts.", resendAfter);
    }
    const verified = await runtime.repo.verifyOtpChallenge({
      code: String(form.get("code") ?? ""),
      id: otpId,
      secrets: secrets(env)
    });
    if (!verified || verified.purpose !== OAUTH_AUTHORIZE_OTP_PURPOSE || verified.userId !== session.user.id) {
      return renderAuthorizeReauthOtp(runtime, session.user.email, otpId, returnTo, "Invalid or expired code.", resendAfter);
    }
    const headers = new Headers();
    headers.append("Set-Cookie", clearCookie(CSRF_COOKIE));
    await issueOAuthReauthMarker(c.env.AUTH_FLOW_KV, runtime, headers, {
      returnTo,
      sessionIdHash: session.sessionIdHash,
      userId: session.user.id
    });
    return redirect(returnTo, headers);
  });

  app.get("/authorize", async (c) => {
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    const returnTo = `${new URL(c.req.url).pathname}${new URL(c.req.url).search}`;
    if (!session) {
      return renderLogin(returnTo);
    }
    const reauth = await consumeOAuthReauthMarker(c.req.raw, c.env.AUTH_FLOW_KV, session, returnTo);
    if (!reauth.ok) {
      return renderAuthorizeReauth(runtime, session.user.email, returnTo);
    }
    const validation = makeValidatedSessionContext("authorize.get", session, ["session"]);
    const oauthReq = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
    const response = await renderOrCompleteAuthorization(c.env.OAUTH_PROVIDER, c.env.AUTH_FLOW_KV, runtime, session, oauthReq);
    response.headers.append("Set-Cookie", clearCookie(OAUTH_REAUTH_COOKIE));
    await touchSessionAfterSafeValidation(runtime, "authorize.get", validation);
    return response;
  });

  app.post("/authorize", async (c) => {
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (!session) {
      return new Response("Sign-in required", { status: 401 });
    }
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const pendingId = String(form.get("pending_id") ?? "");
    const payload = await readPending(c.env.AUTH_FLOW_KV, pendingId);
    if (!payload || payload.user_id !== session.user.id || payload.session_id_hash !== session.sessionIdHash) {
      return new Response("Authorization request expired", { status: 400 });
    }
    if (!(await verifyPendingPayloadBinding(runtime, payload))) {
      return new Response("Invalid authorization flow", { status: 400 });
    }
    if ((await sha256Hex(String(form.get("csrf_token") ?? ""))) !== payload.csrf_hash) {
      return new Response("Invalid authorization flow", { status: 400 });
    }
    if (String(form.get("action") ?? "") !== "approve") {
      return oauthRedirectError(payload.request_json, "access_denied", "The user denied the authorization request.");
    }
    const claim = await runtime.repo.beginPendingAuthorization({
      clientId: payload.client_id,
      csrfHash: payload.csrf_hash,
      leaseSeconds: 60,
      payloadDigest: payload.payload_digest,
      pendingId,
      redirectUri: payload.redirect_uri,
      resource: payload.resource,
      scopeHash: payload.scope_hash,
      sessionIdHash: session.sessionIdHash,
      userId: session.user.id
    });
    if (claim.state === "completed") {
      return new Response("Authorization was already completed", { status: 409 });
    }
    if (claim.state === "busy") {
      return new Response("Authorization request is already being processed", { status: 409 });
    }
    if (!claim.leaseId) {
      return new Response("Authorization request is already being processed", { status: 409 });
    }
    const leaseId = claim.leaseId;
    try {
      const consumed = await runtime.repo.completePendingAuthorization(pendingId, leaseId);
      if (!consumed) {
        return new Response("Authorization request is already being processed", { status: 409 });
      }
      const response = await completeAuthorization(c.env.OAUTH_PROVIDER, runtime, session, payload.request_json, true);
      return response;
    } catch (error) {
      console.warn(error);
      await runtime.repo.failPendingAuthorization(pendingId, leaseId);
      throw error;
    }
  });

  return app;
}

async function renderOrCompleteAuthorization<Env extends AuthWorkerEnv>(
  helpers: OAuthHelpers,
  flowKv: KVNamespace,
  runtime: Runtime<Env>,
  session: { sessionIdHash: string; user: { id: string; email: string; authz_version: number }; adminStepUpAt: string | null },
  request: AuthRequest
): Promise<Response> {
  const requested = assertKnownScopes(request.scope.length ? request.scope : ["profile"]);
  const permissions = await runtime.repo.listPermissions(session.user.id);
  const scopes = requested.filter((scope) => scope === "profile" || permissions.includes("admin") || permissions.includes(scope));
  if (scopes.length !== requested.length) {
    return oauthRedirectError(request, "insufficient_scope", "The signed-in user cannot grant every requested scope.");
  }
  const resource = requireMcpResource(resourceFromAuthRequest(request), runtime.config.resource);
  const policy = await runtime.repo.getClientPolicy(request.clientId);
  if (!policy) {
    return oauthRedirectError(request, "unauthorized_client", "Client is not allowed.");
  }
  const existing = await runtime.repo.getActiveConsent({
    clientId: request.clientId,
    resource,
    scopes,
    userId: session.user.id
  });
  if (existing && existing.authz_version === session.user.authz_version && existing.client_version === policy.client_version) {
    return completeAuthorization(helpers, runtime, session, request, false);
  }
  const pendingId = crypto.randomUUID();
  const scopeHash = await hashScope(scopes);
  const csrf = randomBase64Url(16);
  const payload: Omit<PendingAuthorizationPayload, "payload_digest"> = {
    client_id: request.clientId,
    csrf_hash: await sha256Hex(csrf),
    expires_at: new Date(Date.now() + runtime.config.pendingAuthorizationTtlSeconds * 1000).toISOString(),
    pending_id: pendingId,
    redirect_uri: request.redirectUri,
    request_json: request,
    resource,
    scope_hash: scopeHash,
    session_id_hash: session.sessionIdHash,
    user_id: session.user.id
  };
  const payloadDigest = await sha256Hex(JSON.stringify(payload));
  const prepared = await runtime.repo.beginPendingAuthorization({
    clientId: request.clientId,
    csrfHash: payload.csrf_hash,
    leaseSeconds: 0,
    payloadDigest,
    pendingId,
    redirectUri: request.redirectUri,
    resource,
    scopeHash,
    sessionIdHash: session.sessionIdHash,
    userId: session.user.id
  });
  if (prepared.state === "completed" || prepared.state === "busy") {
    return oauthRedirectError(request, "access_denied", "Authorization request is already being processed.");
  }
  await writePending(flowKv, runtime, pendingId, { ...payload, payload_digest: payloadDigest });
  return renderConsent(runtime, pendingId, request, scopes, session.user.email, csrf);
}

async function completeAuthorization<Env extends AuthWorkerEnv>(
  helpers: OAuthHelpers,
  runtime: Runtime<Env>,
  session: { user: { id: string; email: string; authz_version: number } },
  request: AuthRequest,
  recordConsent: boolean
): Promise<Response> {
  const currentUser = await runtime.repo.findUserById(session.user.id);
  const policy = await runtime.repo.getClientPolicy(request.clientId);
  if (!currentUser || currentUser.status !== "active" || !policy) {
    return oauthRedirectError(request, "access_denied", "Authorization state changed.");
  }
  const scopes = assertKnownScopes(request.scope.length ? request.scope : ["profile"]);
  const permissions = await runtime.repo.listPermissions(currentUser.id);
  const allowedScopes = scopes.filter(
    (scope) => scope === "profile" || permissions.includes("admin") || permissions.includes(scope)
  );
  if (allowedScopes.length !== scopes.length) {
    return oauthRedirectError(request, "insufficient_scope", "The signed-in user cannot grant every requested scope.");
  }
  const resource = requireMcpResource(resourceFromAuthRequest(request), runtime.config.resource);
  const grantTtlSeconds = await runtime.repo.getEffectiveGrantTtlSeconds(currentUser.id);
  const consentExpiresAt =
    grantTtlSeconds === null ? null : new Date(Date.now() + grantTtlSeconds * 1000).toISOString();
  const consent =
    recordConsent
      ? await runtime.repo.saveConsent({
          authzVersion: currentUser.authz_version,
          clientId: request.clientId,
          clientSnapshot: policy,
          clientVersion: policy.client_version,
          expiresAt: consentExpiresAt,
          redirectUri: request.redirectUri,
          resource,
          scopes,
          userId: currentUser.id
        })
      : await runtime.repo.getActiveConsent({
          clientId: request.clientId,
          resource,
          scopes,
          userId: currentUser.id
        });
  if (!consent) {
    return oauthRedirectError(request, "access_denied", "Consent is required.");
  }
  const props: OAuthTokenProps = {
    authz_version: currentUser.authz_version,
    client_id: request.clientId,
    client_version: policy.client_version,
    consent_id: consent.id,
    resource,
    scope_hash: await hashScope(scopes),
    user_id: currentUser.id
  };
  const { redirectTo } = await helpers.completeAuthorization({
    metadata: props,
    props,
    request,
    revokeExistingGrants: false,
    scope: scopes,
    userId: currentUser.id
  });
  return redirect(redirectTo);
}

async function validateTokenExchange<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  input: TokenExchangeCallbackOptions
) {
  const props = input.props as OAuthTokenProps;
  if (!props?.user_id || !isScopeSubset(input.requestedScope, input.scope)) {
    throw new OAuthError("invalid_grant", { description: "Invalid token grant props" });
  }
  try {
    await runtime.repo.verifyTokenProps(props, input.requestedScope);
  } catch (error) {
    if (isTransientAuthStateError(error)) {
      throw new OAuthError("temporarily_unavailable", { description: "Authorization state is temporarily unavailable" });
    }
    throw new OAuthError("invalid_grant", { description: "Authorization state is no longer current" });
  }
  return {
    accessTokenProps: props,
    accessTokenScope: assertKnownScopes(input.requestedScope),
    accessTokenTTL: runtime.config.accessTokenTtlSeconds,
    newProps: props
  };
}

function canUseCapability(context: AuthContext, capability: CapabilityRequirement): boolean {
  const scopeSet = new Set(context.scopes);
  const permissionSet = new Set(context.permissions);
  const isAdmin = permissionSet.has("admin");
  return (
    capability.requiredScopes.every((scope) => scopeSet.has(scope)) &&
    (isAdmin || capability.requiredPermissions.every((permission) => permissionSet.has(permission)))
  );
}

async function requireAdmin<Env extends AuthWorkerEnv>(
  request: Request,
  runtime: Runtime<Env>,
  routeId: RouteId = "admin.home"
): Promise<AdminSession | Response> {
  const session = await runtime.repo.getSession(readCookie(request, SESSION_COOKIE));
  if (!session) {
    return renderLogin("/admin");
  }
  const permissions = await runtime.repo.listPermissions(session.user.id);
  if (!permissions.includes("admin")) {
    return new Response("Forbidden", { status: 403 });
  }
  return {
    adminStepUpAt: session.adminStepUpAt,
    sessionIdHash: session.sessionIdHash,
    user: session.user,
    validation: makeValidatedSessionContext(routeId, session, ["session", "admin"])
  };
}

async function requireHighRiskAdmin<Env extends AuthWorkerEnv>(
  request: Request,
  runtime: Runtime<Env>,
  routeId: RouteId,
  returnTo = "/admin"
): Promise<{ admin: AdminSession; form: FormData; validation: ValidatedSessionContext } | Response> {
  const admin = await requireAdmin(request, runtime, routeId);
  if (admin instanceof Response) {
    return admin;
  }
  const form = await request.formData();
  assertCsrf(request, form);
  if (!isRecentStepUp(admin.adminStepUpAt, runtime.config.adminStepUpTtlSeconds)) {
    return redirect(`/admin/step-up?return_to=${encodeURIComponent(returnTo)}`);
  }
  const validation = addValidationCheck(addValidationCheck(admin.validation, "csrf"), "freshStepUp");
  return { admin, form, validation };
}

function makeValidatedSessionContext(
  routeId: RouteId,
  session: ValidatedSessionContext["session"],
  checks: readonly ValidationCheck[]
): ValidatedSessionContext {
  return {
    routeId,
    sealed: VALIDATED_SESSION_CONTEXT,
    session,
    satisfiedChecks: new Set(checks)
  };
}

function addValidationCheck(context: ValidatedSessionContext, check: ValidationCheck): ValidatedSessionContext {
  return makeValidatedSessionContext(context.routeId, context.session, [...context.satisfiedChecks, check]);
}

function assertFreshStepUp<Env extends AuthWorkerEnv>(
  admin: { adminStepUpAt: string | null },
  runtime: Runtime<Env>
): void {
  if (!isRecentStepUp(admin.adminStepUpAt, runtime.config.adminStepUpTtlSeconds)) {
    throw new Error("fresh_step_up_required");
  }
}

async function touchSessionAfterSafeValidation<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  routeId: RouteId,
  context: ValidatedSessionContext
): Promise<void> {
  const policy = TOUCH_POLICIES[routeId];
  if (!policy || !policy.touch || context.sealed !== VALIDATED_SESSION_CONTEXT || context.routeId !== routeId) {
    throw new Error("Session touch is not allowed for this route");
  }
  for (const check of policy.required) {
    if (!context.satisfiedChecks.has(check)) {
      throw new Error(`Session touch missing validation: ${check}`);
    }
  }
  await runtime.repo.touchSessionAfterSafeValidation(
    context.session.sessionIdHash,
    runtime.config.sessionIdleTtlSeconds,
    runtime.config.sessionTouchIntervalSeconds
  );
}

async function sendOtp<Env extends AuthWorkerEnv>(
  env: Env,
  to: string,
  code: string,
  ttlSeconds: number,
  serverName: string,
  idempotencyKey: string
): Promise<void> {
  await sendEmailViaResend(env, {
    idempotencyKey,
    subject: `${serverName} login code`,
    text: `Your ${serverName} login code is ${code}. It expires in ${Math.floor(ttlSeconds / 60)} minutes.`,
    to
  });
}

async function sendEmailViaResend<Env extends AuthWorkerEnv>(
  env: Env,
  input: { to: string; subject: string; text: string; idempotencyKey: string }
): Promise<void> {
  const response = await fetch("https://api.resend.com/emails", {
    body: JSON.stringify({
      from: env.OTP_EMAIL_FROM,
      reply_to: env.OTP_EMAIL_REPLY_TO,
      subject: input.subject,
      text: input.text,
      to: input.to
    }),
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
      "Idempotency-Key": input.idempotencyKey
    },
    method: "POST"
  });
  if (!response.ok) {
    throw new Error(`Resend failed with ${response.status}`);
  }
}

async function fetchClientMetadata(clientId: string): Promise<ClientMetadataDocument> {
  const response = await fetch(clientId, {
    headers: CLIENT_METADATA_FETCH_HEADERS,
    redirect: "manual",
    signal: AbortSignal.timeout(CLIENT_METADATA_FETCH_TIMEOUT_MS)
  });
  if (response.status >= 300 && response.status < 400) {
    throw new Error("Client metadata redirects are not accepted");
  }
  if (!response.ok) {
    throw new Error(`Client metadata fetch failed with ${response.status}`);
  }
  const raw = await readJsonWithLimit(response, CLIENT_METADATA_MAX_BYTES);
  return normalizeClientMetadata(clientId, raw);
}

function normalizeClientMetadata(clientId: string, raw: unknown): ClientMetadataDocument {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Client metadata must be a JSON object");
  }
  const metadata = raw as Record<string, unknown>;
  const declaredClientId = optionalString(metadata.client_id, "client_id") ?? clientId;
  if (declaredClientId !== clientId) {
    throw new Error("Client metadata client_id does not match the request client_id");
  }
  const redirectUris = requiredStringArray(metadata.redirect_uris, "redirect_uris");
  const grantTypes = optionalStringArray(metadata.grant_types, "grant_types") ?? ["authorization_code"];
  const responseTypes = optionalStringArray(metadata.response_types, "response_types") ?? ["code"];
  if (!grantTypes.includes("authorization_code")) {
    throw new Error("Client metadata must support authorization_code");
  }
  if (!responseTypes.includes("code")) {
    throw new Error("Client metadata must support code response type");
  }
  const tokenEndpointAuthMethod = parseClientMetadataAuthMethod(metadata.token_endpoint_auth_method);
  const jwksUri = optionalString(metadata.jwks_uri, "jwks_uri");
  const jwks = parseInlineJwks(metadata.jwks);
  if (tokenEndpointAuthMethod === "private_key_jwt") {
    const signingAlg = optionalString(metadata.token_endpoint_auth_signing_alg, "token_endpoint_auth_signing_alg");
    if (signingAlg && signingAlg !== "RS256") {
      throw new Error("Only RS256 private_key_jwt client assertions are supported");
    }
    if (!jwksUri && !jwks) {
      throw new Error("private_key_jwt clients must publish jwks_uri or jwks");
    }
  }
  const document: ClientMetadataDocument = {
    grantTypes,
    raw: metadata,
    redirectUris,
    responseTypes,
    tokenEndpointAuthMethod
  };
  const contacts = optionalStringArray(metadata.contacts, "contacts");
  const logoUri = optionalString(metadata.logo_uri, "logo_uri");
  const clientName = optionalString(metadata.client_name, "client_name");
  const clientUri = optionalString(metadata.client_uri, "client_uri");
  const policyUri = optionalString(metadata.policy_uri, "policy_uri");
  const tosUri = optionalString(metadata.tos_uri, "tos_uri");
  if (contacts) document.contacts = contacts;
  if (jwks) document.jwks = jwks;
  if (jwksUri) document.jwksUri = jwksUri;
  if (logoUri) document.logoUri = logoUri;
  if (clientName) document.clientName = clientName;
  if (clientUri) document.clientUri = clientUri;
  if (policyUri) document.policyUri = policyUri;
  if (tosUri) document.tosUri = tosUri;
  return document;
}

function clientMetadataFromPolicy(policy: ClientPolicyRow): ClientMetadataDocument {
  return normalizeClientMetadata(policy.client_id, JSON.parse(policy.metadata_snapshot_json));
}

function synthesizeKnownClientMetadata(clientId: string, expectedRedirectUri?: string): ClientMetadataDocument | null {
  try {
    const url = new URL(clientId);
    if (url.protocol !== "https:" || url.hostname !== "chatgpt.com") {
      return null;
    }
    const match = url.pathname.match(/^\/oauth\/([^/]+)\/client\.json$/);
    const connectorId = match?.[1];
    if (!connectorId || url.search || url.hash || url.username || url.password) {
      return null;
    }
    const redirectUri = `https://chatgpt.com/connector/oauth/${connectorId}`;
    if (expectedRedirectUri && expectedRedirectUri !== redirectUri) {
      return null;
    }
    return normalizeClientMetadata(clientId, {
      client_id: clientId,
      client_name: "ChatGPT",
      client_uri: "https://chatgpt.com/",
      grant_types: ["authorization_code", "refresh_token"],
      redirect_uris: [redirectUri],
      response_types: ["code"],
      token_endpoint_auth_method: "none"
    });
  } catch {
    return null;
  }
}

async function putProviderUrlClient(
  kv: KVNamespace,
  clientId: string,
  metadata: ClientMetadataDocument,
  firstSeenAt: string | null
): Promise<void> {
  const registrationDate =
    firstSeenAt && Number.isFinite(Date.parse(firstSeenAt))
      ? Math.floor(Date.parse(firstSeenAt) / 1000)
      : Math.floor(Date.now() / 1000);
  const providerClient: ProviderClientRecord = {
    clientId,
    grantTypes: metadata.grantTypes,
    redirectUris: metadata.redirectUris,
    registrationDate,
    responseTypes: metadata.responseTypes,
    tokenEndpointAuthMethod: "none"
  };
  if (metadata.clientName) providerClient.clientName = metadata.clientName;
  if (metadata.clientUri) providerClient.clientUri = metadata.clientUri;
  if (metadata.contacts) providerClient.contacts = metadata.contacts;
  if (metadata.jwksUri) providerClient.jwksUri = metadata.jwksUri;
  if (metadata.logoUri) providerClient.logoUri = metadata.logoUri;
  if (metadata.policyUri) providerClient.policyUri = metadata.policyUri;
  if (metadata.tosUri) providerClient.tosUri = metadata.tosUri;
  await kv.put(`client:${clientId}`, JSON.stringify(providerClient));
}

async function validatePrivateKeyJwtClientAssertion(
  params: URLSearchParams,
  clientId: string,
  metadata: ClientMetadataDocument,
  tokenEndpointUrl: string,
  flowKv: KVNamespace
): Promise<string | null> {
  if (params.get("client_assertion_type") !== CLIENT_ASSERTION_TYPE) {
    return "client_assertion_required";
  }
  const assertion = params.get("client_assertion");
  if (!assertion) {
    return "client_assertion_required";
  }
  try {
    const parts = assertion.split(".");
    if (parts.length !== 3) {
      return "invalid_client_assertion";
    }
    const jwtParts = parts as [string, string, string];
    const header = decodeJwtJson<Record<string, unknown>>(jwtParts[0]);
    const payload = decodeJwtJson<Record<string, unknown>>(jwtParts[1]);
    if (header.alg !== "RS256") {
      return "invalid_client_assertion";
    }
    if (optionalString(payload.iss, "iss") !== clientId || optionalString(payload.sub, "sub") !== clientId) {
      return "invalid_client_assertion";
    }
    if (!jwtAudienceMatches(payload.aud, tokenEndpointAudience(tokenEndpointUrl))) {
      return "invalid_client_assertion";
    }
    const now = Math.floor(Date.now() / 1000);
    const exp = optionalNumber(payload.exp, "exp");
    const nbf = optionalNumber(payload.nbf, "nbf");
    const iat = optionalNumber(payload.iat, "iat");
    if (!exp || exp <= now - 60 || exp > now + 600) {
      return "invalid_client_assertion";
    }
    if (nbf && nbf > now + 60) {
      return "invalid_client_assertion";
    }
    if (iat && iat > now + 60) {
      return "invalid_client_assertion";
    }
    const jti = optionalString(payload.jti, "jti");
    if (jti) {
      const replayKey = `client-assertion:${await sha256Hex(clientId)}:${await sha256Hex(jti)}`;
      if (await flowKv.get(replayKey)) {
        return "invalid_client_assertion";
      }
      await flowKv.put(replayKey, "1", { expirationTtl: Math.max(60, exp - now + 60) });
    }
    const jwks = await loadClientJwks(metadata);
    const verified = await verifyRs256Jwt(jwtParts, header, jwks);
    return verified ? null : "invalid_client_assertion";
  } catch (error) {
    console.warn(error);
    return "invalid_client_assertion";
  }
}

async function loadClientJwks(metadata: ClientMetadataDocument): Promise<ClientJsonWebKeySet> {
  if (metadata.jwks) {
    return metadata.jwks;
  }
  if (!metadata.jwksUri) {
    throw new Error("Missing client jwks_uri");
  }
  if (!isPublicHttpsUrl(metadata.jwksUri)) {
    throw new Error("Client jwks_uri must be a public HTTPS URL");
  }
  const response = await fetch(metadata.jwksUri, {
    headers: CLIENT_METADATA_FETCH_HEADERS,
    redirect: "manual"
  });
  if (response.status >= 300 && response.status < 400) {
    throw new Error("Client jwks_uri redirects are not accepted");
  }
  if (!response.ok) {
    throw new Error(`Client jwks_uri fetch failed with ${response.status}`);
  }
  return parseInlineJwks(await readJsonWithLimit(response, CLIENT_METADATA_MAX_BYTES)) ?? { keys: [] };
}

async function verifyRs256Jwt(parts: [string, string, string], header: Record<string, unknown>, jwks: ClientJsonWebKeySet): Promise<boolean> {
  const kid = optionalString(header.kid, "kid");
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlToBytes(parts[2]);
  const keys = jwks.keys.filter((key) => {
    if (key.kty !== "RSA") {
      return false;
    }
    if (kid && key.kid !== kid) {
      return false;
    }
    if (key.use && key.use !== "sig") {
      return false;
    }
    if (key.alg && key.alg !== "RS256") {
      return false;
    }
    return true;
  });
  for (const key of keys) {
    try {
      const cryptoKey = await crypto.subtle.importKey(
        "jwk",
        key,
        { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" },
        false,
        ["verify"]
      );
      if (await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signingInput)) {
        return true;
      }
    } catch (error) {
      console.warn(error);
    }
  }
  return false;
}

function tokenEndpointAudience(value: string): string {
  const url = new URL(value);
  url.hash = "";
  url.search = "";
  return url.toString();
}

function jwtAudienceMatches(value: unknown, expected: string): boolean {
  if (typeof value === "string") {
    return value === expected;
  }
  return Array.isArray(value) && value.some((entry) => entry === expected);
}

function parseClientMetadataAuthMethod(value: unknown): ClientMetadataAuthMethod {
  const method = optionalString(value, "token_endpoint_auth_method") ?? "none";
  if (!CLIENT_METADATA_AUTH_METHODS.includes(method as ClientMetadataAuthMethod)) {
    throw new Error("Unsupported client token endpoint authentication method");
  }
  return method as ClientMetadataAuthMethod;
}

function parseInlineJwks(value: unknown): ClientJsonWebKeySet | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("jwks must be a JSON object");
  }
  const keys = (value as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) {
    throw new Error("jwks.keys must be an array");
  }
  return {
    keys: keys.filter((key): key is ClientJsonWebKey => Boolean(key) && typeof key === "object" && !Array.isArray(key)) as ClientJsonWebKey[]
  };
}

async function readJsonWithLimit(response: Response, maxBytes: number): Promise<unknown> {
  const contentLength = response.headers.get("content-length");
  if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
    throw new Error("JSON response exceeds size limit");
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > maxBytes) {
    throw new Error("JSON response exceeds size limit");
  }
  return JSON.parse(text);
}

function requiredStringArray(value: unknown, fieldName: string): string[] {
  const values = optionalStringArray(value, fieldName);
  if (!values || values.length === 0) {
    throw new Error(`${fieldName} is required`);
  }
  return values;
}

function optionalStringArray(value: unknown, fieldName: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`${fieldName} must be a string array`);
  }
  return [...value];
}

function optionalString(value: unknown, fieldName: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a string`);
  }
  return value;
}

function optionalNumber(value: unknown, fieldName: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${fieldName} must be a number`);
  }
  return value;
}

function decodeJwtJson<T>(part: string): T {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(part))) as T;
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function annotateProviderGrants<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  userId: string,
  grants: readonly GrantSummary[]
): Promise<Map<string, { revocable: boolean; message: string; metadata: OAuthTokenProps | null }>> {
  const annotations = new Map<string, { revocable: boolean; message: string; metadata: OAuthTokenProps | null }>();
  for (const grant of grants) {
    const metadata = parseGrantMetadata(grant);
    if (!metadata || metadata.user_id !== userId) {
      annotations.set(grant.id, { message: "metadata unavailable", metadata, revocable: false });
      continue;
    }
    const consent = await runtime.repo.getConsentById(metadata.consent_id);
    annotations.set(grant.id, {
      metadata,
      message: consent && grantMatchesConsent(grant, metadata, consent) ? "" : "local consent mismatch",
      revocable: Boolean(consent && grantMatchesConsent(grant, metadata, consent))
    });
  }
  return annotations;
}

async function lookupGrantForRevoke(
  helpers: OAuthHelpers,
  userId: string,
  grantId: string,
  config: RuntimeConfig
): Promise<{ outcome: "found"; grant: GrantSummary } | { outcome: Exclude<RevokeOutcome, "changed" | "already_revoked" | "mismatch"> | "deadline" }> {
  const deadline = Date.now() + config.grantLookupDeadlineMs;
  let cursor: string | undefined;
  for (let page = 0; page < config.grantLookupMaxPages; page += 1) {
    if (Date.now() > deadline) {
      return { outcome: "deadline" };
    }
    try {
      const result = await helpers.listUserGrants(userId, cursor ? { cursor, limit: 50 } : { limit: 50 });
      const grant = result.items.find((item) => item.id === grantId);
      if (grant) {
        return { grant, outcome: "found" };
      }
      if (!result.cursor) {
        return { outcome: "not_found" };
      }
      cursor = result.cursor;
    } catch {
      return { outcome: "lookup_failed" };
    }
  }
  return { outcome: "lookup_failed" };
}

function parseGrantMetadata(grant: GrantSummary): OAuthTokenProps | null {
  const value = grant.metadata as Partial<OAuthTokenProps> | null;
  if (
    !value ||
    typeof value.user_id !== "string" ||
    typeof value.client_id !== "string" ||
    typeof value.consent_id !== "string" ||
    typeof value.resource !== "string" ||
    typeof value.scope_hash !== "string" ||
    typeof value.authz_version !== "number" ||
    typeof value.client_version !== "number"
  ) {
    return null;
  }
  return value as OAuthTokenProps;
}

function grantMatchesConsent(
  grant: GrantSummary,
  metadata: OAuthTokenProps,
  consent: { id: string; user_id: string; client_id: string; resource: string; scope_hash: string }
): boolean {
  return (
    grant.userId === metadata.user_id &&
    grant.clientId === metadata.client_id &&
    consent.id === metadata.consent_id &&
    consent.user_id === metadata.user_id &&
    consent.client_id === metadata.client_id &&
    consent.resource === metadata.resource &&
    consent.scope_hash === metadata.scope_hash
  );
}

function adminOutcomeResponse(label: string, outcome: RevokeOutcome | BulkRevokeOutcome): Response | null {
  if (outcome === "changed") {
    return null;
  }
  const status = outcome === "not_found" ? 404 : 409;
  return new Response(`${label} failed: ${outcome}`, { status });
}

function secrets(env: AuthWorkerEnv): CryptoSecrets {
  const output: CryptoSecrets = {
    EMAIL_HASH_KEY_CURRENT: requiredEnv(env.EMAIL_HASH_KEY_CURRENT, "EMAIL_HASH_KEY_CURRENT"),
    OTP_PEPPER_CURRENT: requiredEnv(env.OTP_PEPPER_CURRENT, "OTP_PEPPER_CURRENT"),
    OTP_PEPPER_CURRENT_VERSION: requiredEnv(env.OTP_PEPPER_CURRENT_VERSION, "OTP_PEPPER_CURRENT_VERSION"),
    OTP_SUBJECT_ENCRYPTION_KEY_CURRENT: requiredEnv(env.OTP_SUBJECT_ENCRYPTION_KEY_CURRENT, "OTP_SUBJECT_ENCRYPTION_KEY_CURRENT"),
    OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION: requiredEnv(env.OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION, "OTP_SUBJECT_ENCRYPTION_KEY_CURRENT_VERSION")
  };
  return output;
}

function renderHome<Env extends AuthWorkerEnv>(runtime: Runtime<Env>, email?: string): Response {
  const serviceSummary = renderMcpServerSummary(runtime.config.serverDescription);
  if (!email) {
    return html(`<!doctype html><html><body>
      <h1>${escapeHtml(runtime.config.serverName)}</h1>
      ${serviceSummary}
      <p><a href="/login?return_to=%2F">Sign in</a></p>
    </body></html>`);
  }
  const csrf = randomBase64Url(16);
  return html(
      `<!doctype html><html><body>
        <h1>${escapeHtml(runtime.config.serverName)}</h1>
        ${serviceSummary}
        ${renderAccountActions(email, csrf, true)}
    </body></html>`,
    csrf
  );
}

function renderAccountActions(email: string, csrf: string, includeDeleteAccount: boolean): string {
  const deleteAccount = includeDeleteAccount
    ? `<form method="post" action="/account/delete" style="display:inline;margin-left:1rem" onsubmit="return confirm('Delete this account permanently? All issued MCP URL records and account data will be deleted.');">
          <input type="hidden" name="csrf_token" value="${csrf}">
          <button type="submit" style="background:none;border:0;color:LinkText;text-decoration:underline;cursor:pointer;padding:0">Delete account</button>
        </form>`
    : "";
  return `<div>
      <span style="margin-right:1rem">${escapeHtml(email)}</span>
      <form method="post" action="/logout" style="display:inline">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <button type="submit">Sign out</button>
      </form>
      ${deleteAccount}
    </div>`;
}

function renderMcpServerSummary(description: string): string {
  return `<section>
      <p>${escapeHtml(description)}</p>
      <p>Use this page to sign in to the web UI. MCP clients connect to the protected MCP endpoint and complete OAuth authorization separately.</p>
    </section>`;
}

function renderLogin(returnTo: string, error?: string): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Sign in",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <label>Email <input name="email" type="email" autocomplete="email" required></label>
       <button type="submit">Send code</button>`,
      "/login"
    ),
    csrf
  );
}

function renderOtp(email: string, otpId: string, returnTo: string, error?: string, resendAfter?: string): Response {
  const csrf = randomBase64Url(16);
  const resendAt = displayResendAfter(resendAfter) ?? new Date(Date.now() + LOGIN_OTP_RESEND_DELAY_SECONDS * 1000).toISOString();
  const initialWaitSeconds = Math.max(0, Math.ceil((Date.parse(resendAt) - Date.now()) / 1000));
  return html(
    `<!doctype html><html><body><h1>Enter code</h1>${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}
      <form method="post" action="/login/verify">
       <input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="email" value="${escapeHtml(email)}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <input type="hidden" name="resend_after" value="${escapeHtml(resendAt)}">
       <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
       <button type="submit">Verify</button>
      </form>
      <form method="post" action="/login/resend">
       <input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="email" value="${escapeHtml(email)}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <input type="hidden" name="resend_after" value="${escapeHtml(resendAt)}">
       <button id="resend-code" type="submit" data-resend-after="${escapeHtml(resendAt)}" disabled>
        <span data-resend-wait>Resend code in <span id="resend-countdown">${initialWaitSeconds}</span>s</span>
        <span data-resend-ready hidden>Resend code</span>
       </button>
      </form>
      <script>
      (() => {
        const button = document.getElementById("resend-code");
        const countdown = document.getElementById("resend-countdown");
        const wait = document.querySelector("[data-resend-wait]");
        const ready = document.querySelector("[data-resend-ready]");
        if (!button || !countdown || !wait || !ready) return;
        const readyAt = Date.parse(button.dataset.resendAfter || "");
        if (Number.isNaN(readyAt)) return;
        let timer;
        const update = () => {
          const remaining = Math.max(0, Math.ceil((readyAt - Date.now()) / 1000));
          countdown.textContent = String(remaining);
          button.disabled = remaining > 0;
          wait.hidden = remaining <= 0;
          ready.hidden = remaining > 0;
          if (remaining <= 0 && timer) clearInterval(timer);
        };
        timer = setInterval(update, 1000);
        update();
      })();
      </script>
    </body></html>`,
    csrf
  );
}

function renderAuthorizeReauth<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  email: string,
  returnTo: string,
  error?: string
): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Verify authorization",
      error,
      `${renderMcpServerSummary(runtime.config.serverDescription)}
       <p>${escapeHtml(email)} is authorizing this MCP connection. Verify this email again before granting access.</p>
       <input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <label>Email <input name="email" type="email" autocomplete="email" value="${escapeHtml(email)}" required></label>
       <button type="submit">Send code</button>`,
      "/authorize/reauth"
    ),
    csrf
  );
}

function renderAuthorizeReauthOtp<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  email: string,
  otpId: string,
  returnTo: string,
  error?: string,
  resendAfter?: string
): Response {
  const csrf = randomBase64Url(16);
  const resendAt = displayResendAfter(resendAfter) ?? new Date(Date.now() + LOGIN_OTP_RESEND_DELAY_SECONDS * 1000).toISOString();
  const initialWaitSeconds = Math.max(0, Math.ceil((Date.parse(resendAt) - Date.now()) / 1000));
  return html(
    `<!doctype html><html><body><h1>Enter authorization code</h1>${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}
      ${renderMcpServerSummary(runtime.config.serverDescription)}
      <p>${escapeHtml(email)} is verifying authorization for this MCP connection.</p>
      <form method="post" action="/authorize/reauth/verify">
       <input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="email" value="${escapeHtml(email)}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <input type="hidden" name="resend_after" value="${escapeHtml(resendAt)}">
       <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
       <button type="submit">Verify</button>
      </form>
      <form method="post" action="/authorize/reauth/resend">
       <input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="email" value="${escapeHtml(email)}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <input type="hidden" name="resend_after" value="${escapeHtml(resendAt)}">
       <button id="resend-code" type="submit" data-resend-after="${escapeHtml(resendAt)}" disabled>
        <span data-resend-wait>Resend code in <span id="resend-countdown">${initialWaitSeconds}</span>s</span>
        <span data-resend-ready hidden>Resend code</span>
       </button>
      </form>
      <script>
      (() => {
        const button = document.getElementById("resend-code");
        const countdown = document.getElementById("resend-countdown");
        const wait = document.querySelector("[data-resend-wait]");
        const ready = document.querySelector("[data-resend-ready]");
        if (!button || !countdown || !wait || !ready) return;
        const readyAt = Date.parse(button.dataset.resendAfter || "");
        if (Number.isNaN(readyAt)) return;
        let timer;
        const update = () => {
          const remaining = Math.max(0, Math.ceil((readyAt - Date.now()) / 1000));
          countdown.textContent = String(remaining);
          button.disabled = remaining > 0;
          wait.hidden = remaining <= 0;
          ready.hidden = remaining > 0;
          if (remaining <= 0 && timer) clearInterval(timer);
        };
        timer = setInterval(update, 1000);
        update();
      })();
      </script>
    </body></html>`,
    csrf
  );
}

async function handleInitialAdminPost<Env extends AuthWorkerEnv>(
  request: Request,
  env: Env,
  runtime: Runtime<Env>
): Promise<Response> {
  if ((await runtime.repo.hasActiveAdmin()) || runtime.config.bootstrapAdminEmails.size === 0) {
    return new Response("Not found", { status: 404 });
  }
  const form = await request.formData();
  assertCsrf(request, form);
  if (form.has("otp_id") || form.has("code")) {
    return handleInitialAdminVerify(form, env, runtime);
  }
  return handleInitialAdminSubmit(form, env, runtime);
}

async function handleInitialAdminSubmit<Env extends AuthWorkerEnv>(
  form: FormData,
  env: Env,
  runtime: Runtime<Env>
): Promise<Response> {
  const email = normalizeEmail(String(form.get("email") ?? ""));
  const emailKey = await emailRateKey(env, "bootstrap", email);
  if (!(await runtime.repo.consumeRateLimits([emailKey], 3, 900))) {
    return renderBootstrap("Too many initial admin attempts. Try again later.");
  }
  let otpId: string = crypto.randomUUID();
  if (runtime.config.bootstrapAdminEmails.has(email)) {
    const otp = await runtime.repo.createOtpChallenge({
      bootstrapStateId: "initial",
      email,
      maxAttempts: 6,
      purpose: "bootstrap_admin",
      secrets: secrets(env),
      ttlSeconds: runtime.config.otpTtlSeconds
    });
    otpId = otp.id;
    await sendOtp(env, email, otp.code, otp.ttlSeconds, runtime.config.serverName, otp.id);
  }
  return renderBootstrapVerify(email, otpId);
}

async function handleInitialAdminVerify<Env extends AuthWorkerEnv>(
  form: FormData,
  env: Env,
  runtime: Runtime<Env>
): Promise<Response> {
  const email = String(form.get("email") ?? "");
  const otpId = String(form.get("otp_id") ?? "");
  const verified = await runtime.repo.verifyOtpChallenge({
    code: String(form.get("code") ?? ""),
    id: otpId,
    secrets: secrets(env)
  });
  if (!verified || verified.purpose !== "bootstrap_admin" || !runtime.config.bootstrapAdminEmails.has(verified.email)) {
    return renderBootstrapVerify(email, otpId, "Invalid or expired code.");
  }
  const user = await runtime.repo.consumeInitialBootstrapAndCreateAdmin(verified.email, runtime.requestId);
  if (!user) {
    return new Response("Initial admin setup is no longer available", { status: 409 });
  }
  const session = await runtime.repo.createSession({
    absoluteTtlSeconds: runtime.config.sessionAbsoluteTtlSeconds,
    idleTtlSeconds: runtime.config.sessionIdleTtlSeconds,
    userId: user.id
  });
  const headers = new Headers();
  headers.append("Set-Cookie", clearCookie(CSRF_COOKIE));
  headers.append("Set-Cookie", sessionCookie(session, runtime.config.sessionAbsoluteTtlSeconds));
  return redirect("/admin", headers);
}

function renderBootstrap(error?: string): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Initial admin",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <label>Email <input name="email" type="email" autocomplete="email" required></label>
       <button type="submit">Send code</button>`,
      "/admin"
    ),
    csrf
  );
}

function renderBootstrapVerify(email: string, otpId: string, error?: string): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Verify initial admin",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="email" value="${escapeHtml(email)}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
       <button type="submit">Create admin</button>`,
      "/admin"
    ),
    csrf
  );
}

function renderRecovery(nonce: string, error?: string): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Recovery bootstrap",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="nonce" value="${escapeHtml(nonce)}">
       <label>Email <input name="email" type="email" autocomplete="email" required></label>
       <button type="submit">Send recovery code</button>`,
      "/admin/recovery"
    ),
    csrf
  );
}

function renderRecoveryVerify(
  nonce: string,
  email: string,
  otpId: string,
  recoveryAttemptId: string,
  recoveryConsumeId: string,
  error?: string
): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Verify recovery",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="nonce" value="${escapeHtml(nonce)}">
       <input type="hidden" name="email" value="${escapeHtml(email)}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <input type="hidden" name="recovery_attempt_id" value="${escapeHtml(recoveryAttemptId)}">
       <input type="hidden" name="recovery_consume_id" value="${escapeHtml(recoveryConsumeId)}">
       <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
       <button type="submit">Recover admin</button>`,
      "/admin/recovery/verify"
    ),
    csrf
  );
}

function renderStepUp(returnTo: string, error?: string): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Admin step-up",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <button type="submit">Send admin code</button>`,
      "/admin/step-up"
    ),
    csrf
  );
}

function renderStepUpVerify(otpId: string, returnTo: string, error?: string): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Verify admin code",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
       <button type="submit">Continue</button>`,
      "/admin/step-up/verify"
    ),
    csrf
  );
}

function renderConsent<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  pendingId: string,
  request: AuthRequest,
  scopes: readonly string[],
  email: string,
  csrf: string
): Response {
  return html(
    formPage(
      "Authorize client",
      undefined,
      `${renderMcpServerSummary(runtime.config.serverDescription)}
       <p>${escapeHtml(email)} authorizes <code>${escapeHtml(request.clientId)}</code>.</p>
       <p>Resource: <code>${escapeHtml(runtime.config.resource)}</code></p>
       <p>Scopes: <code>${escapeHtml(formatCanonicalScope(scopes))}</code></p>
       <input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="pending_id" value="${escapeHtml(pendingId)}">
       <button name="action" value="approve" type="submit">Approve</button>
       <button name="action" value="deny" type="submit">Deny</button>`,
      "/authorize"
    ),
    csrf
  );
}

function renderProviderGrants<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  adminEmail: string,
  userId: string,
  grants: readonly GrantSummary[],
  nextCursor: string | undefined,
  annotations: Map<string, { revocable: boolean; message: string; metadata: OAuthTokenProps | null }>
): Response {
  const csrf = randomBase64Url(16);
  const rows = grants
    .map((grant) => {
      const annotation = annotations.get(grant.id) ?? { message: "metadata unavailable", metadata: null, revocable: false };
      const metadata = annotation.metadata;
      const action =
        annotation.revocable && metadata
          ? `<form method="post" action="/admin/grants/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(userId)}">
              <input type="hidden" name="grant_id" value="${escapeHtml(grant.id)}">
              <button type="submit">Revoke</button>
            </form>`
          : escapeHtml(annotation.message);
      return `<tr>
        <td>${escapeHtml(grant.id)}</td>
        <td>${escapeHtml(grant.clientId)}</td>
        <td>${escapeHtml(formatCanonicalScope(grant.scope))}</td>
        <td>${escapeHtml(metadata?.consent_id ?? "")}</td>
        <td>${action}</td>
      </tr>`;
    })
    .join("");
  const next = nextCursor
    ? `<a href="/admin/provider-grants?user_id=${encodeURIComponent(userId)}&cursor=${encodeURIComponent(nextCursor)}">Next</a>`
    : "";
  return html(
    `<!doctype html><html><body>
      <h1>${escapeHtml(runtime.config.serverName)} OAuth Provider Token Grants</h1>
      <p>${escapeHtml(adminEmail)}</p>
      <p><a href="/admin">Admin</a></p>
      <table><thead><tr><th>Grant</th><th>Client</th><th>Scope</th><th>Consent</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table>
      ${next}
    </body></html>`,
    csrf
  );
}

function parseGrantTimeoutForm(
  mode: string,
  secondsValue: string,
  allowInherit: boolean
): { inherit: boolean; ttlSeconds: number | null } | Response {
  if (mode === "inherit" && allowInherit) {
    return { inherit: true, ttlSeconds: null };
  }
  if (mode === "unlimited") {
    return { inherit: false, ttlSeconds: null };
  }
  if (mode === "custom") {
    const parsed = Number(secondsValue.trim());
    if (!Number.isInteger(parsed) || parsed <= 0 || parsed > MAX_GRANT_TTL_SECONDS) {
      return new Response(`MCP OAuth expiration must be a positive whole number of seconds up to ${MAX_GRANT_TTL_SECONDS}`, {
        status: 400
      });
    }
    return { inherit: false, ttlSeconds: parsed };
  }
  return new Response("Invalid MCP OAuth expiration mode", { status: 400 });
}

function parseBulkUserOperationAction(value: string): BulkUserOperationAction | null {
  if (
    value === "disable" ||
    value === "enable" ||
    value === "revoke_sessions" ||
    value === "revoke_grants" ||
    value === "revoke_authorization" ||
    value === "set_grant_timeout"
  ) {
    return value;
  }
  return null;
}

function formatBulkUserOperationAction(action: BulkUserOperationAction): string {
  if (action === "disable") {
    return "Disable selected users";
  }
  if (action === "enable") {
    return "Enable selected users";
  }
  if (action === "revoke_sessions") {
    return "Revoke selected Web UI sessions";
  }
  if (action === "revoke_grants") {
    return "Revoke selected MCP OAuth grants";
  }
  if (action === "revoke_authorization") {
    return "Revoke selected MCP OAuth authorization";
  }
  return "Set selected MCP OAuth expiration";
}

function formatGrantTimeout(ttlSeconds: number | null): string {
  return ttlSeconds === null ? "No expiration" : `${ttlSeconds} seconds`;
}

function formatGrantExpiresAt(expiresAt: string | null): string {
  return expiresAt ?? "No expiration";
}

function formatGrantTimeoutMode(mode: string, secondsValue: string): string {
  if (mode === "inherit") {
    return "Use default";
  }
  if (mode === "unlimited") {
    return "No expiration";
  }
  if (mode === "custom") {
    return `${secondsValue} seconds`;
  }
  return mode;
}

function formatSessionActiveUntil(session: SessionRow): string {
  const timestamps = [session.idle_expires_at, session.absolute_expires_at, session.expires_at]
    .map((value) => (value ? Date.parse(value) : Number.NaN))
    .filter((value) => Number.isFinite(value));
  return timestamps.length === 0 ? "" : new Date(Math.min(...timestamps)).toISOString();
}

function shortFingerprint(value: string | null): string {
  return value ? `${value.slice(0, 12)}...` : "";
}

function clientDisplayName(client: ClientPolicyRow): string {
  const metadata = parseJsonObject(client.metadata_snapshot_json);
  const name = stringField(metadata, "client_name") ?? stringField(metadata, "clientName") ?? stringField(metadata, "name");
  if (name) {
    return name;
  }
  try {
    return new URL(client.client_id).hostname;
  } catch {
    return client.client_id;
  }
}

function renderClientAppCell(client: ClientPolicyRow): string {
  const name = clientDisplayName(client);
  const clientId = escapeHtml(client.client_id);
  if (name === client.client_id) {
    return `<code>${clientId}</code>`;
  }
  return `${escapeHtml(name)}<br><code>${clientId}</code>`;
}

function renderBulkUserConfirmation<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  adminEmail: string,
  csrf: string,
  action: BulkUserOperationAction,
  users: readonly AdminUserRow[],
  grantTimeoutMode: string,
  grantTtlSeconds: string
): Response {
  const userList = users.map((user) => `<li>${escapeHtml(user.email)} <code>${escapeHtml(user.id)}</code></li>`).join("");
  const hiddenUsers = users
    .map((user) => `<input type="hidden" name="user_id" value="${escapeHtml(user.id)}">`)
    .join("");
  const grantTimeoutFields =
    action === "set_grant_timeout"
      ? `<input type="hidden" name="bulk_grant_timeout_mode" value="${escapeHtml(grantTimeoutMode)}">
         <input type="hidden" name="bulk_grant_ttl_seconds" value="${escapeHtml(grantTtlSeconds)}">
         <p>MCP OAuth expiration: ${escapeHtml(formatGrantTimeoutMode(grantTimeoutMode, grantTtlSeconds))}</p>`
      : "";
  return html(`<!doctype html><html><body>
    <h1>${escapeHtml(runtime.config.serverName)} Admin</h1>
    <p>${escapeHtml(adminEmail)}</p>
    <h2>Confirm bulk user action</h2>
    <p>${escapeHtml(formatBulkUserOperationAction(action))}</p>
    ${grantTimeoutFields}
    <ul>${userList}</ul>
    <form method="post" action="/admin/users/bulk">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}">
      <input type="hidden" name="confirmed" value="yes">
      <input type="hidden" name="action" value="${escapeHtml(action)}">
      ${hiddenUsers}
      <button type="submit">Confirm</button>
      <a href="/admin">Cancel</a>
    </form>
  </body></html>`);
}

function renderGrantTimeoutControl(input: {
  allowInherit: boolean;
  id: string;
  modeName: string;
  secondsName: string;
  secondsValue: number | null;
  selectedMode: "inherit" | "unlimited" | "custom";
}): string {
  const secondsHidden = input.selectedMode !== "custom";
  return `<span data-grant-timeout-control>
      <select name="${escapeHtml(input.modeName)}" data-grant-timeout-mode aria-controls="${escapeHtml(input.id)}">
        ${input.allowInherit ? `<option value="inherit"${input.selectedMode === "inherit" ? " selected" : ""}>Use default</option>` : ""}
        <option value="unlimited"${input.selectedMode === "unlimited" ? " selected" : ""}>No expiration</option>
        <option value="custom"${input.selectedMode === "custom" ? " selected" : ""}>Custom</option>
      </select>
      <input id="${escapeHtml(input.id)}" name="${escapeHtml(input.secondsName)}" inputmode="numeric" value="${escapeHtml(input.secondsValue === null ? "" : String(input.secondsValue))}" placeholder="seconds" data-grant-timeout-seconds${secondsHidden ? " hidden disabled" : ""}>
    </span>`;
}

function renderGrantTimeoutScript(): string {
  return `<script>
    (() => {
      const syncTimeoutControl = (control) => {
        const mode = control.querySelector("[data-grant-timeout-mode]");
        const seconds = control.querySelector("[data-grant-timeout-seconds]");
        if (!mode || !seconds) return;
        const custom = mode.value === "custom";
        seconds.hidden = !custom;
        seconds.disabled = !custom;
      };
      document.querySelectorAll("[data-grant-timeout-control]").forEach((control) => {
        const mode = control.querySelector("[data-grant-timeout-mode]");
        if (!mode) return;
        mode.addEventListener("change", () => syncTimeoutControl(control));
        syncTimeoutControl(control);
      });
      const bulkForm = document.getElementById("bulk-users-form");
      const bulkFields = bulkForm?.querySelector("[data-bulk-grant-timeout-fields]");
      const bulkAction = bulkForm?.querySelector('select[name="action"]');
      const syncBulkFields = () => {
        if (!bulkFields || !bulkAction) return;
        const enabled = bulkAction.value === "set_grant_timeout";
        bulkFields.hidden = !enabled;
        bulkFields.querySelectorAll("select, input").forEach((field) => {
          field.disabled = !enabled;
        });
        if (enabled) {
          bulkFields.querySelectorAll("[data-grant-timeout-control]").forEach(syncTimeoutControl);
        }
      };
      bulkAction?.addEventListener("change", syncBulkFields);
      syncBulkFields();
    })();
  </script>`;
}

function renderAdmin<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  adminEmail: string,
  users: AdminUserRow[],
  defaultGrantTtlSeconds: number | null,
  clients: ClientPolicyRow[],
  sessions: SessionRow[],
  consents: AdminConsentRow[],
  jobs: AuthJobRow[],
  auditLogs: AuditLogRow[]
): Response {
  const csrf = randomBase64Url(16);
  const rows = users
    .map(
      (user) =>
        `<tr>
          <td><input type="checkbox" name="user_id" value="${escapeHtml(user.id)}" form="bulk-users-form"></td>
          <td>${escapeHtml(user.email)}</td>
          <td>
            <form method="post" action="/admin/users/grant-timeout">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(user.id)}">
              ${renderGrantTimeoutControl({
                allowInherit: true,
                id: `user-grant-timeout-${user.id}`,
                modeName: "grant_timeout_mode",
                secondsName: "grant_ttl_seconds",
                secondsValue: user.grant_ttl_seconds,
                selectedMode: !user.grant_ttl_override ? "inherit" : user.grant_ttl_seconds === null ? "unlimited" : "custom"
              })}
              <span>${escapeHtml(formatGrantTimeout(user.effective_grant_ttl_seconds))}</span>
              <button type="submit">Set</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/users/update">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(user.id)}">
              <select name="status">
                <option value="active"${user.status === "active" ? " selected" : ""}>active</option>
                <option value="disabled"${user.status === "disabled" ? " selected" : ""}>disabled</option>
              </select>
              ${permissionCheckboxes(user.permissions)}
              <button type="submit">Update</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/users/sessions/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(user.id)}">
              <button type="submit">Revoke Web UI sessions</button>
            </form>
            <form method="post" action="/admin/users/consents/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(user.id)}">
              <button type="submit">Revoke MCP OAuth grants</button>
            </form>
            <a href="/admin/provider-grants?user_id=${encodeURIComponent(user.id)}">OAuth provider token grants</a>
            <form method="post" action="/admin/users/authorization/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(user.id)}">
              <button type="submit">Revoke MCP OAuth authorization</button>
            </form>
          </td>
        </tr>`
    )
    .join("");
  const bulkUsersForm = `<form id="bulk-users-form" method="post" action="/admin/users/bulk">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <select name="action" required>
          <option value="disable">Disable selected</option>
          <option value="enable">Enable selected</option>
          <option value="revoke_sessions">Revoke selected Web UI sessions</option>
          <option value="revoke_grants">Revoke selected MCP OAuth grants</option>
          <option value="revoke_authorization">Revoke selected MCP OAuth authorization</option>
          <option value="set_grant_timeout">Set selected MCP OAuth expiration</option>
        </select>
        <span data-bulk-grant-timeout-fields hidden>
          ${renderGrantTimeoutControl({
            allowInherit: true,
            id: "bulk-grant-timeout",
            modeName: "bulk_grant_timeout_mode",
            secondsName: "bulk_grant_ttl_seconds",
            secondsValue: null,
            selectedMode: "inherit"
          })}
        </span>
        <button type="submit">Review bulk action</button>
      </form>`;
  const clientNames = new Map(clients.map((client) => [client.client_id, clientDisplayName(client)]));
  const clientRows = clients
    .map(
      (client) =>
        `<tr>
          <td>${renderClientAppCell(client)}</td>
          <td>${escapeHtml(client.first_seen_at ?? "")}</td>
          <td>${escapeHtml(client.last_seen_at ?? "")}</td>
          <td>
            <form method="post" action="/admin/clients/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
              <button type="submit">Delete</button>
            </form>
          </td>
        </tr>`
    )
    .join("") || `<tr><td colspan="4">No MCP OAuth client apps</td></tr>`;
  const sessionRows = sessions
    .map(
      (session) =>
        `<tr>
          <td><code>${escapeHtml(shortFingerprint(session.id_hash))}</code></td>
          <td>${escapeHtml(session.user_email)}</td>
          <td>${escapeHtml(session.created_at)}</td>
          <td>${escapeHtml(session.last_seen_at ?? "")}</td>
          <td>${escapeHtml(session.last_touched_at ?? "")}</td>
          <td>${escapeHtml(session.ip_prefix ?? "")}</td>
          <td><code>${escapeHtml(shortFingerprint(session.user_agent_hash))}</code></td>
          <td>${escapeHtml(formatSessionActiveUntil(session))}</td>
          <td>${escapeHtml(session.absolute_expires_at ?? session.expires_at)}</td>
          <td>
            <form method="post" action="/admin/sessions/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="session_id_hash" value="${escapeHtml(session.id_hash)}">
              <button type="submit">Revoke</button>
            </form>
          </td>
        </tr>`
    )
    .join("");
  const consentRows = consents
    .map(
      (consent) =>
        `<tr>
          <td>${escapeHtml(consent.user_email)}</td>
          <td>${escapeHtml(clientNames.get(consent.client_id) ?? consent.client_id)}</td>
          <td>${escapeHtml(consent.canonical_scope)}</td>
          <td>${escapeHtml(formatGrantExpiresAt(consent.expires_at))}</td>
          <td>
            <form method="post" action="/admin/consents/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="consent_id" value="${escapeHtml(consent.id)}">
              <button type="submit">Revoke</button>
            </form>
          </td>
        </tr>`
    )
    .join("");
  const jobRows = jobs
    .map(
      (job) =>
        `<tr>
          <td>${escapeHtml(job.type)}</td>
          <td>${escapeHtml(job.status)}</td>
          <td>${escapeHtml(String(job.attempts))}</td>
          <td>${escapeHtml(job.updated_at)}</td>
        </tr>`
    )
    .join("");
  const auditRows = auditLogs
    .map(
      (log) =>
        `<tr>
          <td>${escapeHtml(log.created_at)}</td>
          <td>${escapeHtml(log.event)}</td>
          <td>${escapeHtml(log.result)}</td>
          <td>${escapeHtml(log.request_id)}</td>
        </tr>`
    )
    .join("");
  return html(
    `<!doctype html><html><body>
      <h1>${escapeHtml(runtime.config.serverName)} Admin</h1>
      ${renderAccountActions(adminEmail, csrf, false)}
      <h2>Scope Guide</h2>
      <ul>
        <li><strong>Web UI sessions</strong> are browser/admin login sessions. Revoking them signs users out of this UI and does not by itself delete MCP OAuth authorizations.</li>
        <li><strong>MCP OAuth user authorizations</strong> are local user-client-resource-scope permissions. Revoking them removes MCP access and invalidates refresh-grant use through local state.</li>
        <li><strong>MCP OAuth client apps</strong> are connector apps discovered from OAuth client metadata URLs and kept as a local allow list.</li>
        <li><strong>OAuth provider token grants</strong> are provider-internal token records. Use MCP OAuth authorization revoke for the normal user access path.</li>
      </ul>
      <h2>MCP OAuth Authorization Expiration</h2>
      <p>Default MCP OAuth expiration: ${escapeHtml(formatGrantTimeout(defaultGrantTtlSeconds))}</p>
      <form method="post" action="/admin/oauth-policy">
        <input type="hidden" name="csrf_token" value="${csrf}">
        ${renderGrantTimeoutControl({
          allowInherit: false,
          id: "default-grant-timeout",
          modeName: "default_grant_timeout_mode",
          secondsName: "default_grant_ttl_seconds",
          secondsValue: defaultGrantTtlSeconds,
          selectedMode: defaultGrantTtlSeconds === null ? "unlimited" : "custom"
        })}
        <button type="submit">Save</button>
      </form>
      <h2>Users</h2>
      <form method="post" action="/admin/users">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <label>Email <input name="email" type="email" required></label>
        ${permissionCheckboxes([])}
        <button type="submit">Add user</button>
      </form>
      ${bulkUsersForm}<table><thead><tr><th>Select</th><th>Email</th><th>MCP OAuth expiration</th><th>State</th><th>Access controls</th></tr></thead><tbody>${rows}</tbody></table>
      <h2>MCP OAuth Client Apps</h2>
      <p>Connector applications discovered from OAuth client metadata URLs. User-specific MCP access is shown under MCP OAuth User Authorizations.</p>
      <table><thead><tr><th>Application</th><th>First seen</th><th>Last seen</th><th>Action</th></tr></thead><tbody>${clientRows}</tbody></table>
      <h2>OAuth Provider Token Grants</h2>
      <p>Open provider token grants from a user row only when provider-level cleanup needs inspection.</p>
      <h2>Active Web UI Sessions</h2><table><thead><tr><th>Session</th><th>User</th><th>Created</th><th>Last seen</th><th>Last touched</th><th>IP prefix</th><th>User agent</th><th>Active until</th><th>Absolute until</th><th>Action</th></tr></thead><tbody>${sessionRows}</tbody></table>
      <h2>MCP OAuth User Authorizations</h2><table><thead><tr><th>User</th><th>Application</th><th>Scope</th><th>Expires</th><th>Action</th></tr></thead><tbody>${consentRows}</tbody></table>
      <h2>Jobs</h2><table><thead><tr><th>Type</th><th>Status</th><th>Attempts</th><th>Updated</th></tr></thead><tbody>${jobRows}</tbody></table>
      <h2>Audit</h2><table><thead><tr><th>Created</th><th>Event</th><th>Result</th><th>Request</th></tr></thead><tbody>${auditRows}</tbody></table>
      ${renderGrantTimeoutScript()}
    </body></html>`,
    csrf
  );
}

function permissionCheckboxes(selected: readonly string[]): string {
  const selectedSet = new Set(selected);
  return USER_PERMISSIONS
    .map(
      (scope) =>
        `<label><input type="checkbox" name="permissions" value="${scope}"${
          selectedSet.has(scope) ? " checked" : ""
        }>${scope}</label>`
    )
    .join("");
}

function formPage(title: string, error: string | undefined, body: string, action: string): string {
  return `<!doctype html><html><body><h1>${escapeHtml(title)}</h1>${
    error ? `<p role="alert">${escapeHtml(error)}</p>` : ""
  }<form method="post" action="${action}">${body}</form></body></html>`;
}

function html(body: string, csrf?: string): Response {
  const response = new Response(body, { headers: SAFE_HEADERS });
  if (csrf) {
    response.headers.append("Set-Cookie", cookie(CSRF_COOKIE, csrf, 600));
  }
  return response;
}

function redirect(location: string, headers = new Headers(), status = 302): Response {
  headers.set("Location", location);
  headers.set("Cache-Control", "no-store");
  return new Response(null, { headers, status });
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Cache-Control": "no-store", "Content-Type": "application/json" },
    status
  });
}

function oauthError(error: string, status: number): Response {
  return json({ error }, status);
}

function oauthRedirectError(request: AuthRequest, error: string, description: string): Response {
  const redirectUri = new URL(request.redirectUri);
  redirectUri.searchParams.set("error", error);
  redirectUri.searchParams.set("error_description", description);
  redirectUri.searchParams.set("state", request.state);
  return redirect(redirectUri.toString());
}

function assertCsrf(request: Request, form: FormData): void {
  const cookieValue = readCookie(request, CSRF_COOKIE);
  const formValue = String(form.get("csrf_token") ?? "");
  if (!cookieValue || !formValue || cookieValue !== formValue) {
    throw new CsrfError();
  }
}

function isCsrfError(error: unknown): error is CsrfError {
  return error instanceof CsrfError;
}

function sessionCookie(value: string, ttlSeconds: number): string {
  return cookie(SESSION_COOKIE, value, ttlSeconds);
}

function cookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name: string): string {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function readCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get("Cookie") ?? "";
  const match = cookieHeader.split(/;\s*/).find((part) => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

function sanitizeReturnTo(value: string): string {
  if (!value.startsWith("/")) {
    return "/";
  }
  const url = new URL(value, "https://local.invalid");
  if (!["/", "/admin", "/authorize"].includes(url.pathname)) {
    return "/";
  }
  return `${url.pathname}${url.search}`;
}

function sanitizeAuthorizeReturnTo(value: string): string {
  const returnTo = sanitizeReturnTo(value);
  return isAuthorizeReturnTo(returnTo) ? returnTo : "/";
}

function isAuthorizeReturnTo(value: string): boolean {
  try {
    return new URL(value, "https://local.invalid").pathname === "/authorize";
  } catch {
    return false;
  }
}

async function issueOAuthReauthMarker<Env extends AuthWorkerEnv>(
  flowKv: KVNamespace,
  runtime: Runtime<Env>,
  headers: Headers,
  input: { sessionIdHash: string; userId: string; returnTo: string }
): Promise<void> {
  const token = randomBase64Url(32);
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + runtime.config.otpTtlSeconds * 1000).toISOString();
  await flowKv.put(
    `${OAUTH_REAUTH_PREFIX}${tokenHash}`,
    JSON.stringify({
      expires_at: expiresAt,
      return_to_hash: await sha256Hex(input.returnTo),
      session_id_hash: input.sessionIdHash,
      user_id: input.userId
    }),
    { expirationTtl: runtime.config.otpTtlSeconds }
  );
  headers.append("Set-Cookie", cookie(OAUTH_REAUTH_COOKIE, token, runtime.config.otpTtlSeconds));
}

async function consumeOAuthReauthMarker(
  request: Request,
  flowKv: KVNamespace,
  session: { sessionIdHash: string; user: { id: string } },
  returnTo: string
): Promise<{ ok: boolean }> {
  const token = readCookie(request, OAUTH_REAUTH_COOKIE);
  if (!token) {
    return { ok: false };
  }
  const key = `${OAUTH_REAUTH_PREFIX}${await sha256Hex(token)}`;
  const value = await flowKv.get(key);
  if (!value) {
    return { ok: false };
  }
  await flowKv.delete(key);
  const decoded = (() => {
    try {
      return JSON.parse(value) as unknown;
    } catch {
      return null;
    }
  })();
  const parsed = oauthReauthPayloadSchema.safeParse(decoded);
  if (!parsed.success || Date.parse(parsed.data.expires_at) <= Date.now()) {
    return { ok: false };
  }
  return {
    ok:
      parsed.data.session_id_hash === session.sessionIdHash &&
      parsed.data.user_id === session.user.id &&
      parsed.data.return_to_hash === (await sha256Hex(returnTo))
  };
}

function isRecentStepUp(value: string | null, ttlSeconds: number): boolean {
  return Boolean(value && Date.parse(value) + ttlSeconds * 1000 > Date.now());
}

function formToParams(form: FormData): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of form.entries()) {
    params.append(key, String(value));
  }
  return params;
}

function displayResendAfter(value: FormDataEntryValue | string | null | undefined): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  return Number.isFinite(Date.parse(value)) ? value : undefined;
}

function resourceFromAuthRequest(request: AuthRequest): string | undefined {
  if (Array.isArray(request.resource)) {
    if (request.resource.length !== 1) {
      throw new Error("single resource is required");
    }
    return request.resource[0];
  }
  return request.resource;
}

function parseBasicClientId(header: string | null): string | null {
  if (!header?.startsWith("Basic ")) {
    return null;
  }
  try {
    const decoded = atob(header.slice(6));
    return decoded.split(":")[0] || "__invalid_basic__";
  } catch {
    return "__invalid_basic__";
  }
}

function parseJsonStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function parseJsonObject(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function stringField(value: Record<string, unknown> | null, key: string): string | null {
  const field = value?.[key];
  return typeof field === "string" && field.trim() ? field.trim() : null;
}

async function consumeRequestRateLimit<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  env: Env,
  request: Request,
  bucket: string,
  subjects: readonly string[],
  limit: number,
  windowSeconds: number
): Promise<boolean> {
  const ip = ipPrefix(request.headers.get("CF-Connecting-IP"));
  const keys = [`${bucket}:ip:${ip ?? "unknown"}`];
  for (const subject of subjects.filter(Boolean)) {
    keys.push(`${bucket}:subject:${await hmacHex(requiredEnv(env.EMAIL_HASH_KEY_CURRENT, "EMAIL_HASH_KEY_CURRENT"), subject)}`);
  }
  return runtime.repo.consumeRateLimits(keys, limit, windowSeconds);
}

async function emailRateKey(env: AuthWorkerEnv, bucket: string, email: string): Promise<string> {
  const digest = await hmacHex(requiredEnv(env.EMAIL_HASH_KEY_CURRENT, "EMAIL_HASH_KEY_CURRENT"), normalizeEmail(email));
  return `${bucket}:email:${digest}`;
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

function authorizationStateErrorResponse(error: unknown): Response {
  if (isTransientAuthStateError(error)) {
    return json({ error: "authorization_state_unavailable" }, 503);
  }
  return json({ error: "authorization_state_stale" }, 403);
}

function isTransientAuthStateError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /busy|timeout|network|fetch|unavailable|schema|migrat|turso|database/i.test(message);
}

async function readPending(kv: KVNamespace, pendingId: string): Promise<PendingAuthorizationPayload | null> {
  const value = await kv.get(`${PENDING_PREFIX}${pendingId}`);
  if (!value) {
    return null;
  }
  const decoded = (() => {
    try {
      return JSON.parse(value) as unknown;
    } catch {
      return null;
    }
  })();
  const parsed = pendingAuthorizationPayloadSchema.safeParse(decoded);
  if (!parsed.success || Date.parse(parsed.data.expires_at) <= Date.now()) {
    return null;
  }
  return parsed.data;
}

async function writePending<Env extends AuthWorkerEnv>(
  kv: KVNamespace,
  runtime: Runtime<Env>,
  pendingId: string,
  payload: PendingAuthorizationPayload
): Promise<void> {
  await kv.put(`${PENDING_PREFIX}${pendingId}`, JSON.stringify(payload), {
    expirationTtl: runtime.config.pendingAuthorizationTtlSeconds
  });
}

async function verifyPendingPayloadBinding<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  payload: PendingAuthorizationPayload
): Promise<boolean> {
  const { payload_digest: _payloadDigest, ...digestPayload } = payload;
  if ((await sha256Hex(JSON.stringify(digestPayload))) !== payload.payload_digest) {
    return false;
  }
  if (payload.request_json.clientId !== payload.client_id || payload.request_json.redirectUri !== payload.redirect_uri) {
    return false;
  }
  try {
  const resource = requireMcpResource(resourceFromAuthRequest(payload.request_json), runtime.config.resource);
    if (resource !== payload.resource) {
      return false;
    }
    const scopes = assertKnownScopes(payload.request_json.scope.length ? payload.request_json.scope : ["profile"]);
    if ((await hashScope(scopes)) !== payload.scope_hash) {
      return false;
    }
  } catch {
    return false;
  }
  return true;
}

async function cleanupOrphanProviderClients(repo: AuthRepository, helpers: OAuthHelpers): Promise<void> {
  const allowedClientIds = new Set((await repo.listClientPolicies()).map((policy) => policy.client_id));
  const nowSeconds = Math.floor(Date.now() / 1000);
  let cursor: string | undefined;
  do {
    const result = await helpers.listClients(cursor ? { cursor, limit: 100 } : { limit: 100 });
    for (const client of result.items) {
      if (allowedClientIds.has(client.clientId)) {
        continue;
      }
      const registrationDate = client.registrationDate ?? nowSeconds;
      if (nowSeconds - registrationDate < 60) {
        continue;
      }
      await repo.enqueueJob({
        idempotencyKey: `delete-orphan-client:${client.clientId}`,
        payload: { cause: "local policy missing", clientId: client.clientId },
        requestId: crypto.randomUUID(),
        targetClientId: client.clientId,
        type: "delete_provider_client"
      });
    }
    cursor = result.cursor;
  } while (cursor);
}

async function runScheduledTask<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  name: string,
  task: () => Promise<unknown>
): Promise<boolean> {
  try {
    await task();
    return true;
  } catch (error) {
    console.warn(error);
    await runtime.repo
      .writeAudit({
        event: `scheduled.${name}.failed`,
        metadata: { task: name },
        requestId: runtime.requestId,
        result: "failure"
      })
      .catch((auditError) => console.error(auditError));
    console.error(error);
    return false;
  }
}

async function runScheduledBestEffortTask(name: string, task: () => Promise<unknown>): Promise<void> {
  try {
    await task();
  } catch (error) {
    console.warn(`Scheduled best-effort task failed: ${name}`);
    console.warn(error);
  }
}

async function runAuthJobs(repo: AuthRepository, helpers: OAuthHelpers, config: RuntimeConfig): Promise<void> {
  const deadline = Date.now() + config.authJobDeadlineMs;
  const jobs = await repo.claimJobs(config.authJobBatchSize, Math.ceil(config.authJobDeadlineMs / 1000));
  for (const job of jobs) {
    const leaseId = job.lease_id;
    if (!leaseId) {
      await repo.writeAudit({
        event: "auth_job.lease_missing",
        metadata: { jobId: job.job_id, type: job.type },
        requestId: job.request_id,
        result: "denied",
        targetUserId: job.target_user_id
      });
      continue;
    }
    if (Date.now() >= deadline) {
      console.warn(`Auth job deadline exceeded: ${job.job_id}`);
      await repo.finishJob(job.job_id, leaseId, "failed", config.authJobMaxAttempts);
      continue;
    }
    try {
      const payload = JSON.parse(job.payload_json) as Record<string, unknown>;
      if (job.type === "delete_provider_client") {
        await helpers.deleteClient(String(payload.clientId ?? job.target_client_id ?? ""));
      } else if (job.type === "revoke_provider_grant") {
        await helpers.revokeGrant(String(payload.grantId ?? ""), String(payload.userId ?? job.target_user_id ?? ""));
      } else if (job.type === "revoke_user_grants") {
        const userId = String(payload.userId ?? job.target_user_id ?? "");
        let cursor: string | undefined;
        do {
          if (Date.now() >= deadline) {
            throw new Error("auth job deadline exceeded");
          }
          const result = await helpers.listUserGrants(userId, cursor ? { cursor, limit: 50 } : { limit: 50 });
          for (const grant of result.items) {
            if (Date.now() >= deadline) {
              throw new Error("auth job deadline exceeded");
            }
            await helpers.revokeGrant(grant.id, userId);
          }
          cursor = result.cursor;
        } while (cursor);
      } else {
        throw new Error(`Unknown auth job type: ${job.type}`);
      }
      await repo.finishJob(job.job_id, leaseId, "succeeded", config.authJobMaxAttempts);
    } catch (error) {
      console.warn(error);
      await repo.finishJob(job.job_id, leaseId, "failed", config.authJobMaxAttempts);
    }
  }
}

async function recoveryAllowed<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  nonce: string
): Promise<boolean> {
  if (
    runtime.config.recoveryBootstrapEmails.size === 0 ||
    runtime.config.securityContactEmails.length === 0 ||
    !runtime.config.recoveryEnabledUntil ||
    runtime.config.recoveryEnabledUntil <= Date.now() ||
    !runtime.config.recoveryNonceHash ||
    !nonce
  ) {
    return false;
  }
  return (await sha256Hex(nonce)) === runtime.config.recoveryNonceHash;
}

async function notifyRecoveryContacts<Env extends AuthWorkerEnv>(
  env: Env,
  runtime: Runtime<Env>,
  message: string,
  requestId: string,
  event: string
): Promise<void> {
  if (runtime.config.securityContactEmails.length === 0) {
    throw new Error("SECURITY_CONTACT_EMAILS is required for recovery");
  }
  const users = await runtime.repo.listUsers();
  const recipients = new Set([
    ...runtime.config.securityContactEmails,
    ...users
      .filter((user) => user.status === "active" && user.permissions.includes("admin"))
      .map((user) => user.email)
  ]);
  if (recipients.size === 0) {
    throw new Error("Recovery notification recipients are required");
  }
  for (const email of recipients) {
    await sendEmailViaResend(env, {
      idempotencyKey: `recovery:${requestId}:${event}:${await sha256Hex(email)}`,
      subject: `${runtime.config.serverName} security notice`,
      text: message,
      to: email
    });
  }
}

function splitSet(value: string | undefined): Set<string> {
  return new Set((value ?? "").split(/[,\s]+/).map((part) => part.trim()).filter(Boolean));
}

function parseBoundedInteger(value: string | undefined, defaultValue: number, min: number, max: number): number {
  const parsed = Number(value ?? defaultValue);
  if (!Number.isFinite(parsed)) {
    return defaultValue;
  }
  return Math.max(min, Math.min(Math.floor(parsed), max));
}

function parseOptionalTtlSeconds(value: string | undefined, name: string, maxValue: number): number | undefined {
  if (value === undefined || value === "" || value === "unlimited" || value === "none" || value === "never") {
    return undefined;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive number of seconds, or omitted for non-expiring grants`);
  }
  return Math.min(Math.floor(parsed), maxValue);
}

function parseSessionConfig(env: AuthWorkerEnv): { idle: number; absolute: number; touch: number } {
  const minIdle = 60;
  const minAbsolute = 300;
  const maxAbsolute = 604_800;
  const absolute = parseStrictInteger(env.SESSION_ABSOLUTE_TTL_SECONDS, 43_200);
  const idleCandidate =
    env.SESSION_IDLE_TTL_SECONDS === undefined || env.SESSION_IDLE_TTL_SECONDS === ""
      ? Math.min(1_800, absolute - 1)
      : parseStrictInteger(env.SESSION_IDLE_TTL_SECONDS, 1_800);
  const touch = parseStrictInteger(env.SESSION_TOUCH_INTERVAL_SECONDS, 300);
  if (absolute < minAbsolute || absolute > maxAbsolute) {
    throw new Error(`SESSION_ABSOLUTE_TTL_SECONDS must be between ${minAbsolute} and ${maxAbsolute}`);
  }
  if (idleCandidate < minIdle) {
    throw new Error(`SESSION_IDLE_TTL_SECONDS must be at least ${minIdle}`);
  }
  if (touch < 0) {
    throw new Error("SESSION_TOUCH_INTERVAL_SECONDS must not be negative");
  }
  if (idleCandidate >= absolute) {
    throw new Error("SESSION_IDLE_TTL_SECONDS must be lower than SESSION_ABSOLUTE_TTL_SECONDS");
  }
  if (touch >= idleCandidate) {
    throw new Error("SESSION_TOUCH_INTERVAL_SECONDS must be lower than SESSION_IDLE_TTL_SECONDS");
  }
  return { absolute, idle: idleCandidate, touch };
}

function assertDeployableResourceUri(resource: string, allowLocal: boolean): void {
  const url = new URL(resource);
  const host = url.hostname.toLowerCase();
  const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  if (isLocal) {
    if (!allowLocal) {
      throw new Error("MCP_RESOURCE_URI uses a local host; set ALLOW_LOCAL_RESOURCE_URI=true only for local development");
    }
    return;
  }
  if (url.protocol !== "https:") {
    throw new Error("MCP_RESOURCE_URI must use https outside local development");
  }
}

function parseStrictInteger(value: string | undefined, defaultValue: number): number {
  const parsed = Number(value ?? defaultValue);
  if (!Number.isInteger(parsed)) {
    throw new Error("Expected integer configuration value");
  }
  return parsed;
}

function requiredEnv(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function renderOAuthServerMetadata(url: URL): Response {
  const origin = url.origin;
  return json({
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    scopes_supported: [...OAUTH_SCOPES],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
    token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    revocation_endpoint: `${origin}/token`,
    code_challenge_methods_supported: ["S256"],
    client_id_metadata_document_supported: true
  });
}

function addCorsHeaders(response: Response, request: Request): Response {
  const origin = request.headers.get("Origin");
  if (!origin) {
    return response;
  }
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Methods", "*");
  headers.set("Access-Control-Allow-Headers", "Authorization, *");
  headers.set("Access-Control-Max-Age", "86400");
  return new Response(response.body, { headers, status: response.status, statusText: response.statusText });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

