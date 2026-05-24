import OAuthProvider, {
  OAuthError,
  getOAuthApi,
  type AuthRequest,
  type ClientInfo,
  type GrantSummary,
  type OAuthHelpers,
  type OAuthProviderOptions,
  type TokenExchangeCallbackOptions
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
  CIMD_ALLOWED_CLIENT_IDS?: string;
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
  cimdAllowedClientIds: Set<string>;
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
  | "admin.home"
  | "authorize.get"
  | "admin.user.create"
  | "admin.user.update"
  | "admin.users.bulk"
  | "admin.oauth_policy.update"
  | "admin.user_grant_timeout.update"
  | "admin.client.create"
  | "admin.client.revoke"
  | "admin.cimd.approve"
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
  "admin.home": { required: ["session", "admin"], touch: true },
  "authorize.get": { required: ["session"], touch: true },
  "admin.user.create": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.user.update": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.users.bulk": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.oauth_policy.update": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.user_grant_timeout.update": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.client.create": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.client.revoke": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
  "admin.cimd.approve": { required: ["session", "admin", "csrf", "freshStepUp"], touch: true },
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
const MAX_GRANT_TTL_SECONDS = 7_776_000;
const PENDING_PREFIX = "pending:";
const SAFE_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "text/html; charset=utf-8",
  "Referrer-Policy": "no-referrer"
};

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
          await runScheduledTask(runtime, "auth.optimize_storage", () => runtime.repo.optimizeStorage());
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
    clientIdMetadataDocumentEnabled: true,
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
    cimdAllowedClientIds: splitSet(env.CIMD_ALLOWED_CLIENT_IDS),
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
    const error = await validateAuthorizePreflight(params, runtime).catch((validationError) => {
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
    const error = await validateTokenPreflight(params, basicClientId, runtime).catch((validationError) => {
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
  const clientError = await validateClientPreflight(clientId, runtime);
  if (clientError) {
    return clientError;
  }
  const redirectUri = params.get("redirect_uri");
  if (!redirectUri) {
    return "redirect_uri_required";
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
  runtime: Runtime<Env>
): Promise<string | null> {
  const grantType = params.get("grant_type");
  const clientId = basicClientId ?? params.get("client_id");
  if (
    basicClientId ||
    params.has("client_secret") ||
    params.has("client_assertion") ||
    params.has("client_assertion_type")
  ) {
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
  const clientError = await validateClientPreflight(clientId, runtime);
  if (clientError) {
    return clientError;
  }
  if (grantType === "authorization_code") {
    const redirectUri = params.get("redirect_uri");
    if (!redirectUri) {
      return "redirect_uri_required";
    }
    const policy = await runtime.repo.getClientPolicy(clientId);
    if (policy && !parseJsonStringArray(policy.allowed_redirect_uris_json).includes(redirectUri)) {
      return "redirect_uri_not_registered";
    }
  }
  return null;
}

async function validateClientPreflight<Env extends AuthWorkerEnv>(
  clientId: string,
  runtime: Runtime<Env>
): Promise<string | null> {
  const policy = await runtime.repo.getClientPolicy(clientId);
  if (isUrlClientId(clientId)) {
    if (!isPublicHttpsUrl(clientId)) {
      return "invalid_client_id_url";
    }
    if (!runtime.config.cimdAllowedClientIds.has(clientId) && !(policy?.status === "active" && policy.source === "cimd")) {
      return "cimd_client_not_allowed";
    }
  }
  if (!policy || policy.status !== "active") {
    return "client_not_active";
  }
  if (policy.source !== "admin_created" && policy.source !== "cimd") {
    return "invalid_client_source";
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
      const token = await helpers.unwrapToken<OAuthTokenProps>(bearer);
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
        env: requestEnv
      });
      return runtime.workerOptions.handleMcpRequest(request, requestEnv, ctx, server);
    }
  };
}

function createDefaultHandler<Env extends AuthWorkerEnv>(
  env: Env,
  runtime: Runtime<Env>
): ExportedHandler<Env> {
  const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

  app.get("/", () => renderHome(runtime));

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
    let otpId: string = crypto.randomUUID();
    if (user?.status === "active") {
      const otp = await runtime.repo.createOtpChallenge({
        email: user.email,
        maxAttempts: 6,
        purpose: "login",
        secrets: secrets(env),
        ttlSeconds: runtime.config.otpTtlSeconds,
        userId: user.id
      });
      otpId = otp.id;
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
    }
    return renderOtp(email, otpId, returnTo);
  });

  app.post("/login/verify", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const otpId = String(form.get("otp_id") ?? "");
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
        "Too many verification attempts. Try again later."
      );
    }
    const verified = await runtime.repo.verifyOtpChallenge({
      code: String(form.get("code") ?? ""),
      id: otpId,
      secrets: secrets(env)
    });
    if (!verified || verified.purpose !== "login" || !verified.userId) {
      return renderOtp(String(form.get("email") ?? ""), String(form.get("otp_id") ?? ""), sanitizeReturnTo(String(form.get("return_to") ?? "/")), "Invalid or expired code.");
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
    return redirect(sanitizeReturnTo(String(form.get("return_to") ?? "/")), headers);
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
    return redirect("/", headers);
  });

  app.get("/admin/bootstrap", async () => {
    if ((await runtime.repo.hasActiveAdmin()) || runtime.config.bootstrapAdminEmails.size === 0) {
      return new Response("Not found", { status: 404 });
    }
    return renderBootstrap();
  });

  app.post("/admin/bootstrap", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const email = normalizeEmail(String(form.get("email") ?? ""));
    const emailKey = await emailRateKey(env, "bootstrap", email);
    if (!(await runtime.repo.consumeRateLimits([emailKey], 3, 900))) {
      return renderBootstrap("Too many bootstrap attempts. Try again later.");
    }
    let otpId: string = crypto.randomUUID();
    if (runtime.config.bootstrapAdminEmails.has(email) && !(await runtime.repo.hasActiveAdmin())) {
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
  });

  app.post("/admin/bootstrap/verify", async (c) => {
    const form = await c.req.raw.formData();
    assertCsrf(c.req.raw, form);
    const verified = await runtime.repo.verifyOtpChallenge({
      code: String(form.get("code") ?? ""),
      id: String(form.get("otp_id") ?? ""),
      secrets: secrets(env)
    });
    if (!verified || verified.purpose !== "bootstrap_admin" || !runtime.config.bootstrapAdminEmails.has(verified.email)) {
      return renderBootstrapVerify(String(form.get("email") ?? ""), String(form.get("otp_id") ?? ""), "Invalid or expired code.");
    }
    const user = await runtime.repo.consumeInitialBootstrapAndCreateAdmin(verified.email, runtime.requestId);
    if (!user) {
      return new Response("Bootstrap is no longer available", { status: 409 });
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
    const failed = adminOutcomeResponse("User grant timeout update", outcome);
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

  app.post("/admin/clients", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.client.create");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const redirectUris = String(form.get("redirect_uris") ?? "")
      .split(/\s+/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (redirectUris.length === 0 || redirectUris.some((uri) => !isAllowedRedirectUri(uri))) {
      return new Response("Invalid redirect URI", { status: 400 });
    }
    const clientCreationRequestId = await runtime.repo.createClientCreationRequest(admin.user.id, {
      clientName: String(form.get("client_name") ?? "MCP Client"),
      redirectUris
    });
    let created: ClientInfo | null = null;
    try {
      created = await c.env.OAUTH_PROVIDER.createClient({
        clientName: String(form.get("client_name") ?? "MCP Client"),
        grantTypes: ["authorization_code", "refresh_token"],
        redirectUris,
        responseTypes: ["code"],
        tokenEndpointAuthMethod: "none"
      });
      if (created.tokenEndpointAuthMethod !== "none") {
        throw new Error("Provider did not create a public client");
      }
      await runtime.repo.createOrUpdateClientPolicy({
        actorUserId: admin.user.id,
        clientId: created.clientId,
        metadata: created,
        redirectUris: created.redirectUris,
        requestId: runtime.requestId,
        source: "admin_created",
        status: "active"
      });
      await runtime.repo.markClientCreationRequest(clientCreationRequestId, "succeeded", created.clientId);
    } catch (error) {
      await runtime.repo.markClientCreationRequest(clientCreationRequestId, "failed", created?.clientId ?? null);
      if (!created) {
        throw error;
      }
      const createdClient = created;
      await c.env.OAUTH_PROVIDER.deleteClient(createdClient.clientId).catch(async (deleteError) => {
        await runtime.repo.enqueueJob({
          idempotencyKey: `delete-client:${createdClient.clientId}`,
          payload: { clientId: createdClient.clientId },
          requestId: runtime.requestId,
          targetClientId: createdClient.clientId,
          type: "delete_provider_client"
        });
        console.warn(deleteError);
      });
      return new Response("Client creation failed", { status: 503 });
    }
    await touchSessionAfterSafeValidation(runtime, "admin.client.create", validation);
    return redirect("/admin");
  });

  app.post("/admin/cimd/approve", async (c) => {
    const authorized = await requireHighRiskAdmin(c.req.raw, runtime, "admin.cimd.approve");
    if (authorized instanceof Response) {
      return authorized;
    }
    const { admin, form, validation } = authorized;
    const clientId = String(form.get("client_id") ?? "");
    if (!isUrlClientId(clientId) || !isPublicHttpsUrl(clientId)) {
      return new Response("Invalid CIMD client_id URL", { status: 400 });
    }
    const metadata = await fetchClientMetadata(clientId);
    const redirectUris = metadata.redirectUris;
    if (redirectUris.length === 0 || redirectUris.some((uri) => !isAllowedRedirectUri(uri))) {
      return new Response("Invalid CIMD redirect URI metadata", { status: 400 });
    }
    await runtime.repo.createOrUpdateClientPolicy({
      actorUserId: admin.user.id,
      clientId,
      metadata: metadata.raw,
      redirectUris,
      requestId: runtime.requestId,
      source: "cimd",
      status: "active"
    });
    await touchSessionAfterSafeValidation(runtime, "admin.cimd.approve", validation);
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
    const failed = adminOutcomeResponse("Client revoke", outcome);
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

  app.get("/authorize", async (c) => {
    const session = await runtime.repo.getSession(readCookie(c.req.raw, SESSION_COOKIE));
    if (!session) {
      return renderLogin(`${new URL(c.req.url).pathname}${new URL(c.req.url).search}`);
    }
    const validation = makeValidatedSessionContext("authorize.get", session, ["session"]);
    const oauthReq = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
    const response = await renderOrCompleteAuthorization(c.env.OAUTH_PROVIDER, c.env.AUTH_FLOW_KV, runtime, session, oauthReq);
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
  if (!policy || policy.status !== "active") {
    return oauthRedirectError(request, "unauthorized_client", "Client is not active.");
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
  if (!currentUser || currentUser.status !== "active" || !policy || policy.status !== "active") {
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
    client_source: policy.source,
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
  return (
    capability.requiredScopes.every((scope) => scopeSet.has(scope)) &&
    capability.requiredPermissions.every((permission) => permissionSet.has(permission))
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

async function fetchClientMetadata(clientId: string): Promise<{ raw: unknown; redirectUris: string[] }> {
  const response = await fetch(clientId, {
    headers: { Accept: "application/json" },
    redirect: "error"
  });
  if (!response.ok) {
    throw new Error(`CIMD metadata fetch failed with ${response.status}`);
  }
  const raw = (await response.json()) as Record<string, unknown>;
  const redirectUris =
    Array.isArray(raw.redirect_uris)
      ? raw.redirect_uris.map(String)
      : Array.isArray(raw.redirectUris)
        ? raw.redirectUris.map(String)
        : [];
  return { raw, redirectUris };
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
  consent: { id: string; user_id: string; client_id: string; resource: string; scope_hash: string; revoked_at: string | null }
): boolean {
  return (
    grant.userId === metadata.user_id &&
    grant.clientId === metadata.client_id &&
    consent.id === metadata.consent_id &&
    consent.user_id === metadata.user_id &&
    consent.client_id === metadata.client_id &&
    consent.resource === metadata.resource &&
    consent.scope_hash === metadata.scope_hash &&
    !consent.revoked_at
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

function renderHome<Env extends AuthWorkerEnv>(runtime: Runtime<Env>): Response {
  return html(`<!doctype html><html><body>
    <h1>${escapeHtml(runtime.config.serverName)}</h1>
    <p>${escapeHtml(runtime.config.serverDescription)}</p>
    <p>MCP endpoint: ${escapeHtml(runtime.config.resource)}</p>
  </body></html>`);
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

function renderOtp(email: string, otpId: string, returnTo: string, error?: string): Response {
  const csrf = randomBase64Url(16);
  return html(
    formPage(
      "Enter code",
      error,
      `<input type="hidden" name="csrf_token" value="${csrf}">
       <input type="hidden" name="email" value="${escapeHtml(email)}">
       <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}">
       <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
       <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
       <button type="submit">Verify</button>`,
      "/login/verify"
    ),
    csrf
  );
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
      "/admin/bootstrap"
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
      "/admin/bootstrap/verify"
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
      `<p>${escapeHtml(email)} authorizes <code>${escapeHtml(request.clientId)}</code>.</p>
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
      <h1>${escapeHtml(runtime.config.serverName)} Provider grants</h1>
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
      return new Response(`Grant timeout must be a positive whole number of seconds up to ${MAX_GRANT_TTL_SECONDS}`, {
        status: 400
      });
    }
    return { inherit: false, ttlSeconds: parsed };
  }
  return new Response("Invalid grant timeout mode", { status: 400 });
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
    return "Revoke selected sessions";
  }
  if (action === "revoke_grants") {
    return "Revoke selected grants";
  }
  if (action === "revoke_authorization") {
    return "Revoke selected authorization";
  }
  return "Set selected grant timeout";
}

function formatGrantTimeout(ttlSeconds: number | null): string {
  return ttlSeconds === null ? "unlimited" : `${ttlSeconds}s`;
}

function formatGrantExpiresAt(expiresAt: string | null): string {
  return expiresAt ?? "unlimited";
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
         <p>Grant timeout: ${escapeHtml(grantTimeoutMode === "custom" ? `${grantTtlSeconds}s` : grantTimeoutMode)}</p>`
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

function renderAdmin<Env extends AuthWorkerEnv>(
  runtime: Runtime<Env>,
  adminEmail: string,
  users: AdminUserRow[],
  defaultGrantTtlSeconds: number | null,
  clients: Array<{ client_id: string; status: string; source: string }>,
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
              <select name="grant_timeout_mode">
                <option value="inherit"${!user.grant_ttl_override ? " selected" : ""}>inherit</option>
                <option value="unlimited"${user.grant_ttl_override && user.grant_ttl_seconds === null ? " selected" : ""}>unlimited</option>
                <option value="custom"${user.grant_ttl_override && user.grant_ttl_seconds !== null ? " selected" : ""}>custom</option>
              </select>
              <input name="grant_ttl_seconds" inputmode="numeric" value="${user.grant_ttl_seconds ?? ""}" placeholder="seconds">
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
              <button type="submit">Revoke sessions</button>
            </form>
            <form method="post" action="/admin/users/consents/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(user.id)}">
              <button type="submit">Revoke grants</button>
            </form>
            <a href="/admin/provider-grants?user_id=${encodeURIComponent(user.id)}">Provider grants</a>
            <form method="post" action="/admin/users/authorization/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="user_id" value="${escapeHtml(user.id)}">
              <button type="submit">Revoke all authorization</button>
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
          <option value="revoke_sessions">Revoke selected sessions</option>
          <option value="revoke_grants">Revoke selected grants</option>
          <option value="revoke_authorization">Revoke selected authorization</option>
          <option value="set_grant_timeout">Set selected grant timeout</option>
        </select>
        <select name="bulk_grant_timeout_mode">
          <option value="inherit">inherit</option>
          <option value="unlimited">unlimited</option>
          <option value="custom">custom</option>
        </select>
        <input name="bulk_grant_ttl_seconds" inputmode="numeric" placeholder="seconds">
        <button type="submit">Review bulk action</button>
      </form>`;
  const clientRows = clients
    .map(
      (client) =>
        `<tr>
          <td>${escapeHtml(client.client_id)}</td>
          <td>${escapeHtml(client.source)}</td>
          <td>${escapeHtml(client.status)}</td>
          <td>
            <form method="post" action="/admin/clients/revoke">
              <input type="hidden" name="csrf_token" value="${csrf}">
              <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
              <button type="submit">Revoke</button>
            </form>
          </td>
        </tr>`
    )
    .join("");
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
          <td>${escapeHtml(consent.client_id)}</td>
          <td>${escapeHtml(consent.canonical_scope)}</td>
          <td>${escapeHtml(formatGrantExpiresAt(consent.expires_at))}</td>
          <td>${escapeHtml(consent.revoked_at ?? "")}</td>
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
      <p>${escapeHtml(adminEmail)}</p>
      <form method="post" action="/logout">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <button type="submit">Sign out</button>
      </form>
      <h2>OAuth Grant Timeout</h2>
      <p>Default: ${escapeHtml(formatGrantTimeout(defaultGrantTtlSeconds))}</p>
      <form method="post" action="/admin/oauth-policy">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <select name="default_grant_timeout_mode">
          <option value="unlimited"${defaultGrantTtlSeconds === null ? " selected" : ""}>unlimited</option>
          <option value="custom"${defaultGrantTtlSeconds !== null ? " selected" : ""}>custom</option>
        </select>
        <input name="default_grant_ttl_seconds" inputmode="numeric" value="${defaultGrantTtlSeconds ?? ""}" placeholder="seconds">
        <button type="submit">Save</button>
      </form>
      <form method="post" action="/admin/users">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <label>Email <input name="email" type="email" required></label>
        ${permissionCheckboxes([])}
        <button type="submit">Add user</button>
      </form>
      <h2>Users</h2>${bulkUsersForm}<table><thead><tr><th>Select</th><th>Email</th><th>Grant timeout</th><th>State</th><th>Revoke</th></tr></thead><tbody>${rows}</tbody></table>
      <h2>Clients</h2>
      <form method="post" action="/admin/clients">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <label>Name <input name="client_name" required></label>
        <label>Redirect URIs <textarea name="redirect_uris" required></textarea></label>
        <button type="submit">Create public client</button>
      </form>
      <form method="post" action="/admin/cimd/approve">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <label>Client ID URL <input name="client_id" type="url" required></label>
        <button type="submit">Approve CIMD client</button>
      </form>
      <table><thead><tr><th>Client</th><th>Source</th><th>Status</th><th>Action</th></tr></thead><tbody>${clientRows}</tbody></table>
      <h2>Provider grants</h2>
      <p>Open provider grants from a user row.</p>
      <h2>Active sessions</h2><table><thead><tr><th>Session</th><th>User</th><th>Created</th><th>Last seen</th><th>Last touched</th><th>IP prefix</th><th>User agent</th><th>Active until</th><th>Absolute until</th><th>Action</th></tr></thead><tbody>${sessionRows}</tbody></table>
      <h2>Consents</h2><table><thead><tr><th>User</th><th>Client</th><th>Scope</th><th>Expires</th><th>Revoked</th><th>Action</th></tr></thead><tbody>${consentRows}</tbody></table>
      <h2>Jobs</h2><table><thead><tr><th>Type</th><th>Status</th><th>Attempts</th><th>Updated</th></tr></thead><tbody>${jobRows}</tbody></table>
      <h2>Audit</h2><table><thead><tr><th>Created</th><th>Event</th><th>Result</th><th>Request</th></tr></thead><tbody>${auditRows}</tbody></table>
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

function redirect(location: string, headers = new Headers()): Response {
  headers.set("Location", location);
  headers.set("Cache-Control", "no-store");
  return new Response(null, { headers, status: 302 });
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
    throw new Error("Invalid CSRF token");
  }
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
  const policies = new Map((await repo.listClientPolicies()).map((policy) => [policy.client_id, policy.status]));
  const nowSeconds = Math.floor(Date.now() / 1000);
  let cursor: string | undefined;
  do {
    const result = await helpers.listClients(cursor ? { cursor, limit: 100 } : { limit: 100 });
    for (const client of result.items) {
      const policyStatus = policies.get(client.clientId);
      if (policyStatus === "active" || policyStatus === "pending") {
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
