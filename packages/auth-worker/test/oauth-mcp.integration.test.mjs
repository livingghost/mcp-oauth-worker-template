import assert from "node:assert/strict";
import { test } from "node:test";

test("OAuth authorization-code flow issues a bearer token that reaches the protected MCP handler", async () => {
  await withQuietProviderWarnings(async () => {
  globalThis.Cloudflare = { compatibilityFlags: { global_fetch_strictly_public: true } };
  const [{ default: OAuthProvider, getOAuthApi }, { buildOAuthProviderOptions }] = await Promise.all([
    import("@cloudflare/workers-oauth-provider"),
    import("../dist/index.js")
  ]);
  const resource = "https://server.example/mcp";
  const redirectUri = "https://client.example/callback";
  const userId = "user-1";
  const authzVersion = 1;
  const consentId = "consent-1";
  const scopeHash = "scope-hash";
  let clientId = "";

  const env = {
    OAUTH_KV: createMemoryKv(),
    AUTH_FLOW_KV: createMemoryKv()
  };
  const ctx = {
    passThroughOnException() {},
    waitUntil(promise) {
      void promise;
    }
  };
  const runtime = {
    config: {
      accessTokenTtlSeconds: 600,
      allowedOrigins: new Set(),
      resource,
      refreshTokenTtlSeconds: undefined,
      serverDescription: "OAuth-protected MCP server",
      serverName: "MCP Server"
    },
    repo: {
      async verifyTokenProps(props, scopes) {
        assert.equal(props.user_id, userId);
        assert.equal(props.authz_version, authzVersion);
        assert.equal(props.client_id, clientId);
        assert.equal(props.resource, resource);
        assert.equal(props.scope_hash, scopeHash);
        assert.equal(props.consent_id, consentId);
        assert.deepEqual(scopes, ["profile"]);
        return {
          client: { id: clientId, version: 1 },
          consentId,
          permissions: [],
          resource,
          scopeHash,
          scopes: ["profile"],
          user: { authzVersion, email: "user@example.com", id: userId, status: "active" }
        };
      }
    },
    requestId: "integration-test",
    workerOptions: {
      createMcpServer({ authContext }) {
        return { authContext };
      },
      async handleMcpRequest(_request, _env, _ctx, server) {
        return new Response(
          JSON.stringify({
            clientId: server.authContext.client.id,
            ok: true,
            resource: server.authContext.resource,
            userId: server.authContext.user.id
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
    }
  };

  const options = buildOAuthProviderOptions(env, runtime);
  const provider = new OAuthProvider(options);
  const helpers = getOAuthApi(options, env);
  const client = await helpers.createClient({
    clientName: "Integration Client",
    grantTypes: ["authorization_code", "refresh_token"],
    redirectUris: [redirectUri],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "none"
  });
  clientId = client.clientId;

  const codeVerifier = "test-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
  const { redirectTo } = await helpers.completeAuthorization({
    metadata: { consent_id: consentId },
    props: {
      authz_version: authzVersion,
      client_id: clientId,
      client_version: 1,
      consent_id: consentId,
      resource,
      scope_hash: scopeHash,
      user_id: userId
    },
    request: {
      clientId,
      codeChallenge: await pkceChallenge(codeVerifier),
      codeChallengeMethod: "S256",
      redirectUri,
      resource,
      responseType: "code",
      scope: ["profile"],
      state: "state-1"
    },
    revokeExistingGrants: false,
    scope: ["profile"],
    userId
  });
  const code = new URL(redirectTo).searchParams.get("code");
  assert.ok(code);

  const tokenResponse = await provider.fetch(
    new Request("https://server.example/token", {
      body: new URLSearchParams({
        client_id: clientId,
        code,
        code_verifier: codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
        resource,
        scope: "profile"
      }),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      method: "POST"
    }),
    env,
    ctx
  );
  assert.equal(tokenResponse.status, 200);
  const tokenBody = await tokenResponse.json();
  assert.equal(tokenBody.expires_in, 600);
  assert.equal(tokenBody.resource, resource);
  assert.equal(tokenBody.scope, "profile");
  assert.ok(tokenBody.access_token);
  assert.ok(tokenBody.refresh_token);

  const rejectedMcp = await provider.fetch(new Request(resource), env, ctx);
  assert.equal(rejectedMcp.status, 401);

  const mcpResponse = await provider.fetch(
    new Request(resource, { headers: { Authorization: `Bearer ${tokenBody.access_token}` } }),
    env,
    ctx
  );
  assert.equal(mcpResponse.status, 200);
  assert.deepEqual(await mcpResponse.json(), {
    clientId,
    ok: true,
    resource,
    userId
  });

  const refreshResponse = await provider.fetch(
    new Request("https://server.example/token", {
      body: new URLSearchParams({
        client_id: clientId,
        grant_type: "refresh_token",
        refresh_token: tokenBody.refresh_token,
        resource,
        scope: "profile"
      }),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      method: "POST"
    }),
    env,
    ctx
  );
  assert.equal(refreshResponse.status, 200);
  const refreshed = await refreshResponse.json();
  assert.ok(refreshed.access_token);
  assert.ok(refreshed.refresh_token);
  assert.equal(refreshed.expires_in, 600);
  });
});

async function withQuietProviderWarnings(fn) {
  const originalCloudflare = globalThis.Cloudflare;
  const originalWarn = console.warn;
  console.warn = (...args) => {
    const message = String(args[0] ?? "");
    const normalized = message.toLowerCase();
    if (
      (normalized.includes("metadata") && normalized.includes("disabled")) ||
      message.startsWith("OAuth error response: 401 invalid_token")
    ) {
      return;
    }
    originalWarn(...args);
  };
  try {
    await fn();
  } finally {
    if (originalCloudflare === undefined) {
      delete globalThis.Cloudflare;
    } else {
      globalThis.Cloudflare = originalCloudflare;
    }
    console.warn = originalWarn;
  }
}

async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return Buffer.from(new Uint8Array(digest)).toString("base64url");
}

function createMemoryKv() {
  const entries = new Map();
  return {
    async delete(key) {
      entries.delete(key);
    },
    async get(key, options) {
      const entry = entries.get(key);
      if (!entry || (entry.expiresAt !== null && entry.expiresAt <= Date.now())) {
        entries.delete(key);
        return null;
      }
      if (options?.type === "json") {
        return JSON.parse(entry.value);
      }
      return entry.value;
    },
    async list(options = {}) {
      const prefix = options.prefix ?? "";
      const keys = [...entries.keys()]
        .filter((key) => key.startsWith(prefix))
        .sort()
        .slice(0, options.limit ?? 1000)
        .map((name) => ({ name }));
      return { keys, list_complete: true };
    },
    async put(key, value, options = {}) {
      const expiresAt =
        typeof options.expiration === "number"
          ? options.expiration * 1000
          : typeof options.expirationTtl === "number"
            ? Date.now() + options.expirationTtl * 1000
            : null;
      entries.set(key, { expiresAt, value: String(value) });
    }
  };
}
