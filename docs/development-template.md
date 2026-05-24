# Development Template Guide

This repository is a Cloudflare Workers template for an OAuth-protected MCP server. The auth surface is reusable, and project-specific MCP behavior belongs in `packages/mcp-tools`.

## Extension Points

```txt
packages/mcp-tools
  Add tools, resources, prompts, and capability requirements.

packages/shared
  Add OAuth scopes, user permissions, token props, and shared utility types.

packages/auth-worker
  Keep provider composition, login, admin, consent, and MCP bearer verification here.

packages/auth-db
  Keep auth persistence and admin operation transactions here.

apps/mcp-worker
  Keep the deployable Worker assembly here.
```

`packages/mcp-tools` must not import `packages/auth-db`. Auth state reaches tools through `AuthContext` and `AuthorizationRuntime`.

## Adding A Tool

1. Add a capability entry to `CAPABILITIES` in `packages/mcp-tools/src/index.ts`.
2. Register the tool in `createMcpServer`.
3. Call `assertCapability(options, capability)` inside the tool handler.
4. Return MCP SDK content from the handler.
5. Add or update tests that prove the capability is listed only when the authenticated context satisfies the required scopes and permissions.

## Adding A Scope

1. Add the scope to `OAUTH_SCOPES` in `packages/shared/src/index.ts`.
2. Update the tool capability `requiredScopes`.
3. Update consent text and test expectations when the new scope changes user-visible authorization.
4. Run `pnpm test`; the permission/scope invariant tests should catch catalog drift.

## Adding A User Permission

1. Add the permission to `USER_PERMISSIONS` in `packages/shared/src/index.ts`.
2. Add it to a capability `requiredPermissions`.
3. Recreate the clean auth schema before release, because this template keeps one initial migration until it is published.
4. Update admin UX text only where operators assign that permission.

## Auth Boundary

- `/mcp` must stay protected by the OAuth provider and then rechecked against Turso state.
- Access tokens stay short-lived.
- Provider refresh grants are non-expiring by default.
- Local grant timeout and revoke are controlled by admin policy, per-user policy, consent state, user status, client status, and `authz_version`.
- Admin bulk user changes must remain one repository transaction and must keep the last active admin guard.

## Verification

Run this set before treating a generated project as template-complete:

```powershell
pnpm build
pnpm test
pnpm verify:dependencies
pnpm --filter @mcp-auth/mcp-worker exec wrangler deploy --dry-run
```

The test suite includes:

- source invariants for package boundaries and security decisions
- repository transaction rollback behavior
- OAuth provider authorization-code and refresh-token integration
- protected `/mcp` bearer-token routing into the MCP handler

## Deployment Shape

The deployable Worker is `apps/mcp-worker`. It composes:

```ts
createProtectedOAuthMcpWorker({
  createMcpServer,
  handleMcpRequest
});
```

For a new project, keep that composition and replace only the MCP capabilities and project metadata first. Change auth internals only when the project has a concrete auth requirement that is not represented by scopes, permissions, grants, or admin policy.
