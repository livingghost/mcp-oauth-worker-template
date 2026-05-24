import { createMcpHandler } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AuthContext, AuthorizationRuntime, CapabilityRequirement } from "@mcp-auth/shared";

export interface McpRuntimeOptions<Env> {
  authContext: AuthContext;
  authorizationRuntime: AuthorizationRuntime;
  env: Env;
  ctx: ExecutionContext;
}

export type McpServerFactory<Env> = (options: McpRuntimeOptions<Env>) => McpServer;

export const CAPABILITIES = [
  {
    kind: "tool",
    name: "whoami",
    requiredPermissions: [],
    requiredScopes: ["profile"],
    requiresFreshAuthz: true,
    visibility: "listed"
  }
] satisfies CapabilityRequirement[];

export function createMcpServer<Env>(options: McpRuntimeOptions<Env>): McpServer {
  const server = new McpServer({
    name: options.authorizationRuntime.serverName,
    version: "0.0.1"
  });

  for (const capability of CAPABILITIES) {
    if (!options.authorizationRuntime.canUseCapability(options.authContext, capability)) {
      continue;
    }
    if (capability.name === "whoami") {
      server.tool("whoami", "Return the authenticated MCP user context", {}, async () => {
        assertCapability(options, capability);
        return {
          content: [
            {
              text: JSON.stringify(
                {
                  clientId: options.authContext.client.id,
                  permissions: options.authContext.permissions,
                  resource: options.authContext.resource,
                  scopes: options.authContext.scopes,
                  userEmail: options.authContext.user.email,
                  userId: options.authContext.user.id
                },
                null,
                2
              ),
              type: "text"
            }
          ]
        };
      });
    }
  }

  return server;
}

export async function handleMcpRequest<Env>(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  server: unknown
): Promise<Response> {
  return createMcpHandler(server as McpServer)(request, env, ctx);
}

function assertCapability<Env>(
  options: McpRuntimeOptions<Env>,
  capability: CapabilityRequirement
): void {
  if (!options.authorizationRuntime.canUseCapability(options.authContext, capability)) {
    throw new Error("Capability is not authorized");
  }
}
