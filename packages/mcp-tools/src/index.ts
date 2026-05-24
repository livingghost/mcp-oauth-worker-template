import { createMcpHandler } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { AuthContext, AuthorizationRuntime, CapabilityRequirement } from "@mcp-auth/shared";

export interface McpRuntimeOptions<Env> {
  authContext: AuthContext;
  authorizationRuntime: AuthorizationRuntime;
  env: Env;
  ctx: ExecutionContext;
  request: Request;
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
      server.registerTool("whoami", {
        annotations: {
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
          readOnlyHint: true,
          title: "Show MCP authorization context"
        },
        description:
          "Return the OAuth-authenticated MCP user, client, resource, scopes, and granted permissions. Use this to confirm which account and authorization context are active.",
        inputSchema: {},
        title: "Show MCP authorization context",
        _meta: {
          "mcp-auth/toolCategory": "read",
          "openai/toolInvocation/invoked": "Authorization context ready",
          "openai/toolInvocation/invoking": "Reading authorization context..."
        }
      }, async () => {
        assertCapability(options, capability);
        return jsonResult({
          clientId: options.authContext.client.id,
          clientVersion: options.authContext.client.version,
          permissions: options.authContext.permissions,
          resource: options.authContext.resource,
          scopes: options.authContext.scopes,
          userEmail: options.authContext.user.email,
          userId: options.authContext.user.id
        });
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

function jsonResult(value: unknown): CallToolResult {
  return {
    content: [
      {
        text: JSON.stringify(value, null, 2),
        type: "text"
      }
    ]
  };
}

function assertCapability<Env>(
  options: McpRuntimeOptions<Env>,
  capability: CapabilityRequirement
): void {
  if (!options.authorizationRuntime.canUseCapability(options.authContext, capability)) {
    throw new Error("Capability is not authorized");
  }
}
