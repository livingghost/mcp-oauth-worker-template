import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import type { AuthContext, AuthorizationRuntime, CapabilityRequirement } from "@mcp-auth/shared";
import { z } from "zod";

export interface McpRuntimeOptions<Env> {
  authContext: AuthContext;
  authorizationRuntime: AuthorizationRuntime;
  env: Env;
  ctx: ExecutionContext;
  request: Request;
}

export type McpServerFactory<Env> = (options: McpRuntimeOptions<Env>) => McpServer;

type OutputShape = z.ZodRawShape;
type ProtocolRequestHandler = (request: unknown, extra: unknown) => unknown | Promise<unknown>;
type ToolListRequestHandlerHost = {
  _requestHandlers?: Map<string, ProtocolRequestHandler>;
  setRequestHandler(schema: typeof ListToolsRequestSchema, handler: ProtocolRequestHandler): void;
};
type ToolSecurityScheme = {
  type: "oauth2";
  scopes: [typeof PROFILE_SCOPE];
};

const PROFILE_SCOPE = "profile" as const;
const MCP_TOOL_SECURITY_SCHEMES = [{ type: "oauth2", scopes: [PROFILE_SCOPE] }] satisfies ToolSecurityScheme[];
const TEMPLATE_MCP_INSTRUCTIONS =
  "This is an OAuth-protected MCP server template. Use read-only tools for discovery and add domain-specific tools with clear descriptions, input schemas, output schemas, and safety annotations.";

const currentUserOutputSchema: OutputShape = {
  clientId: z.string(),
  clientVersion: z.number(),
  permissions: z.array(z.string()),
  resource: z.string(),
  scopes: z.array(z.literal(PROFILE_SCOPE)),
  userEmail: z.string().email(),
  userId: z.string()
};

export const CAPABILITIES = [
  {
    kind: "tool",
    name: "get_current_user",
    requiredPermissions: [],
    requiredScopes: [PROFILE_SCOPE],
    requiresFreshAuthz: true,
    visibility: "listed"
  }
] satisfies CapabilityRequirement[];

export function createMcpServer<Env>(options: McpRuntimeOptions<Env>): McpServer {
  const server = new McpServer(
    {
      name: options.authorizationRuntime.serverName,
      version: "0.1.0"
    },
    {
      instructions: TEMPLATE_MCP_INSTRUCTIONS
    }
  );

  const capability = requireCapability("get_current_user");
  if (options.authorizationRuntime.canUseCapability(options.authContext, capability)) {
    const annotations: ToolAnnotations = {
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
      readOnlyHint: true,
      title: "Get Current User"
    };
    server.registerTool(
      "get_current_user",
      {
        annotations,
        description:
          "Return the OAuth-authenticated user and authorization scope for this MCP server. Use this read-only tool to confirm which account is active before calling server-specific tools.",
        inputSchema: {},
        outputSchema: currentUserOutputSchema,
        title: "Get Current User",
        _meta: {
          "mcp-auth/toolCategory": "read",
          "openai/toolInvocation/invoked": "Current user loaded",
          "openai/toolInvocation/invoking": "Loading current user...",
          securitySchemes: MCP_TOOL_SECURITY_SCHEMES
        }
      },
      async () => {
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
      }
    );
  }

  installToolDescriptorSecuritySchemes(server);

  return server;
}

export async function handleMcpRequest<Env>(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  server: unknown
): Promise<Response> {
  const { createMcpHandler } = await import("agents/mcp");
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

function requireCapability(name: string): CapabilityRequirement {
  const capability = CAPABILITIES.find((item) => item.name === name);
  if (!capability) {
    throw new Error(`Unknown capability: ${name}`);
  }
  return capability;
}

function jsonResult(value: unknown): CallToolResult {
  const structuredContent = toStructuredContent(value);
  return {
    content: [
      {
        text: JSON.stringify(structuredContent, null, 2),
        type: "text"
      }
    ],
    structuredContent
  };
}

function toStructuredContent(value: unknown): Record<string, unknown> {
  if (isRecord(value)) {
    return value;
  }
  return { value };
}

function installToolDescriptorSecuritySchemes(server: McpServer): void {
  const protocol = server.server as unknown as ToolListRequestHandlerHost;
  const listToolsHandler = protocol._requestHandlers?.get("tools/list");
  if (!listToolsHandler) {
    throw new Error("tools/list handler is not initialized");
  }
  protocol.setRequestHandler(ListToolsRequestSchema, async (request, extra) => {
    const result = await listToolsHandler(request, extra);
    if (!isRecord(result) || !Array.isArray(result.tools)) {
      return result;
    }
    return {
      ...result,
      tools: result.tools.map(addToolSecuritySchemes)
    };
  });
}

function addToolSecuritySchemes(tool: unknown): unknown {
  if (!isRecord(tool)) {
    return tool;
  }
  return {
    ...tool,
    securitySchemes: MCP_TOOL_SECURITY_SCHEMES,
    _meta: {
      ...(isRecord(tool._meta) ? tool._meta : {}),
      securitySchemes: MCP_TOOL_SECURITY_SCHEMES
    }
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
