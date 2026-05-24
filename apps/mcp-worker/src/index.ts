import { createProtectedOAuthMcpWorker } from "@mcp-auth/auth-worker";
import { createMcpServer, handleMcpRequest } from "@mcp-auth/mcp-tools";
import type { Env } from "./env";

export default createProtectedOAuthMcpWorker<Env>({
  createMcpServer,
  handleMcpRequest
});
