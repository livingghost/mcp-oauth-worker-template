import type { AuthWorkerEnv } from "@mcp-auth/auth-worker";

export interface Env extends AuthWorkerEnv {
  MCP_SERVER_NAME?: string;
  MCP_SERVER_DESCRIPTION?: string;
}
