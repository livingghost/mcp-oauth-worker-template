# Dependency Decisions

Checked on 2026-05-24 by querying `https://registry.npmjs.org/<package>/latest`.

| Package | Adopted version | Registry latest | Decision |
| --- | --- | --- | --- |
| `typescript` | `6.0.3` | `6.0.3` | latest stable |
| `wrangler` | `4.94.0` | `4.94.0` | latest stable |
| `@cloudflare/workers-types` | `4.20260524.1` | `4.20260524.1` | latest stable |
| `@cloudflare/workers-oauth-provider` | `0.7.0` | `0.7.0` | latest stable |
| `@tursodatabase/serverless` | `1.2.0-pre.2` | `1.2.0-pre.2` | registry latest is pre-release; adopted because package latest points to it and Turso Cloud support is required |
| `@modelcontextprotocol/sdk` | `1.29.0` | `1.29.0` | latest stable |
| `agents` | `0.13.2` | `0.13.2` | latest stable |
| `hono` | `4.12.22` | `4.12.22` | latest stable |
| `zod` | `4.4.3` | `4.4.3` | latest stable |

Dependency updates require repeating this check. Pre-release adoption must be recorded here explicitly.
For `@tursodatabase/serverless`, updates must also pass auth-db transaction behavior tests because `withWriteTransaction()` intentionally depends on `connection.transaction(fn).immediate()`.
