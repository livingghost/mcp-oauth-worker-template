import { createAuthDb } from "./client.js";
import { runAuthMigrations } from "./migrations.js";

declare const process: {
  env: Record<string, string | undefined>;
};

const url = process.env.AUTH_TURSO_DATABASE_URL;
const databaseToken = process.env.AUTH_TURSO_DATABASE_TOKEN;

if (!url || !databaseToken) {
  throw new Error("AUTH_TURSO_DATABASE_URL and AUTH_TURSO_DATABASE_TOKEN are required");
}

await runAuthMigrations(
  createAuthDb({
    AUTH_TURSO_DATABASE_TOKEN: databaseToken,
    AUTH_TURSO_DATABASE_URL: url
  })
);
console.log("Auth migrations applied");
