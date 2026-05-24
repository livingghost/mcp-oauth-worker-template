import { createAuthDb } from "./client.js";

declare const process: {
  env: Record<string, string | undefined>;
};

const url = process.env.AUTH_TURSO_DATABASE_URL;
const databaseToken = process.env.AUTH_TURSO_DATABASE_TOKEN;

if (!url || !databaseToken) {
  throw new Error("AUTH_TURSO_DATABASE_URL and AUTH_TURSO_DATABASE_TOKEN are required");
}

const db = createAuthDb({
  AUTH_TURSO_DATABASE_TOKEN: databaseToken,
  AUTH_TURSO_DATABASE_URL: url
});

await db.run("VACUUM");
await db.run("PRAGMA optimize");
console.log("Auth database compacted");
