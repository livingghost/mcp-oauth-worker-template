import { connect, type Connection } from "@tursodatabase/serverless";

export interface AuthTursoEnv {
  AUTH_TURSO_DATABASE_URL: string;
  AUTH_TURSO_DATABASE_TOKEN: string;
}

export type SqlValue = string | number | boolean | null;

export interface DbStatement {
  all?: (args?: SqlValue[]) => Promise<unknown>;
  get?: (args?: SqlValue[]) => Promise<unknown>;
  run?: (args?: SqlValue[]) => Promise<unknown>;
}

export interface DbContext {
  readonly inTransaction?: boolean;
  prepare(sql: string): Promise<DbStatement> | DbStatement;
  pragma?(pragma: string): Promise<unknown>;
  transaction?(fn: () => unknown): { immediate: () => Promise<unknown> };
}

interface BaseAuthDb {
  readonly ctx: DbContext;
  all<T = Record<string, unknown>>(sql: string, args?: SqlValue[]): Promise<T[]>;
  get<T = Record<string, unknown>>(sql: string, args?: SqlValue[]): Promise<T | null>;
  pragma(pragma: string): Promise<unknown>;
  run(sql: string, args?: SqlValue[]): Promise<void>;
}

export interface TxAuthDb extends BaseAuthDb {
  readonly kind: "tx";
}

export interface AuthDb extends BaseAuthDb {
  readonly kind: "root";
  withWriteTransaction<T>(fn: (tx: TxAuthDb) => Promise<T>): Promise<T>;
}

export function createAuthDb(env: AuthTursoEnv): AuthDb {
  return createAuthDbFromConnection(
    connect({
      authToken: env.AUTH_TURSO_DATABASE_TOKEN,
      url: env.AUTH_TURSO_DATABASE_URL
    })
  );
}

export function createAuthDbFromConnection(connection: Connection): AuthDb {
  return createRootAuthDb(connection as unknown as DbContext);
}

function createBaseAuthDb(
  ctx: DbContext,
  kind: "root" | "tx",
  assertAvailable: (() => void) | undefined = undefined
): BaseAuthDb & { readonly kind: "root" | "tx" } {
  const db: BaseAuthDb & { readonly kind: "root" | "tx" } = {
    ctx,
    kind,
    async all<T = Record<string, unknown>>(sql: string, args: SqlValue[] = []): Promise<T[]> {
      assertAvailable?.();
      const stmt = await ctx.prepare(sql);
      if (!stmt.all) {
        throw new Error("Turso statement all() is required");
      }
      const result = await stmt.all(args);
      if (Array.isArray(result)) {
        return result as T[];
      }
      return (((result as { rows?: unknown[] }).rows ?? []) as T[]);
    },
    async get<T = Record<string, unknown>>(sql: string, args: SqlValue[] = []): Promise<T | null> {
      assertAvailable?.();
      const stmt = await ctx.prepare(sql);
      if (stmt.get) {
        return (await stmt.get(args)) as T | null;
      }
      const rows = await db.all<T>(sql, args);
      return rows[0] ?? null;
    },
    async pragma(pragma: string): Promise<unknown> {
      assertAvailable?.();
      if (!/^[A-Za-z_][A-Za-z0-9_]*(?:\s*=\s*(?:ON|OFF|[0-9]+))?$/.test(pragma)) {
        throw new Error("Invalid PRAGMA statement");
      }
      if (ctx.pragma) {
        return ctx.pragma(pragma);
      }
      return db.all(`PRAGMA ${pragma}`);
    },
    async run(sql: string, args: SqlValue[] = []): Promise<void> {
      assertAvailable?.();
      const stmt = await ctx.prepare(sql);
      if (!stmt.run) {
        throw new Error("Turso statement run() is required");
      }
      await stmt.run(args);
    }
  };
  return db;
}

function createRootAuthDb(ctx: DbContext): AuthDb {
  let transactionActive = false;
  const base = createBaseAuthDb(ctx, "root", () => {
    if (transactionActive || ctx.inTransaction) {
      throw new Error("Root auth-db queries are not allowed while a write transaction is active");
    }
  });
  return {
    ...base,
    kind: "root",
    async withWriteTransaction<T>(fn: (tx: TxAuthDb) => Promise<T>): Promise<T> {
      if (!ctx.transaction) {
        throw new Error("Turso connection transaction() is required");
      }
      if (transactionActive || ctx.inTransaction) {
        throw new Error("Auth-db write transactions must not be nested");
      }
      transactionActive = true;
      try {
        const runInTransaction = ctx.transaction(async () => {
          const tx = createBaseAuthDb(ctx, "tx") as TxAuthDb;
          return fn(tx);
        });
        return (await runInTransaction.immediate()) as T;
      } finally {
        transactionActive = false;
      }
    }
  };
}
