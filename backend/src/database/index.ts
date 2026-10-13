import { getEnv, resolveDatabaseTarget, type Env } from '../config/env';
import type { Database } from './adapter';
import { runMigrations } from './migrations';
import { SqliteDatabase } from './sqlite-database';
import { PostgresDatabase } from './postgres-database';

export * from './adapter';
export { runMigrations, MIGRATIONS } from './migrations';
export { SqliteDatabase } from './sqlite-database';
export { PostgresDatabase } from './postgres-database';

export interface CreateDatabaseOptions {
  /** Override the connection target (used by tests for an in-memory DB). */
  location?: string;
  client?: 'sqlite' | 'postgres';
  /** Run migrations immediately after connecting (default true). */
  migrate?: boolean;
}

export async function createDatabase(
  env: Env = getEnv(),
  options: CreateDatabaseOptions = {},
): Promise<Database> {
  const target = resolveDatabaseTarget(env);
  const client = options.client ?? target.client;
  const location = options.location ?? target.location;

  const db: Database =
    client === 'postgres' ? new PostgresDatabase(location) : new SqliteDatabase(location);

  if (options.migrate !== false) {
    await runMigrations(db);
  }
  return db;
}

/** A throwaway in-memory database for tests. */
export async function createTestDatabase(): Promise<Database> {
  const db = new SqliteDatabase(':memory:');
  await runMigrations(db);
  return db;
}
