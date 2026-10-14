/**
 * Mobile ThreatGuard — database service.
 *
 * Opens the SQLite database, runs migrations, and provides a singleton DB instance.
 * Uses @op-engineering/op-sqlite for native SQLite access.
 */

import { openAsync, type DB, type QueryResult, type Scalar, type Transaction } from '@op-engineering/op-sqlite';
import { MIGRATIONS, splitSqlStatements } from './schema';

let dbInstance: DB | null = null;
let initPromise: Promise<DB> | null = null;

const DB_NAME = 'threatguard.db';

/**
 * Get or create the database instance. Runs migrations on first open.
 */
export async function getDB(): Promise<DB> {
  if (dbInstance) return dbInstance;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const db = await openAsync({ name: DB_NAME });
    await runMigrations(db);
    dbInstance = db;
    return db;
  })();

  return initPromise;
}

/**
 * Run any pending migrations.
 */
async function runMigrations(db: DB): Promise<void> {
  await db.executeSync(`
    CREATE TABLE IF NOT EXISTS schema_version (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const result = await db.executeSync('SELECT version FROM schema_version ORDER BY version DESC LIMIT 1');
  const currentVersion = (result.rows[0]?.version as number) ?? 0;

  for (const migration of MIGRATIONS) {
    if (migration.from <= currentVersion && migration.to > currentVersion) {
      const statements = splitSqlStatements(migration.sql);
      for (const stmt of statements) {
        await db.executeSync(stmt);
      }
      await db.executeSync('INSERT INTO schema_version (version) VALUES (?)', [migration.to]);
    }
  }
}

/**
 * Execute a single query with parameters.
 */
export async function execute<T = unknown>(
  query: string,
  params?: Scalar[]
): Promise<QueryResult & { rows: T[] }> {
  const db = await getDB();
  return db.execute(query, params) as Promise<QueryResult & { rows: T[] }>;
}

/**
 * Execute a query synchronously (for simple reads).
 * Use sparingly as it blocks the JS thread.
 */
export function executeSync<T = unknown>(
  query: string,
  params?: Scalar[]
): QueryResult & { rows: T[] } {
  if (!dbInstance) {
    throw new Error('Database not initialized. Call getDB() first.');
  }
  return dbInstance.executeSync(query, params) as QueryResult & { rows: T[] };
}

/**
 * Run multiple queries in a transaction.
 */
export async function transaction<T>(
  fn: (tx: Transaction) => Promise<T>
): Promise<T> {
  const db = await getDB();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return db.transaction(fn as any) as Promise<T>;
}

/**
 * Close the database connection.
 */
export async function closeDB(): Promise<void> {
  if (dbInstance) {
    await dbInstance.closeAsync();
    dbInstance = null;
    initPromise = null;
  }
}

/**
 * Delete the database file (for testing or reset).
 */
export function deleteDB(): void {
  if (dbInstance) {
    dbInstance.delete();
    dbInstance = null;
    initPromise = null;
  } else {
    const { open } = require('@op-engineering/op-sqlite');
    const db = open({ name: DB_NAME });
    db.delete();
  }
}

/**
 * Get the database file path (for debugging).
 */
export async function getDBPath(): Promise<string> {
  const db = await getDB();
  return db.getDbPath();
}