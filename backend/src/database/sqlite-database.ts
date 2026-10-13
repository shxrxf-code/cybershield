import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import {
  normalizeParam,
  type Database,
  type Dialect,
  type ExecuteResult,
  type QueryResult,
  type SqlValue,
} from './adapter';

/**
 * SQLite driver built on Node's built-in `node:sqlite` (Node >= 22.5).
 *
 * Using the built-in module means no native compilation, which keeps the
 * development setup reproducible. The API is synchronous; we expose promises so
 * callers cannot accidentally depend on that detail if we swap in an async
 * driver later.
 */
export class SqliteDatabase implements Database {
  readonly dialect: Dialect = 'sqlite';
  private readonly db: DatabaseSync;
  private inTransaction = false;

  constructor(location: string) {
    if (location !== ':memory:') {
      const resolved = path.resolve(location);
      mkdirSync(path.dirname(resolved), { recursive: true });
      this.db = new DatabaseSync(resolved);
    } else {
      this.db = new DatabaseSync(':memory:');
    }
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
  }

  async query<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []): Promise<QueryResult<T>> {
    const statement = this.db.prepare(sql);
    const rows = statement.all(...params.map(normalizeParam)) as T[];
    return { rows, rowCount: rows.length };
  }

  async execute(sql: string, params: SqlValue[] = []): Promise<ExecuteResult> {
    const statement = this.db.prepare(sql);
    const result = statement.run(...params.map(normalizeParam));
    // node:sqlite may hand back a bigint rowid; keep the interface contract
    // (string | number) by down-casting safely, falling back to a string for
    // values beyond Number.MAX_SAFE_INTEGER.
    const rawId = result.lastInsertRowid;
    const lastInsertId: string | number =
      typeof rawId === 'bigint'
        ? rawId <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(rawId)
          : rawId.toString()
        : rawId;
    return {
      changes: Number(result.changes ?? 0),
      lastInsertId,
    };
  }

  async execRaw(sql: string): Promise<void> {
    this.db.exec(sql);
  }

  async transaction<T>(work: (tx: Database) => Promise<T>): Promise<T> {
    // Nested calls simply run inside the outer transaction.
    if (this.inTransaction) return work(this);
    this.inTransaction = true;
    this.db.exec('BEGIN');
    try {
      const result = await work(this);
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* ignore rollback failure */
      }
      throw error;
    } finally {
      this.inTransaction = false;
    }
  }

  async close(): Promise<void> {
    this.db.close();
  }
}
