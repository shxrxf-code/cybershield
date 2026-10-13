import { Pool, type PoolClient } from 'pg';
import {
  normalizeParam,
  toPostgresPlaceholders,
  type Database,
  type Dialect,
  type ExecuteResult,
  type QueryResult,
  type SqlValue,
} from './adapter';

/**
 * PostgreSQL driver (`pg`). Only instantiated when DATABASE_URL points at
 * postgres, so the `pg` dependency is never required for SQLite development.
 */
export class PostgresDatabase implements Database {
  readonly dialect: Dialect = 'postgres';
  private readonly pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: Number(process.env.PG_POOL_MAX ?? 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    });
  }

  async query<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []): Promise<QueryResult<T>> {
    const result = await this.pool.query(toPostgresPlaceholders(sql), params.map(normalizeParam));
    return { rows: result.rows as T[], rowCount: result.rowCount ?? result.rows.length };
  }

  async execute(sql: string, params: SqlValue[] = []): Promise<ExecuteResult> {
    const result = await this.pool.query(toPostgresPlaceholders(sql), params.map(normalizeParam));
    const first = result.rows[0] as { id?: string | number } | undefined;
    return { changes: result.rowCount ?? 0, lastInsertId: first?.id };
  }

  async execRaw(sql: string): Promise<void> {
    await this.pool.query(sql);
  }

  async transaction<T>(work: (tx: Database) => Promise<T>): Promise<T> {
    const client: PoolClient = await this.pool.connect();
    const tx: Database = {
      dialect: 'postgres',
      query: async <R>(sql: string, params: SqlValue[] = []) => {
        const result = await client.query(toPostgresPlaceholders(sql), params.map(normalizeParam));
        return { rows: result.rows as R[], rowCount: result.rowCount ?? result.rows.length };
      },
      execute: async (sql: string, params: SqlValue[] = []) => {
        const result = await client.query(toPostgresPlaceholders(sql), params.map(normalizeParam));
        const first = result.rows[0] as { id?: string | number } | undefined;
        return { changes: result.rowCount ?? 0, lastInsertId: first?.id };
      },
      execRaw: async (sql: string) => {
        await client.query(sql);
      },
      transaction: () => {
        throw new Error('Nested transactions are not supported');
      },
      close: async () => undefined,
    };
    try {
      await client.query('BEGIN');
      const result = await work(tx);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
