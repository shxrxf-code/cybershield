/**
 * Minimal database abstraction.
 *
 * Two concrete drivers implement it: SQLite (Node's built-in `node:sqlite`,
 * used for development and tests) and PostgreSQL (`pg`, used in production).
 *
 * SQL is written with `?` placeholders. The PostgreSQL driver rewrites them to
 * `$1..$n`, so repositories contain one copy of each statement. Repositories
 * are the only place that talk to this interface – nothing else issues SQL.
 */

export type Dialect = 'sqlite' | 'postgres';

export type SqlValue = string | number | bigint | boolean | null | undefined | Date | Uint8Array;

export interface QueryResult<T> {
  rows: T[];
  rowCount: number;
}

export interface ExecuteResult {
  changes: number;
  lastInsertId?: string | number;
}

export interface Database {
  readonly dialect: Dialect;
  query<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): Promise<QueryResult<T>>;
  execute(sql: string, params?: SqlValue[]): Promise<ExecuteResult>;
  /** Run several statements as one migration step (no parameters). */
  execRaw(sql: string): Promise<void>;
  transaction<T>(work: (tx: Database) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/** Normalise JS values into something a driver accepts. */
export function normalizeParam(value: SqlValue): string | number | bigint | null | Uint8Array {
  if (value === undefined || value === null) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (value instanceof Date) return value.toISOString();
  return value;
}

/**
 * Convert `?` placeholders to PostgreSQL's `$1..$n`.
 *
 * Query strings in this codebase never contain a `?` inside a string literal,
 * which keeps this translation safe and simple.
 */
export function toPostgresPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => {
    index += 1;
    return `$${index}`;
  });
}
