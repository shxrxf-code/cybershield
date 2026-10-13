import type { Database } from '../adapter';

/**
 * Durable tier of the reputation cache.
 *
 * The in-memory TTL cache handles the hot path; this table survives restarts
 * so we do not re-query external providers for the same verdict after a
 * deploy. Expired rows are ignored on read and swept periodically.
 */

export interface CachedVerdict {
  cacheKey: string;
  kind: 'url' | 'hash';
  verdict: string;
  provider?: string;
  payload: unknown;
  createdAt: string;
  expiresAt: string;
}

interface CacheRow {
  cache_key: string;
  kind: string;
  verdict: string;
  provider: string | null;
  payload: string;
  created_at: string;
  expires_at: string;
}

function mapRow(row: CacheRow): CachedVerdict {
  let payload: unknown = {};
  try {
    payload = JSON.parse(row.payload);
  } catch {
    payload = {};
  }
  return {
    cacheKey: row.cache_key,
    kind: row.kind as 'url' | 'hash',
    verdict: row.verdict,
    provider: row.provider ?? undefined,
    payload,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

export class ReputationCacheRepository {
  constructor(private readonly db: Database) {}

  async get(cacheKey: string): Promise<CachedVerdict | undefined> {
    const { rows } = await this.db.query<CacheRow>(
      'SELECT * FROM reputation_cache WHERE cache_key = ? AND expires_at > ?',
      [cacheKey, new Date().toISOString()],
    );
    return rows[0] ? mapRow(rows[0]) : undefined;
  }

  async set(entry: Omit<CachedVerdict, 'createdAt'> & { createdAt?: string }): Promise<void> {
    const createdAt = entry.createdAt ?? new Date().toISOString();
    await this.db.execute(
      `INSERT INTO reputation_cache (cache_key, kind, verdict, provider, payload, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (cache_key) DO UPDATE SET
         verdict = excluded.verdict,
         provider = excluded.provider,
         payload = excluded.payload,
         created_at = excluded.created_at,
         expires_at = excluded.expires_at`,
      [
        entry.cacheKey,
        entry.kind,
        entry.verdict,
        entry.provider ?? null,
        JSON.stringify(entry.payload ?? {}),
        createdAt,
        entry.expiresAt,
      ],
    );
  }

  async purgeExpired(): Promise<number> {
    const result = await this.db.execute('DELETE FROM reputation_cache WHERE expires_at <= ?', [
      new Date().toISOString(),
    ]);
    return result.changes;
  }

  async clear(): Promise<number> {
    const result = await this.db.execute('DELETE FROM reputation_cache');
    return result.changes;
  }
}
