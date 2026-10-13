/**
 * A tiny in-process TTL cache.
 *
 * Purpose: reputation lookups are expensive (network + external quota). We
 * cache by key with an explicit expiry and never treat an expired entry as a
 * hit. A production deployment with several instances would swap this for
 * Redis; the interface is kept deliberately small so that is a drop-in change.
 */

export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  storedAt: number;
}

export interface CacheOptions {
  /** Default TTL in milliseconds for entries stored without an explicit TTL. */
  defaultTtlMs: number;
  /** Hard cap on entries; oldest are evicted first. */
  maxEntries?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

export class TtlCache<T> {
  private readonly store = new Map<string, CacheEntry<T>>();
  private readonly defaultTtlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: CacheOptions) {
    this.defaultTtlMs = options.defaultTtlMs;
    this.maxEntries = options.maxEntries ?? 5_000;
    this.now = options.now ?? Date.now;
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.store.delete(key);
      return undefined;
    }
    // Refresh recency for LRU eviction.
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  set(key: string, value: T, ttlMs?: number): void {
    const ttl = ttlMs ?? this.defaultTtlMs;
    if (ttl <= 0) return;
    if (this.store.size >= this.maxEntries && !this.store.has(key)) {
      const oldest = this.store.keys().next();
      if (!oldest.done) this.store.delete(oldest.value);
    }
    const now = this.now();
    this.store.set(key, { value, expiresAt: now + ttl, storedAt: now });
  }

  delete(key: string): boolean {
    return this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  get size(): number {
    return this.store.size;
  }

  /** Remove expired entries; call periodically if the cache is long-lived. */
  prune(): number {
    const now = this.now();
    let removed = 0;
    for (const [key, entry] of this.store) {
      if (entry.expiresAt <= now) {
        this.store.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  /** Age of an entry in milliseconds, or undefined when absent/expired. */
  ageOf(key: string): number | undefined {
    const entry = this.store.get(key);
    if (!entry || entry.expiresAt <= this.now()) return undefined;
    return this.now() - entry.storedAt;
  }
}

/**
 * Cache a verdict only for a bounded window. Threat reputation is a
 * time-sensitive judgement, so callers should never cache "safe" forever.
 */
export const CACHE_TTL = {
  /** A brand-new lookup with no verdict (UNKNOWN) is retried sooner. */
  UNKNOWN_VERDICT_MS: 5 * 60 * 1000,
  /** A definitive verdict can live longer. */
  DEFINITIVE_VERDICT_MS: 6 * 60 * 60 * 1000,
  /** Provider errors are not cached (we want to retry). */
} as const;
