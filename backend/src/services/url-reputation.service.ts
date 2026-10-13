import {
  mergeVerdicts,
  type MergedVerdict,
  type Severity,
  type SourceResult,
  type VerdictStatus,
} from '../domain/verdict';
import { analyzeUrlHeuristics } from '../detection/url/heuristics';
import { normalizeUrl, InvalidUrlError, type NormalizedUrl } from '../detection/url/normalize';
import { queryUrlProviders, type IntelRegistry } from '../providers';
import { CACHE_TTL, TtlCache } from '../utils/cache';
import { ValidationError } from '../utils/errors';
import { scopedLogger } from '../utils/logger';
import type { ReputationCacheRepository } from '../database/repositories/reputation-cache-repository';

export interface UrlScanOutcome {
  input: string;
  normalized: NormalizedUrl;
  verdict: MergedVerdict;
  cached: boolean;
  durationMs: number;
  scannedAt: string;
}

export interface UrlReputationServiceDeps {
  registry: IntelRegistry;
  cache?: TtlCache<SourceResult[]>;
  cacheRepository?: ReputationCacheRepository;
  now?: () => number;
}

/** A single, short sentence telling the user what to do next. */
export function recommendedAction(status: VerdictStatus): string {
  switch (status) {
    case 'MALICIOUS':
      return 'Do not open this link. Delete the message and, if you already entered details, contact your bank or the service directly.';
    case 'SUSPICIOUS':
      return 'Avoid opening this link until you can confirm it is genuine through an official channel.';
    case 'SAFE':
      return 'This address was not reported as dangerous by the sources we checked. Stay alert if anything feels unusual.';
    default:
      return 'We could not confirm this address. Treat it with caution and verify with the sender through a channel you trust.';
  }
}

export function severityLabel(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export class UrlReputationService {
  private readonly log = scopedLogger('url-reputation');
  private readonly cache: TtlCache<SourceResult[]>;
  private readonly now: () => number;

  constructor(private readonly deps: UrlReputationServiceDeps) {
    this.cache =
      deps.cache ??
      new TtlCache<SourceResult[]>({ defaultTtlMs: CACHE_TTL.DEFINITIVE_VERDICT_MS, maxEntries: 2_000 });
    this.now = deps.now ?? Date.now;
  }

  private ttlFor(status: VerdictStatus): number {
    return status === 'UNKNOWN' ? CACHE_TTL.UNKNOWN_VERDICT_MS : CACHE_TTL.DEFINITIVE_VERDICT_MS;
  }

  /** Normalise `raw`, or raise a ValidationError the API can render. */
  normalize(raw: string): NormalizedUrl {
    try {
      return normalizeUrl(raw);
    } catch (error) {
      if (error instanceof InvalidUrlError) {
        throw new ValidationError(error.message, { input: raw });
      }
      throw error;
    }
  }

  async analyze(raw: string, options: { skipCache?: boolean } = {}): Promise<UrlScanOutcome> {
    const started = this.now();
    const normalized = this.normalize(raw);
    const cacheKey = `url:${normalized.canonical}`;

    let sources: SourceResult[] | undefined;
    let cached = false;

    if (!options.skipCache) {
      const memory = this.cache.get(cacheKey);
      if (memory) {
        sources = memory;
        cached = true;
      } else if (this.deps.cacheRepository) {
        const durable = await this.deps.cacheRepository.get(cacheKey);
        if (durable) {
          sources = durable.payload as SourceResult[];
          cached = true;
          this.cache.set(cacheKey, sources, this.ttlFor(sources.length > 0 ? mergeVerdicts(sources).status : 'UNKNOWN'));
        }
      }
    }

    if (!sources) {
      const heuristics = analyzeUrlHeuristics(normalized);
      const { results } = await queryUrlProviders(this.deps.registry, {
        url: normalized.original,
        canonical: normalized.canonical,
      });
      sources = [heuristics, ...results];
    }

    const verdict = mergeVerdicts(sources);
    const durationMs = this.now() - started;

    if (!cached) {
      const ttl = this.ttlFor(verdict.status);
      this.cache.set(cacheKey, sources, ttl);
      if (this.deps.cacheRepository) {
        try {
          await this.deps.cacheRepository.set({
            cacheKey,
            kind: 'url',
            verdict: verdict.status,
            provider: 'aggregate',
            payload: sources,
            expiresAt: new Date(this.now() + ttl).toISOString(),
          });
        } catch (error) {
          // A cache write failure must never fail the user's scan.
          this.log.warn({ err: error }, 'failed to persist reputation cache entry');
        }
      }
    }

    this.log.info(
      { domain: normalized.domain, status: verdict.status, cached, durationMs },
      'url scan completed',
    );

    return {
      input: raw,
      normalized,
      verdict,
      cached,
      durationMs,
      scannedAt: new Date(this.now()).toISOString(),
    };
  }

  /** Exposed so tests can reset state between cases. */
  clearCache(): void {
    this.cache.clear();
  }
}
