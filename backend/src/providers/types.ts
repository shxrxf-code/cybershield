import type { Env } from '../config/env';
import type { SourceResult, ThreatCategory } from '../domain/verdict';

/**
 * A threat-intelligence provider answers one narrow question: "do you know
 * this URL / hash, and what do you know about it?"
 *
 * Providers never throw across this boundary – a failure is reported as an
 * `UNKNOWN` result carrying `error`, so one dead API degrades the overall
 * verdict instead of breaking the request.
 */

export interface ProviderDeps {
  env: Env;
  timeoutMs: number;
  /** Injected for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
}

export interface UrlQuery {
  /** Original, user-supplied URL, unchanged. */
  url: string;
  /** Canonical form used for provider lookups and caching. */
  canonical: string;
}

export interface HashQuery {
  sha256: string;
}

export interface UrlReputationProvider {
  readonly id: string;
  readonly label: string;
  isConfigured(): boolean;
  query(input: UrlQuery): Promise<SourceResult>;
}

export interface HashReputationProvider {
  readonly id: string;
  readonly label: string;
  isConfigured(): boolean;
  queryHash(input: HashQuery): Promise<SourceResult>;
}

export const THREAT_TYPE_CATEGORY: Record<string, ThreatCategory> = {
  MALWARE: 'malware',
  SOCIAL_ENGINEERING: 'phishing',
  UNWANTED_SOFTWARE: 'unwanted-software',
  POTENTIALLY_HARMFUL_APPLICATION: 'unwanted-software',
  'malware_download': 'malware',
  'phishing': 'phishing',
  'scam': 'scam',
};

export function unknownResult(
  source: SourceResult['source'],
  detail: string,
  error?: string,
): SourceResult {
  return { source, status: 'UNKNOWN', reasons: [], detail, error };
}

export function disabledResult(source: SourceResult['source'], reason: string): SourceResult {
  return { source, status: 'UNKNOWN', reasons: [], detail: reason };
}
