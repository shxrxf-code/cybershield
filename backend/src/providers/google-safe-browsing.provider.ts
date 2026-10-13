import type { SourceResult } from '../domain/verdict';
import { fetchJson } from '../utils/http';
import { UpstreamError } from '../utils/errors';
import type { ProviderDeps, UrlQuery, UrlReputationProvider } from './types';
import { disabledResult } from './types';

/**
 * Google Safe Browsing v4 – `threatMatches.find`.
 *
 * We only ever send the URL string. No file, page content or user identity is
 * transmitted. An empty `matches` array is a genuine "not listed" answer, which
 * is the one thing that lets the merged verdict become SAFE.
 */

const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
] as const;

interface GsbMatch {
  threatType?: string;
  platformType?: string;
  threat?: { url?: string };
  cacheDuration?: string;
}

interface GsbResponse {
  matches?: GsbMatch[];
}

const CATEGORY_BY_THREAT_TYPE: Record<string, SourceResult['categories']> = {
  MALWARE: ['malware'],
  SOCIAL_ENGINEERING: ['phishing'],
  UNWANTED_SOFTWARE: ['unwanted-software'],
  POTENTIALLY_HARMFUL_APPLICATION: ['unwanted-software'],
};

export class GoogleSafeBrowsingProvider implements UrlReputationProvider {
  readonly id = 'google-safe-browsing';
  readonly label = 'Google Safe Browsing';

  constructor(private readonly deps: ProviderDeps) {}

  isConfigured(): boolean {
    return this.deps.env.INTEL_ENABLED && Boolean(this.deps.env.GOOGLE_SAFE_BROWSING_API_KEY);
  }

  async query(input: UrlQuery): Promise<SourceResult> {
    const started = Date.now();
    const key = this.deps.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!this.deps.env.INTEL_ENABLED) return disabledResult(this.id, 'Threat intelligence disabled');
    if (!key) return disabledResult(this.id, 'Google Safe Browsing API key not configured');

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`;

    try {
      const response = await fetchJson<GsbResponse>(endpoint, {
        method: 'POST',
        provider: this.label,
        timeoutMs: this.deps.timeoutMs,
        minIntervalMs: this.deps.env.INTEL_MIN_REQUEST_INTERVAL_MS,
        fetchImpl: this.deps.fetchImpl,
        body: {
          client: { clientId: 'mobile-threatguard', clientVersion: '0.1.0' },
          threatInfo: {
            threatTypes: [...THREAT_TYPES],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: input.canonical }],
          },
        },
      });

      if (!response.ok) {
        return {
          source: this.id,
          status: 'UNKNOWN',
          reasons: [],
          detail: `Safe Browsing returned HTTP ${response.status}`,
          error: `upstream status ${response.status}`,
          durationMs: Date.now() - started,
        };
      }

      const matches = response.data?.matches ?? [];
      if (matches.length === 0) {
        return {
          source: this.id,
          status: 'SAFE',
          reasons: [],
          detail: 'Not present in the Google Safe Browsing threat lists.',
          durationMs: Date.now() - started,
        };
      }

      const threatTypes = Array.from(
        new Set(matches.map((match) => match.threatType).filter((t): t is string => Boolean(t))),
      );
      const categories = threatTypes.flatMap((type) => CATEGORY_BY_THREAT_TYPE[type] ?? []);

      return {
        source: this.id,
        status: 'MALICIOUS',
        categories: categories.length > 0 ? Array.from(new Set(categories)) : ['malware'],
        reasons: [
          {
            code: 'gsb-listed',
            message: `Google Safe Browsing lists this address as ${threatTypes.join(', ') || 'unsafe'}.`,
            weight: 100,
            severity: 'critical',
          },
        ],
        detail: `Listed by Google Safe Browsing (${threatTypes.join(', ') || 'unsafe'}).`,
        durationMs: Date.now() - started,
      };
    } catch (error) {
      return {
        source: this.id,
        status: 'UNKNOWN',
        reasons: [],
        detail: 'Google Safe Browsing could not be reached.',
        error: error instanceof UpstreamError ? error.message : 'unexpected provider error',
        durationMs: Date.now() - started,
      };
    }
  }
}
