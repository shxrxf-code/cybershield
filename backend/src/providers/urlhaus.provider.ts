import type { SourceResult } from '../domain/verdict';
import { fetchJson } from '../utils/http';
import { UpstreamError } from '../utils/errors';
import type { ProviderDeps, UrlQuery, UrlReputationProvider } from './types';
import { disabledResult } from './types';

/**
 * abuse.ch URLhaus.
 *
 * URLhaus is a malware-URL feed. Its API now requires an Auth-Key header.
 * A `no_results` answer means "not in URLhaus"; we treat that as SAFE for the
 * scope URLhaus covers, but the merged verdict still depends on other sources.
 */

interface UrlhausResponse {
  query_status?: 'ok' | 'no_results' | 'invalid_url' | string;
  id?: string;
  urlhaus_reference?: string;
  url_status?: 'online' | 'offline' | 'unknown' | string;
  threat?: string;
  tags?: string[] | null;
  date_added?: string;
}

export class UrlhausProvider implements UrlReputationProvider {
  readonly id = 'urlhaus';
  readonly label = 'URLhaus (abuse.ch)';

  constructor(private readonly deps: ProviderDeps) {}

  isConfigured(): boolean {
    return this.deps.env.INTEL_ENABLED && Boolean(this.deps.env.URLHAUS_AUTH_KEY);
  }

  async query(input: UrlQuery): Promise<SourceResult> {
    const started = Date.now();
    if (!this.deps.env.INTEL_ENABLED) return disabledResult(this.id, 'Threat intelligence disabled');
    const authKey = this.deps.env.URLHAUS_AUTH_KEY;
    if (!authKey) return disabledResult(this.id, 'URLhaus Auth-Key not configured');

    try {
      const response = await fetchJson<UrlhausResponse>('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        provider: this.label,
        timeoutMs: this.deps.timeoutMs,
        minIntervalMs: this.deps.env.INTEL_MIN_REQUEST_INTERVAL_MS,
        headers: { 'Auth-Key': authKey },
        fetchImpl: this.deps.fetchImpl,
        form: { url: input.canonical },
      });

      if (!response.ok) {
        return {
          source: this.id,
          status: 'UNKNOWN',
          reasons: [],
          detail: `URLhaus returned HTTP ${response.status}`,
          error: `upstream status ${response.status}`,
          durationMs: Date.now() - started,
        };
      }

      const data = response.data;
      if (!data || data.query_status === 'no_results') {
        return {
          source: this.id,
          status: 'SAFE',
          reasons: [],
          detail: 'Not present in the URLhaus malware feed.',
          durationMs: Date.now() - started,
        };
      }

      if (data.query_status !== 'ok') {
        return {
          source: this.id,
          status: 'UNKNOWN',
          reasons: [],
          detail: `URLhaus could not classify this URL (${data.query_status ?? 'unknown'}).`,
          durationMs: Date.now() - started,
        };
      }

      const tags = data.tags ?? [];
      const isPhishing = tags.some((tag) => tag.toLowerCase().includes('phish'));
      const status = data.url_status === 'online' ? 'online' : data.url_status ?? 'unknown';

      return {
        source: this.id,
        status: 'MALICIOUS',
        categories: isPhishing ? ['phishing'] : ['malware'],
        reasons: [
          {
            code: 'urlhaus-listed',
            message: `URLhaus lists this address as a known ${isPhishing ? 'phishing' : 'malware'} URL.`,
            weight: 100,
            severity: 'critical',
          },
        ],
        detail: `URLhaus match (threat: ${data.threat ?? 'unknown'}, feed status: ${status}).`,
        durationMs: Date.now() - started,
      };
    } catch (error) {
      return {
        source: this.id,
        status: 'UNKNOWN',
        reasons: [],
        detail: 'URLhaus could not be reached.',
        error: error instanceof UpstreamError ? error.message : 'unexpected provider error',
        durationMs: Date.now() - started,
      };
    }
  }
}
