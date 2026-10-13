import type { SourceResult } from '../domain/verdict';
import { fetchJson } from '../utils/http';
import { UpstreamError } from '../utils/errors';
import type { HashQuery, HashReputationProvider, ProviderDeps, UrlQuery, UrlReputationProvider } from './types';
import { disabledResult } from './types';

/**
 * VirusTotal v3 – report lookup only.
 *
 * We deliberately never *submit* unknown URLs or files: querying an existing
 * report does not upload the user's data to VirusTotal, whereas submitting
 * would. A 404 means "VirusTotal has no report", which is reported as UNKNOWN –
 * never as clean.
 */

interface VtStats {
  harmless?: number;
  malicious?: number;
  suspicious?: number;
  undetected?: number;
  timeout?: number;
}

interface VtAnalysisResponse {
  data?: {
    id?: string;
    type?: string;
    attributes?: {
      last_analysis_stats?: VtStats;
      last_analysis_date?: number;
      meaningful_name?: string;
      names?: string[];
      reputation?: number;
    };
  };
  error?: { code?: string; message?: string };
}

function classify(stats: VtStats | undefined): { status: SourceResult['status']; detail: string; categories?: SourceResult['categories'] } {
  const malicious = stats?.malicious ?? 0;
  const suspicious = stats?.suspicious ?? 0;
  const harmless = stats?.harmless ?? 0;
  const undetected = stats?.undetected ?? 0;
  const total = malicious + suspicious + harmless + undetected;

  if (malicious > 0) {
    return {
      status: 'MALICIOUS',
      detail: `${malicious} of ${total} VirusTotal engines flag this as malicious.`,
      categories: ['malware'],
    };
  }
  if (suspicious > 0) {
    return {
      status: 'SUSPICIOUS',
      detail: `${suspicious} of ${total} VirusTotal engines flag this as suspicious.`,
      categories: ['suspicious'],
    };
  }
  if (total === 0) {
    return { status: 'UNKNOWN', detail: 'VirusTotal has no engine results for this item yet.' };
  }
  return {
    status: 'SAFE',
    detail: `No VirusTotal engine flagged this (${harmless} harmless, ${undetected} undetected).`,
  };
}

export class VirusTotalProvider implements UrlReputationProvider, HashReputationProvider {
  readonly id = 'virustotal';
  readonly label = 'VirusTotal';

  constructor(private readonly deps: ProviderDeps) {}

  isConfigured(): boolean {
    return this.deps.env.INTEL_ENABLED && Boolean(this.deps.env.VIRUSTOTAL_API_KEY);
  }

  private headers(): Record<string, string> {
    return { 'x-apikey': this.deps.env.VIRUSTOTAL_API_KEY ?? '' };
  }

  async query(input: UrlQuery): Promise<SourceResult> {
    const started = Date.now();
    if (!this.deps.env.INTEL_ENABLED) return disabledResult(this.id, 'Threat intelligence disabled');
    if (!this.deps.env.VIRUSTOTAL_API_KEY) return disabledResult(this.id, 'VirusTotal API key not configured');

    const id = Buffer.from(input.canonical, 'utf8').toString('base64url');
    return this.lookup(`https://www.virustotal.com/api/v3/urls/${id}`, 'URL', started);
  }

  async queryHash(input: HashQuery): Promise<SourceResult> {
    const started = Date.now();
    if (!this.deps.env.INTEL_ENABLED) return disabledResult(this.id, 'Threat intelligence disabled');
    if (!this.deps.env.VIRUSTOTAL_API_KEY) return disabledResult(this.id, 'VirusTotal API key not configured');

    const sha256 = input.sha256.toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      return {
        source: this.id,
        status: 'UNKNOWN',
        reasons: [],
        detail: 'A SHA-256 hash is required for a file reputation lookup.',
        durationMs: Date.now() - started,
      };
    }
    return this.lookup(`https://www.virustotal.com/api/v3/files/${sha256}`, 'file', started);
  }

  private async lookup(endpoint: string, kind: 'URL' | 'file', started: number): Promise<SourceResult> {
    try {
      const response = await fetchJson<VtAnalysisResponse>(endpoint, {
        provider: this.label,
        timeoutMs: this.deps.timeoutMs,
        minIntervalMs: this.deps.env.INTEL_MIN_REQUEST_INTERVAL_MS,
        headers: this.headers(),
        fetchImpl: this.deps.fetchImpl,
      });

      if (response.status === 404) {
        return {
          source: this.id,
          status: 'UNKNOWN',
          reasons: [],
          detail: `VirusTotal has no report for this ${kind} yet.`,
          durationMs: Date.now() - started,
        };
      }
      if (!response.ok) {
        return {
          source: this.id,
          status: 'UNKNOWN',
          reasons: [],
          detail: `VirusTotal returned HTTP ${response.status}`,
          error: `upstream status ${response.status}`,
          durationMs: Date.now() - started,
        };
      }

      const attributes = response.data?.data?.attributes;
      const verdict = classify(attributes?.last_analysis_stats);
      const reasons: SourceResult['reasons'] =
        verdict.status === 'MALICIOUS' || verdict.status === 'SUSPICIOUS'
          ? [
              {
                code: 'virustotal-detections',
                message: verdict.detail,
                weight: verdict.status === 'MALICIOUS' ? 100 : 55,
                severity: verdict.status === 'MALICIOUS' ? 'critical' : 'high',
              },
            ]
          : [];

      return {
        source: this.id,
        status: verdict.status,
        categories: verdict.categories,
        reasons,
        detail: verdict.detail,
        durationMs: Date.now() - started,
      };
    } catch (error) {
      return {
        source: this.id,
        status: 'UNKNOWN',
        reasons: [],
        detail: 'VirusTotal could not be reached.',
        error: error instanceof UpstreamError ? error.message : 'unexpected provider error',
        durationMs: Date.now() - started,
      };
    }
  }
}
