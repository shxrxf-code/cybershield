import type { SourceResult } from '../domain/verdict';
import type { HashQuery, HashReputationProvider, ProviderDeps, UrlQuery, UrlReputationProvider } from './types';

/**
 * Local signature store.
 *
 * This backs the "local threat signatures" requirement: a small, curated set
 * of known-bad URLs and SHA-256 hashes that ships with the backend and can be
 * extended from the `threat_signatures` table. A *hit* is authoritative
 * (MALICIOUS); a *miss* is UNKNOWN, because our list is deliberately tiny and
 * absence from it proves nothing.
 */

export interface SignatureStore {
  hasUrl(canonicalUrl: string): boolean;
  hasHash(sha256: string): boolean;
}

export class InMemorySignatureStore implements SignatureStore {
  private readonly urls: Set<string>;
  private readonly hashes: Set<string>;

  constructor(seed: { urls?: readonly string[]; hashes?: readonly string[] } = {}) {
    this.urls = new Set((seed.urls ?? []).map((url) => url.trim().toLowerCase()));
    this.hashes = new Set((seed.hashes ?? []).map((hash) => hash.trim().toLowerCase()));
  }

  addUrl(canonicalUrl: string): void {
    this.urls.add(canonicalUrl.trim().toLowerCase());
  }

  addHash(sha256: string): void {
    this.hashes.add(sha256.trim().toLowerCase());
  }

  hasUrl(canonicalUrl: string): boolean {
    const normalized = canonicalUrl.trim().toLowerCase();
    if (this.urls.has(normalized)) return true;
    // Also match the bare origin so `evil.example/x` matches `evil.example`.
    try {
      const url = new URL(normalized);
      return this.urls.has(`${url.protocol}//${url.host}`);
    } catch {
      return false;
    }
  }

  hasHash(sha256: string): boolean {
    return this.hashes.has(sha256.trim().toLowerCase());
  }

  get size(): { urls: number; hashes: number } {
    return { urls: this.urls.size, hashes: this.hashes.size };
  }
}

/**
 * Well-known, safe test fixtures and documentation examples. These are NOT
 * malware: they exist so the signature path can be exercised end-to-end on a
 * development machine without ever handling real samples.
 */
export const TEST_SIGNATURES = {
  urls: [
    'http://malware.wicar.org/data/ms14_064_ole_not_xp.doc',
    'http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/',
  ],
  hashes: [
    // SHA-256 of the EICAR anti-malware test string ("eicar-file" fixture).
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  ],
} as const;

export class LocalSignatureProvider implements UrlReputationProvider, HashReputationProvider {
  readonly id = 'local-signature';
  readonly label = 'Local threat signatures';

  constructor(
    private readonly store: SignatureStore,
    _deps?: ProviderDeps,
  ) {}

  isConfigured(): boolean {
    return true;
  }

  async query(input: UrlQuery): Promise<SourceResult> {
    const started = Date.now();
    if (this.store.hasUrl(input.canonical) || this.store.hasUrl(input.url)) {
      return {
        source: this.id,
        status: 'MALICIOUS',
        categories: ['malware'],
        reasons: [
          {
            code: 'local-signature-url',
            message: 'This address matches a signature in the local threat database.',
            weight: 100,
            severity: 'critical',
          },
        ],
        detail: 'Matched a known-bad URL signature stored locally.',
        durationMs: Date.now() - started,
      };
    }
    return {
      source: this.id,
      status: 'UNKNOWN',
      reasons: [],
      detail: 'No match in the local signature database (this is not a guarantee of safety).',
      durationMs: Date.now() - started,
    };
  }

  async queryHash(input: HashQuery): Promise<SourceResult> {
    const started = Date.now();
    if (this.store.hasHash(input.sha256)) {
      return {
        source: this.id,
        status: 'MALICIOUS',
        categories: ['malware'],
        reasons: [
          {
            code: 'local-signature-hash',
            message: 'This file’s fingerprint matches a signature in the local threat database.',
            weight: 100,
            severity: 'critical',
          },
        ],
        detail: 'Matched a known-bad file hash stored locally.',
        durationMs: Date.now() - started,
      };
    }
    return {
      source: this.id,
      status: 'UNKNOWN',
      reasons: [],
      detail: 'No match in the local signature database (this is not a guarantee of safety).',
      durationMs: Date.now() - started,
    };
  }
}
