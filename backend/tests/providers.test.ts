import { GoogleSafeBrowsingProvider } from '../src/providers/google-safe-browsing.provider';
import { UrlhausProvider } from '../src/providers/urlhaus.provider';
import { VirusTotalProvider } from '../src/providers/virustotal.provider';
import {
  InMemorySignatureStore,
  LocalSignatureProvider,
  TEST_SIGNATURES,
} from '../src/providers/local-signature.provider';
import { createIntelRegistry, queryUrlProviders } from '../src/providers/index';
import { jsonFetch, recordingFetch, testEnv } from './helpers';

const query = { url: 'http://evil.example/x', canonical: 'http://evil.example/x' };

describe('GoogleSafeBrowsingProvider', () => {
  it('reports SAFE when no threat matches are returned', async () => {
    const provider = new GoogleSafeBrowsingProvider({
      env: testEnv({ GOOGLE_SAFE_BROWSING_API_KEY: 'test-key' }),
      timeoutMs: 1000,
      fetchImpl: jsonFetch({}),
    });
    const result = await provider.query(query);
    expect(result.status).toBe('SAFE');
    expect(result.source).toBe('google-safe-browsing');
  });

  it('reports MALICIOUS and maps the threat type to a category', async () => {
    const { fetchImpl, calls } = recordingFetch({
      matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM' }],
    });
    const provider = new GoogleSafeBrowsingProvider({
      env: testEnv({ GOOGLE_SAFE_BROWSING_API_KEY: 'test-key' }),
      timeoutMs: 1000,
      fetchImpl,
    });
    const result = await provider.query(query);
    expect(result.status).toBe('MALICIOUS');
    expect(result.categories).toContain('phishing');
    // The API key must be sent to Google but never as part of the verdict.
    expect(calls[0]?.url).toContain('key=test-key');
    expect(JSON.stringify(result)).not.toContain('test-key');
  });

  it('is disabled without a key, and stays UNKNOWN', async () => {
    const provider = new GoogleSafeBrowsingProvider({ env: testEnv(), timeoutMs: 1000 });
    expect(provider.isConfigured()).toBe(false);
    const result = await provider.query(query);
    expect(result.status).toBe('UNKNOWN');
  });

  it('degrades gracefully on an upstream error', async () => {
    const provider = new GoogleSafeBrowsingProvider({
      env: testEnv({ GOOGLE_SAFE_BROWSING_API_KEY: 'test-key' }),
      timeoutMs: 1000,
      fetchImpl: jsonFetch({ error: 'boom' }, { status: 500 }),
    });
    const result = await provider.query(query);
    expect(result.status).toBe('UNKNOWN');
    expect(result.error).toBeDefined();
  });
});

describe('UrlhausProvider', () => {
  const env = testEnv({ URLHAUS_AUTH_KEY: 'auth' });

  it('reports SAFE for no_results', async () => {
    const provider = new UrlhausProvider({
      env,
      timeoutMs: 1000,
      fetchImpl: jsonFetch({ query_status: 'no_results' }),
    });
    expect((await provider.query(query)).status).toBe('SAFE');
  });

  it('reports MALICIOUS for a listed URL and detects phishing tags', async () => {
    const provider = new UrlhausProvider({
      env,
      timeoutMs: 1000,
      fetchImpl: jsonFetch({
        query_status: 'ok',
        threat: 'phishing',
        url_status: 'online',
        tags: ['phishing'],
      }),
    });
    const result = await provider.query(query);
    expect(result.status).toBe('MALICIOUS');
    expect(result.categories).toContain('phishing');
  });

  it('sends the Auth-Key header on requests', async () => {
    const { fetchImpl, calls } = recordingFetch({ query_status: 'no_results' });
    const provider = new UrlhausProvider({ env, timeoutMs: 1000, fetchImpl });
    await provider.query(query);
    const headers = calls[0]?.init?.headers as Record<string, string> | undefined;
    expect(headers?.['Auth-Key']).toBe('auth');
  });
});

describe('VirusTotalProvider', () => {
  const env = testEnv({ VIRUSTOTAL_API_KEY: 'vt' });

  it('reports UNKNOWN (never SAFE) on a 404', async () => {
    const provider = new VirusTotalProvider({
      env,
      timeoutMs: 1000,
      fetchImpl: jsonFetch({ error: { code: 'NotFoundError' } }, { status: 404 }),
    });
    const result = await provider.query(query);
    expect(result.status).toBe('UNKNOWN');
  });

  it('reports MALICIOUS when engines flag the URL', async () => {
    const provider = new VirusTotalProvider({
      env,
      timeoutMs: 1000,
      fetchImpl: jsonFetch({
        data: { attributes: { last_analysis_stats: { malicious: 12, suspicious: 1, harmless: 60, undetected: 5 } } },
      }),
    });
    expect((await provider.query(query)).status).toBe('MALICIOUS');
  });

  it('reports SAFE when no engine flags it', async () => {
    const provider = new VirusTotalProvider({
      env,
      timeoutMs: 1000,
      fetchImpl: jsonFetch({
        data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 2 } } },
      }),
    });
    expect((await provider.query(query)).status).toBe('SAFE');
  });

  it('rejects a malformed hash', async () => {
    const provider = new VirusTotalProvider({ env, timeoutMs: 1000, fetchImpl: jsonFetch({}) });
    const result = await provider.queryHash({ sha256: 'not-a-hash' });
    expect(result.status).toBe('UNKNOWN');
  });
});

describe('LocalSignatureProvider', () => {
  it('flags a known-bad URL as MALICIOUS and leaves misses UNKNOWN', async () => {
    const store = new InMemorySignatureStore(TEST_SIGNATURES);
    const provider = new LocalSignatureProvider(store);
    const hit = await provider.query({ url: TEST_SIGNATURES.urls[0], canonical: TEST_SIGNATURES.urls[0] });
    expect(hit.status).toBe('MALICIOUS');
    const miss = await provider.query({ url: 'https://example.com', canonical: 'https://example.com' });
    expect(miss.status).toBe('UNKNOWN');
  });

  it('flags a known-bad hash as MALICIOUS', async () => {
    const store = new InMemorySignatureStore(TEST_SIGNATURES);
    const provider = new LocalSignatureProvider(store);
    const hit = await provider.queryHash({ sha256: TEST_SIGNATURES.hashes[0] });
    expect(hit.status).toBe('MALICIOUS');
  });
});

describe('createIntelRegistry + queryUrlProviders', () => {
  it('aggregates provider results without throwing', async () => {
    const registry = createIntelRegistry({
      env: testEnv({ GOOGLE_SAFE_BROWSING_API_KEY: 'k' }),
      timeoutMs: 1000,
      fetchImpl: jsonFetch({}),
      seedTestSignatures: true,
    });
    const summary = await queryUrlProviders(registry, {
      url: 'http://paypal.com.secure-login.tk/verify',
      canonical: 'http://paypal.com.secure-login.tk/verify',
    });
    // local-signature, safe-browsing, urlhaus (disabled), virustotal (disabled)
    expect(summary.results).toHaveLength(4);
    expect(summary.results.map((r) => r.source)).toEqual(
      expect.arrayContaining(['local-signature', 'google-safe-browsing', 'urlhaus', 'virustotal']),
    );
  });

  it('turns a throwing provider into an UNKNOWN result', async () => {
    const registry = createIntelRegistry({ env: testEnv(), timeoutMs: 1000 });
    registry.urlProviders = [
      {
        id: 'virustotal',
        label: 'Exploding provider',
        isConfigured: () => true,
        query: async () => {
          throw new Error('kaboom');
        },
      },
    ];
    const summary = await queryUrlProviders(registry, query);
    expect(summary.results[0]?.status).toBe('UNKNOWN');
    expect(summary.results[0]?.error).toContain('kaboom');
  });
});
