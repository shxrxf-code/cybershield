import type { SourceResult } from '../domain/verdict';
import type {
  HashQuery,
  HashReputationProvider,
  ProviderDeps,
  UrlQuery,
  UrlReputationProvider,
} from './types';
import { GoogleSafeBrowsingProvider } from './google-safe-browsing.provider';
import { UrlhausProvider } from './urlhaus.provider';
import { VirusTotalProvider } from './virustotal.provider';
import { InMemorySignatureStore, LocalSignatureProvider, TEST_SIGNATURES, type SignatureStore } from './local-signature.provider';

export * from './types';
export { GoogleSafeBrowsingProvider } from './google-safe-browsing.provider';
export { UrlhausProvider } from './urlhaus.provider';
export { VirusTotalProvider } from './virustotal.provider';
export {
  InMemorySignatureStore,
  LocalSignatureProvider,
  TEST_SIGNATURES,
  type SignatureStore,
} from './local-signature.provider';

export interface IntelRegistry {
  urlProviders: UrlReputationProvider[];
  hashProviders: HashReputationProvider[];
  signatureStore: SignatureStore;
}

export interface CreateRegistryOptions extends ProviderDeps {
  signatureStore?: SignatureStore;
  /** Include the built-in test signatures (development / tests only). */
  seedTestSignatures?: boolean;
}

export function createIntelRegistry(options: CreateRegistryOptions): IntelRegistry {
  const signatureStore =
    options.signatureStore ??
    new InMemorySignatureStore(options.seedTestSignatures ? TEST_SIGNATURES : undefined);

  const google = new GoogleSafeBrowsingProvider(options);
  const urlhaus = new UrlhausProvider(options);
  const virusTotal = new VirusTotalProvider(options);
  const local = new LocalSignatureProvider(signatureStore, options);

  return {
    urlProviders: [local, google, urlhaus, virusTotal],
    hashProviders: [local, virusTotal],
    signatureStore,
  };
}

export interface QuerySummary {
  results: SourceResult[];
  /** Number of providers that were configured and consulted. */
  consulted: number;
  /** Number of providers that returned a definitive (non-UNKNOWN) answer. */
  answered: number;
}

async function runAll<TProvider extends { id: string; label: string }, TInput>(
  providers: TProvider[],
  input: TInput,
  invoke: (provider: TProvider, input: TInput) => Promise<SourceResult>,
  sourceFromId: (id: string) => SourceResult['source'],
): Promise<QuerySummary> {
  const results = await Promise.all(
    providers.map(async (provider) => {
      try {
        return await invoke(provider, input);
      } catch (error) {
        // Defence in depth: a provider must not take down the request.
        return {
          source: sourceFromId(provider.id),
          status: 'UNKNOWN',
          reasons: [],
          detail: `${provider.label} failed unexpectedly.`,
          error: error instanceof Error ? error.message : 'unknown provider error',
        } satisfies SourceResult;
      }
    }),
  );

  return {
    results,
    consulted: results.length,
    answered: results.filter((result) => result.status !== 'UNKNOWN').length,
  };
}

const URL_SOURCE_IDS: Record<string, SourceResult['source']> = {
  'google-safe-browsing': 'google-safe-browsing',
  urlhaus: 'urlhaus',
  virustotal: 'virustotal',
  'local-signature': 'local-signature',
};

const HASH_SOURCE_IDS: Record<string, SourceResult['source']> = {
  virustotal: 'virustotal',
  'local-signature': 'local-signature',
};

export async function queryUrlProviders(
  registry: IntelRegistry,
  input: UrlQuery,
): Promise<QuerySummary> {
  return runAll(
    registry.urlProviders,
    input,
    (provider, query) => provider.query(query),
    (id) => URL_SOURCE_IDS[id] ?? 'local-url-heuristics',
  );
}

export async function queryHashProviders(
  registry: IntelRegistry,
  input: HashQuery,
): Promise<QuerySummary> {
  return runAll(
    registry.hashProviders,
    input,
    (provider, query) => provider.queryHash(query),
    (id) => HASH_SOURCE_IDS[id] ?? 'local-signature',
  );
}
