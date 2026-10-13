import type { Env } from './config/env';
import { getEnv, resolveDatabaseTarget, isProduction } from './config/env';
import { createDatabase } from './database/index';
import type { Database } from './database/adapter';
import { ScanRepository } from './database/repositories/scan-repository';
import { AlertRepository } from './database/repositories/alert-repository';
import { SettingsRepository } from './database/repositories/settings-repository';
import { SignatureRepository } from './database/repositories/signature-repository';
import { ReputationCacheRepository } from './database/repositories/reputation-cache-repository';
import { createIntelRegistry, type CreateRegistryOptions, type IntelRegistry } from './providers';
import { UrlReputationService } from './services/url-reputation.service';
import { FileAnalysisService } from './services/file-analysis.service';
import { NotificationAnalysisService } from './services/notification-analysis.service';
import { ScanHistoryService } from './services/scan-history.service';
import { getLogger } from './utils/logger';

/**
 * Composition root. Everything is constructed here and injected downwards, so
 * tests can substitute an in-memory database or a stubbed intel registry
 * without touching the application code.
 */

export interface Repositories {
  scans: ScanRepository;
  alerts: AlertRepository;
  settings: SettingsRepository;
  signatures: SignatureRepository;
  reputationCache: ReputationCacheRepository;
}

export interface Services {
  urlReputation: UrlReputationService;
  fileAnalysis: FileAnalysisService;
  notificationAnalysis: NotificationAnalysisService;
  scanHistory: ScanHistoryService;
}

export interface Container {
  env: Env;
  db: Database;
  repositories: Repositories;
  intel: IntelRegistry;
  services: Services;
  /** True when the container created (and therefore owns) the database. */
  ownsDatabase: boolean;
}

export interface CreateContainerOptions {
  env?: Env;
  /** Provide a database (tests pass an in-memory one). Otherwise one is built. */
  database?: Database;
  /** Extra options for the intel registry (e.g. a fake fetch in tests). */
  intel?: Partial<CreateRegistryOptions>;
  /** Close the database on dispose. Defaults to true when we created it. */
  ownsDatabase?: boolean;
}

const logger = getLogger();

export async function createContainer(options: CreateContainerOptions = {}): Promise<Container> {
  const env = options.env ?? getEnv();

  const ownsDatabase = options.ownsDatabase ?? options.database === undefined;
  const db = options.database ?? (await createDatabase(env));

  const repositories: Repositories = {
    scans: new ScanRepository(db),
    alerts: new AlertRepository(db),
    settings: new SettingsRepository(db),
    signatures: new SignatureRepository(db),
    reputationCache: new ReputationCacheRepository(db),
  };

  if (options.intel?.seedTestSignatures === undefined) {
    // Seed the built-in, harmless test signatures outside production so the
    // signature path is exercisable end-to-end during development.
    options.intel = { ...options.intel, seedTestSignatures: !isProduction(env) };
  }

  const intel = createIntelRegistry({
    env,
    timeoutMs: env.INTEL_TIMEOUT_MS,
    ...options.intel,
  });

  const urlReputation = new UrlReputationService({
    registry: intel,
    cacheRepository: repositories.reputationCache,
  });

  const services: Services = {
    urlReputation,
    fileAnalysis: new FileAnalysisService(intel),
    notificationAnalysis: new NotificationAnalysisService(urlReputation),
    scanHistory: new ScanHistoryService(repositories.scans, repositories.alerts),
  };

  return {
    env,
    db,
    repositories,
    intel,
    services,
    ownsDatabase,
  };
}

export async function disposeContainer(container: Container): Promise<void> {
  if (!container.ownsDatabase) return;
  try {
    await container.db.close();
  } catch (error) {
    logger.warn({ err: error }, 'error closing database');
  }
}

/** Description of the configured threat-intelligence providers (no secrets). */
export function describeProviders(container: Container): Array<{ id: string; configured: boolean }> {
  const providers = [...container.intel.urlProviders];
  const seen = new Set<string>();
  const out: Array<{ id: string; configured: boolean }> = [];
  for (const provider of providers) {
    if (seen.has(provider.id)) continue;
    seen.add(provider.id);
    out.push({ id: provider.id, configured: provider.isConfigured() });
  }
  return out;
}

export { resolveDatabaseTarget };
