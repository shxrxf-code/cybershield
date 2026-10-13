import { existsSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

/**
 * Environment configuration.
 *
 * Settings are environment-only (12-factor): nothing is hard-coded, and every
 * value has a safe development default. `.env` is loaded with Node's native
 * loader (no `dotenv` dependency) when the file exists.
 */

const booleanish = z.union([z.boolean(), z.string()]).transform((value) => {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
});

const commaList = z
  .string()
  .optional()
  .transform((value) =>
    (value ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0),
  );

const optionalString = z
  .string()
  .optional()
  .transform((value) => {
    const trimmed = (value ?? '').trim();
    return trimmed.length > 0 ? trimmed : undefined;
  });

/**
 * Express `trust proxy` value. Accepts nothing (direct exposure), `true`,
 * or an Express shorthand string such as `loopback` / `uniquel` when the
 * server really sits behind a reverse proxy.
 */
const trustProxyValue = z
  .union([booleanish, z.string()])
  .optional()
  .transform((value) => {
    if (value === undefined) return undefined;
    if (typeof value === 'boolean') return value;
    const trimmed = value.trim().toLowerCase();
    if (trimmed.length === 0 || trimmed === 'false') return false;
    if (trimmed === 'true') return true;
    return trimmed;
  });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(8000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

  /** Set ONLY when this server is behind a known reverse proxy. */
  TRUST_PROXY: trustProxyValue,

  DATABASE_URL: z.string().default('file:./data/threatguard.sqlite'),
  DB_CLIENT: z.enum(['sqlite', 'postgres']).optional(),

  API_KEY_HASHES: commaList,

  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(120),

  GOOGLE_SAFE_BROWSING_API_KEY: optionalString,
  URLHAUS_AUTH_KEY: optionalString,
  VIRUSTOTAL_API_KEY: optionalString,

  INTEL_ENABLED: booleanish.default(true),
  INTEL_TIMEOUT_MS: z.coerce.number().int().positive().default(6_000),
  INTEL_CACHE_TTL_SECONDS: z.coerce.number().int().positive().default(21_600),
  INTEL_MIN_REQUEST_INTERVAL_MS: z.coerce.number().int().min(0).default(0),

  CORS_ALLOWED_ORIGINS: commaList,
});

export type Env = z.infer<typeof envSchema>;

export interface DatabaseTarget {
  client: 'sqlite' | 'postgres';
  /** File path for sqlite (without the `file:` scheme) or the raw URL for postgres. */
  location: string;
}

function loadDotEnv(): void {
  if (process.env.NODE_ENV === 'test') return;
  if (String(process.env.SKIP_DOTENV ?? '') === 'true') return;
  const candidates = [path.resolve(process.cwd(), '.env'), path.resolve(process.cwd(), '../.env')];
  const found = candidates.find((file) => existsSync(file));
  if (!found) return;
  try {
    // Available on Node >= 21.7. Does not override already-set variables.
    process.loadEnvFile(found);
  } catch {
    /* ignore malformed .env – the schema below will report real problems */
  }
}

let cached: Env | undefined;

/** Parse and validate the environment. Throws a readable error on failure. */
export function readEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  return result.data;
}

/** Memoised accessor used by the application at runtime. */
export function getEnv(): Env {
  if (cached) return cached;
  loadDotEnv();
  cached = readEnv(process.env);
  return cached;
}

/** Test helper – drops the memoised environment. */
export function resetEnvCache(): void {
  cached = undefined;
}

/** Derive the concrete database target from DATABASE_URL / DB_CLIENT. */
export function resolveDatabaseTarget(env: Env): DatabaseTarget {
  const raw = env.DATABASE_URL;
  if (env.DB_CLIENT === 'sqlite') {
    return { client: 'sqlite', location: raw.replace(/^file:/, '') };
  }
  if (env.DB_CLIENT === 'postgres') {
    return { client: 'postgres', location: raw };
  }
  if (raw.startsWith('file:')) {
    return { client: 'sqlite', location: raw.replace(/^file:/, '') };
  }
  if (raw.startsWith('postgres://') || raw.startsWith('postgresql://')) {
    return { client: 'postgres', location: raw };
  }
  throw new Error(
    `Cannot infer database client from DATABASE_URL="${raw}". ` +
      `Set DB_CLIENT to "sqlite" or "postgres".`,
  );
}

export function isProduction(env: Env): boolean {
  return env.NODE_ENV === 'production';
}

export function isTest(env: Env): boolean {
  return env.NODE_ENV === 'test';
}
