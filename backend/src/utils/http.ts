import { UpstreamError } from './errors';

/**
 * HTTP client for outbound threat-intelligence calls.
 *
 * Requirements it satisfies:
 *   * hard timeout per request (AbortController),
 *   * bounded retries with exponential backoff + jitter on transient failures,
 *   * no retry on 4xx (except 429, which we back off on),
 *   * never throws a raw `fetch` error – always an `UpstreamError`,
 *   * a minimum spacing between requests to the same origin (politeness /
 *     quota protection), tunable via INTEL_MIN_REQUEST_INTERVAL_MS.
 */

export interface FetchJsonOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  /** JSON body (serialised automatically). */
  body?: unknown;
  /** application/x-www-form-urlencoded body (mutually exclusive with `body`). */
  form?: Record<string, string>;
  timeoutMs: number;
  /** Number of *additional* attempts after the first. */
  retries?: number;
  /** Base backoff in ms (doubled per attempt, with jitter). */
  backoffMs?: number;
  provider: string;
  /** Minimum spacing to the same origin in ms. */
  minIntervalMs?: number;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export interface JsonResponse<T> {
  status: number;
  ok: boolean;
  data: T | undefined;
  headers: Headers;
}

const lastRequestAt = new Map<string, number>();

export const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

function jitter(base: number): number {
  return base + Math.floor(Math.random() * Math.max(1, base / 2));
}

export async function fetchJson<T>(url: string, options: FetchJsonOptions): Promise<JsonResponse<T>> {
  const {
    method = 'GET',
    headers = {},
    body,
    form,
    timeoutMs,
    retries = 1,
    backoffMs = 250,
    provider,
    minIntervalMs = 0,
    fetchImpl = fetch,
    sleep = defaultSleep,
    now = Date.now,
  } = options;

  let origin = '';
  try {
    origin = new URL(url).origin;
  } catch {
    throw new UpstreamError(provider, `${provider}: invalid URL`, { cause: url });
  }

  const maxAttempts = retries + 1;
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (minIntervalMs > 0) {
      const previous = lastRequestAt.get(origin);
      if (previous !== undefined) {
        const wait = previous + minIntervalMs - now();
        if (wait > 0) await sleep(wait);
      }
      lastRequestAt.set(origin, now());
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, {
        method,
        headers: {
          accept: 'application/json',
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...(form !== undefined
            ? { 'content-type': 'application/x-www-form-urlencoded' }
            : {}),
          ...headers,
        },
        body:
          body !== undefined
            ? JSON.stringify(body)
            : form !== undefined
              ? new URLSearchParams(form).toString()
              : undefined,
        signal: controller.signal,
      });

      if (response.status === 429 || response.status >= 500) {
        lastError = new UpstreamError(provider, `${provider} responded ${response.status}`, {
          cause: response.status,
        });
        if (attempt < maxAttempts) {
          await sleep(jitter(backoffMs * 2 ** (attempt - 1)));
          continue;
        }
        return { status: response.status, ok: false, data: undefined, headers: response.headers };
      }

      // Any other 4xx is terminal: retrying will not help.
      if (!response.ok) {
        return { status: response.status, ok: false, data: undefined, headers: response.headers };
      }

      const text = await response.text();
      let data: T | undefined;
      if (text.length > 0) {
        try {
          data = JSON.parse(text) as T;
        } catch (parseError) {
          throw new UpstreamError(provider, `${provider} returned malformed JSON`, {
            cause: parseError,
          });
        }
      }
      return { status: response.status, ok: true, data, headers: response.headers };
    } catch (error) {
      if (error instanceof UpstreamError) {
        lastError = error;
        if (error.code === 'UPSTREAM_TIMEOUT' && attempt < maxAttempts) {
          await sleep(jitter(backoffMs * 2 ** (attempt - 1)));
          continue;
        }
        if (attempt < maxAttempts && error.code !== 'UPSTREAM_TIMEOUT') {
          await sleep(jitter(backoffMs * 2 ** (attempt - 1)));
          continue;
        }
        throw error;
      }
      const aborted = controller.signal.aborted;
      lastError = new UpstreamError(
        provider,
        aborted ? `${provider} request timed out after ${timeoutMs}ms` : `${provider} request failed`,
        { timeout: aborted, cause: error },
      );
      if (attempt < maxAttempts) {
        await sleep(jitter(backoffMs * 2 ** (attempt - 1)));
        continue;
      }
    } finally {
      clearTimeout(timer);
    }
  }

  if (lastError instanceof UpstreamError) throw lastError;
  throw new UpstreamError(provider, `${provider} request failed`, { cause: lastError });
}

/** Test-only: reset the politeness clock between cases. */
export function resetRateLimitClock(): void {
  lastRequestAt.clear();
}
