import { readEnv, type Env } from '../src/config/env';

/** Build a validated Env for tests without touching the real process env. */
export function testEnv(overrides: Record<string, string> = {}): Env {
  return readEnv({ NODE_ENV: 'test', ...overrides } as NodeJS.ProcessEnv);
}

/** A minimal `fetch` replacement returning a JSON body. */
export function jsonFetch(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status: init.status ?? 200,
      headers: { 'content-type': 'application/json', ...(init.headers ?? {}) },
    });
}

/** A `fetch` that records the calls it received. */
export function recordingFetch(
  body: unknown,
  init: { status?: number } = {},
): { fetchImpl: typeof fetch; calls: Array<{ url: string; init?: RequestInit }> } {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (input, requestInit) => {
    calls.push({ url: String(input), init: requestInit });
    return new Response(JSON.stringify(body), {
      status: init.status ?? 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetchImpl, calls };
}

/** A `fetch` that never resolves until aborted (for timeout tests). */
export const hangingFetch: typeof fetch = (_input, init) =>
  new Promise((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => {
      reject(new DOMException('Aborted', 'AbortError'));
    });
  });

/** A `fetch` that fails the first `failures` calls, then succeeds. */
export function flakyFetch(
  body: unknown,
  failures: number,
): { fetchImpl: typeof fetch; attempts: () => number } {
  let seen = 0;
  const fetchImpl: typeof fetch = async () => {
    seen += 1;
    if (seen <= failures) throw new TypeError('network down');
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetchImpl, attempts: () => seen };
}
