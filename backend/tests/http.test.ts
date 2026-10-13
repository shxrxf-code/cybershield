import { fetchJson, resetRateLimitClock } from '../src/utils/http';
import { UpstreamError } from '../src/utils/errors';
import { flakyFetch, hangingFetch } from './helpers';

const noSleep = async () => undefined;

beforeEach(() => resetRateLimitClock());

describe('fetchJson', () => {
  it('parses a JSON body', async () => {
    const response = await fetchJson<{ hello: string }>('http://example.test/api', {
      timeoutMs: 500,
      provider: 'test',
      fetchImpl: async () =>
        new Response(JSON.stringify({ hello: 'world' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    });
    expect(response.ok).toBe(true);
    expect(response.data?.hello).toBe('world');
  });

  it('raises a timeout UpstreamError when the request hangs', async () => {
    await expect(
      fetchJson('http://example.test/slow', {
        timeoutMs: 20,
        retries: 0,
        provider: 'sleeper',
        fetchImpl: hangingFetch,
        sleep: noSleep,
      }),
    ).rejects.toMatchObject({ code: 'UPSTREAM_TIMEOUT', provider: 'sleeper' });
  });

  it('retries a transient network failure and then succeeds', async () => {
    const { fetchImpl, attempts } = flakyFetch({ ok: true }, 1);
    const response = await fetchJson('http://example.test/flaky', {
      timeoutMs: 500,
      retries: 1,
      provider: 'flaky',
      fetchImpl,
      sleep: noSleep,
      backoffMs: 1,
    });
    expect(response.ok).toBe(true);
    expect(attempts()).toBe(2);
  });

  it('retries a 429 too', async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      if (calls === 1) return new Response('', { status: 429 });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };
    const response = await fetchJson('http://example.test/limited', {
      timeoutMs: 500,
      retries: 1,
      provider: 'limited',
      fetchImpl,
      sleep: noSleep,
      backoffMs: 1,
    });
    expect(response.ok).toBe(true);
    expect(calls).toBe(2);
  });

  it('does not retry a terminal 4xx', async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      return new Response('', { status: 400 });
    };
    const response = await fetchJson('http://example.test/bad', {
      timeoutMs: 500,
      retries: 2,
      provider: 'bad',
      fetchImpl,
      sleep: noSleep,
      backoffMs: 1,
    });
    expect(response.ok).toBe(false);
    expect(response.status).toBe(400);
    expect(calls).toBe(1);
  });

  it('raises on malformed JSON instead of returning partial data', async () => {
    await expect(
      fetchJson('http://example.test/broken', {
        timeoutMs: 500,
        retries: 0,
        provider: 'broken',
        fetchImpl: async () => new Response('{not json', { status: 200 }),
        sleep: noSleep,
      }),
    ).rejects.toBeInstanceOf(UpstreamError);
  });

  it('refuses an unparseable URL', async () => {
    await expect(
      fetchJson('not a url', { timeoutMs: 100, provider: 'nope', sleep: noSleep }),
    ).rejects.toBeInstanceOf(UpstreamError);
  });
});
