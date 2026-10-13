import request from 'supertest';
import type { Express } from 'express';
import { createApp } from '../src/app';
import { createContainer, type Container } from '../src/container';
import { createTestDatabase } from '../src/database';
import { sha256Hex } from '../src/utils/hash';
import { testEnv } from './helpers';
import { resetRateLimitClock } from '../src/utils/http';

/** SHA-256 of the EICAR anti-malware test string (seeded local signature). */
const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
/** URL seeded in the local signature store for end-to-end dev tests. */
const SIGNATURE_URL = 'http://malware.wicar.org/data/ms14_064_ole_not_xp.doc';

const API_KEY = 'test-key-2026';
const API_KEY_HASH = sha256Hex(API_KEY);

interface Fixture {
  container: Container;
  app: Express;
  close: () => Promise<void>;
}

/**
 * Build a real app on an in-memory database. The env defaults to "open
 * dev-mode" (no API_KEY_HASHES) unless overridden, exactly like a local dev
 * box. NODE_ENV=test also seeds the harmless test signatures.
 */
async function makeApp(overrides: Record<string, string> = {}): Promise<Fixture> {
  const db = await createTestDatabase();
  const env = testEnv(overrides);
  const container = await createContainer({ env, database: db });
  return {
    container,
    app: createApp(container),
    close: async () => {
      await db.close();
    },
  };
}

/** Brief sleep so alert dedupe timestamps cannot collide across tests. */
const tick = (ms = 5) => new Promise((resolve) => setTimeout(resolve, ms));

describe('Mobile ThreatGuard API (integration)', () => {
  // A single shared app per describe block so history/alert state is
  // exercised the way a real device would see it.
  let fx: Fixture;

  beforeAll(async () => {
    fx = await makeApp();
  });

  afterAll(async () => {
    await fx.close();
  });

  describe('GET /api/v1/health (public)', () => {
    it('reports ok with a live database and the configured providers', async () => {
      const res = await request(fx.app).get('/api/v1/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.database).toMatchObject({ client: 'sqlite', ok: true });
      expect(typeof res.body.uptime_seconds).toBe('number');
      expect(res.body.providers).toEqual(
        expect.arrayContaining([expect.objectContaining({ id: 'local-signature', configured: true })]),
      );
    });

    it('is reachable without any API key', async () => {
      const res = await request(fx.app).get('/api/v1/health').set('x-api-key', 'not-a-real-key');
      expect(res.status).toBe(200);
    });
  });

  describe('API key enforcement', () => {
    it('rejects protected routes with a missing key when hashes are configured', async () => {
      const locked = await makeApp({ API_KEY_HASHES: API_KEY_HASH });
      try {
        const res = await request(locked.app).get('/api/v1/preferences');
        expect(res.status).toBe(401);
        expect(res.body.error.code).toBe('UNAUTHORIZED');
      } finally {
        await locked.close();
      }
    });

    it('rejects bad keys with 401', async () => {
      const locked = await makeApp({ API_KEY_HASHES: API_KEY_HASH });
      try {
        const res = await request(locked.app)
          .get('/api/v1/preferences')
          .set('x-api-key', 'wrong-key');
        expect(res.status).toBe(401);
      } finally {
        await locked.close();
      }
    });

    it('accepts the correct key via the X-API-Key header', async () => {
      const locked = await makeApp({ API_KEY_HASHES: API_KEY_HASH });
      try {
        const res = await request(locked.app).get('/api/v1/preferences').set('x-api-key', API_KEY);
        expect(res.status).toBe(200);
      } finally {
        await locked.close();
      }
    });

    it('accepts the correct key via Authorization: Bearer', async () => {
      const locked = await makeApp({ API_KEY_HASHES: API_KEY_HASH });
      try {
        const res = await request(locked.app)
          .get('/api/v1/preferences')
          .set('authorization', `Bearer ${API_KEY}`);
        expect(res.status).toBe(200);
      } finally {
        await locked.close();
      }
    });

    it('exposes a correlation id in every error envelope and response header', async () => {
      const locked = await makeApp({ API_KEY_HASHES: API_KEY_HASH });
      try {
        const res = await request(locked.app).get('/api/v1/preferences');
        expect(res.status).toBe(401);
        expect(res.headers['x-request-id']).toBeTruthy();
        expect(res.body.error.correlation_id).toBe(res.headers['x-request-id']);
        expect(res.body.error).toHaveProperty('status_code', 401);
      } finally {
        await locked.close();
      }
    });
  });

  describe('validation', () => {
    it('returns a per-field detail list for a malformed body', async () => {
      const res = await request(fx.app).post('/api/v1/scans/url').send({});
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(res.body.error.details).toEqual(
        expect.arrayContaining([expect.objectContaining({ field: 'url' })]),
      );
    });

    it('rejects invalid JSON body with a readable message', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/url')
        .set('content-type', 'application/json')
        .send('{"broken');
      expect(res.status).toBe(400);
      expect(res.body.error.message).toBe('Request body is not valid JSON');
    });

    it('rejects a notification with empty text', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/notification')
        .send({ text: '   ' });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('rejects a file scan whose sha256 is not hex', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/file')
        .send({ sha256: 'not-a-hash' });
      expect(res.status).toBe(400);
      expect(res.body.error.details[0]?.field).toBe('sha256');
    });
  });

  describe('URL scans', () => {
    it('analyses a benign address as UNKNOWN (never SAFE without evidence)', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/url')
        .send({ url: 'https://example.com/' });
      expect(res.status).toBe(200);
      expect(res.body.url).toBe('https://example.com/');
      expect(res.body.domain).toBe('example.com');
      expect(res.body.verdict.status).toBe('UNKNOWN');
      expect(res.body.verdict.definitive).toBe(false);
      expect(res.body.verdict.recommended_action).toBeTruthy();
      expect(res.body.scan_id).toBeTruthy();
    });

    it('flags a URL that matches a local signature as MALICIOUS and creates an alert', async () => {
      const res = await request(fx.app).post('/api/v1/scans/url').send({ url: SIGNATURE_URL });
      expect(res.status).toBe(200);
      expect(res.body.verdict.status).toBe('MALICIOUS');
      expect(res.body.verdict.definitive).toBe(true);
      expect(res.body.verdict.category).toBe('malware');
      expect(res.body.alert).toMatchObject({ threat_type: 'malicious_url', severity: 'critical' });
      expect(res.body.duplicate_alert).toBe(false);
    });

    it('deduplicates repeated scans into a single alert', async () => {
      // A fresh target so the first scan in this test is not a duplicate of an
      // alert created by an earlier test in the same shared app.
      const fresh = 'http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/';
      const first = await request(fx.app).post('/api/v1/scans/url').send({ url: fresh });
      expect(first.body.duplicate_alert).toBe(false);
      expect(first.body.alert?.id).toBeTruthy();
      const second = await request(fx.app).post('/api/v1/scans/url').send({ url: fresh });
      expect(second.body.duplicate_alert).toBe(true);
      expect(second.body.alert?.id).toBe(first.body.alert?.id);
    });

    it('rejects a URL that cannot be parsed at all', async () => {
      const res = await request(fx.app).post('/api/v1/scans/url').send({ url: 'not a url' });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('analyses a batch and reports per-URL results', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/url/batch')
        .send({ urls: [SIGNATURE_URL, 'https://example.org/x'] });
      expect(res.status).toBe(200);
      expect(res.body.count).toBe(2);
      expect(res.body.results).toHaveLength(2);
      expect(res.body.results[0].verdict.status).toBe('MALICIOUS');
    });
  });

  describe('file scans', () => {
    it('flags the EICAR test hash as MALICIOUS malware', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/file')
        .send({ sha256: EICAR_SHA256, fileName: 'eicar.txt', extension: 'txt' });
      expect(res.status).toBe(200);
      expect(res.body.verdict.status).toBe('MALICIOUS');
      expect(res.body.verdict.category).toBe('malware');
      expect(res.body.alert?.severity).toBe('critical');
      expect(res.body.file_name).toBe('eicar.txt');
    });

    it('returns UNKNOWN for an unknown hash without ever claiming safety', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/file')
        .send({ sha256: 'a'.repeat(64) });
      expect(res.status).toBe(200);
      expect(res.body.verdict.status).toBe('UNKNOWN');
      expect(res.body.verdict.definitive).toBe(false);
    });
  });

  describe('notification scans', () => {
    it('flags a phishing message with urgency + credential lure', async () => {
      const res = await request(fx.app)
        .post('/api/v1/scans/notification')
        .send({
          text: 'URGENT: Your account will be blocked. Verify your account details now to avoid losing access. Click http://example.com/login',
          title: 'Security alert',
          sourceApp: 'SMS',
          packageName: 'com.android.mms',
        });
      expect(res.status).toBe(200);
      expect(res.body.verdict.status).toBe('SUSPICIOUS');
      expect(res.body.text_score).toBeGreaterThan(0);
      expect(res.body.matched_signals.length).toBeGreaterThanOrEqual(1);
      expect(res.body.urls[0]).toMatchObject({ domain: 'example.com', status: 'UNKNOWN' });
      expect(res.body.privacy_note).toContain('not stored');
    });
  });

  describe('scan history & dashboard', () => {
    it('lists records with pagination metadata', async () => {
      const res = await request(fx.app).get('/api/v1/scans?limit=5');
      expect(res.status).toBe(200);
      expect(res.body.items.length).toBeGreaterThanOrEqual(1);
      expect(res.body.total).toBeGreaterThanOrEqual(1);
      expect(res.body.limit).toBe(5);
      expect(res.body.items[0]).toHaveProperty('scan_type');
    });

    it('filters by scan type', async () => {
      const res = await request(fx.app).get('/api/v1/scans?scanType=url');
      expect(res.status).toBe(200);
      for (const item of res.body.items) {
        expect(item.scan_type).toBe('url');
      }
    });

    it('rejects pagination beyond the allowed ceiling', async () => {
      const res = await request(fx.app).get('/api/v1/scans?limit=9999');
      expect(res.status).toBe(400);
    });

    it('returns the dashboard aggregate from real data', async () => {
      const res = await request(fx.app).get('/api/v1/scans/dashboard');
      expect(res.status).toBe(200);
      expect(res.body.totals.total_scans).toBeGreaterThanOrEqual(1);
      expect(res.body.totals.total_threats).toBeGreaterThanOrEqual(1);
      expect(res.body.totals.alerts_by_severity.critical).toBeGreaterThanOrEqual(1);
      expect(res.body.recent_scans[0]).toHaveProperty('scanned_at');
      expect(res.body.recent_alerts).toEqual(expect.any(Array));
    });

    it('fetches a single scan by id and 404s for a missing one', async () => {
      await tick();
      const created = await request(fx.app).get('/api/v1/scans?limit=1');
      const id = created.body.items[0].id;
      const detail = await request(fx.app).get(`/api/v1/scans/${id}`);
      expect(detail.status).toBe(200);
      expect(detail.body.id).toBe(id);

      const missing = await request(fx.app).get('/api/v1/scans/00000000-0000-0000-0000-000000000000');
      expect(missing.status).toBe(404);
      expect(missing.body.error.code).toBe('NOT_FOUND');
    });

    it('clears history and reports the removed count', async () => {
      const cleared = await request(fx.app).delete('/api/v1/scans');
      expect(cleared.status).toBe(200);
      expect(typeof cleared.body.removed).toBe('number');
      const after = await request(fx.app).get('/api/v1/scans/dashboard');
      expect(after.body.totals.total_scans).toBe(0);
    });
  });

  describe('alerts', () => {
    let alertId: string;

    beforeAll(async () => {
      // Re-seed one alert so this block is independent of test order.
      await request(fx.app).post('/api/v1/scans/url').send({ url: SIGNATURE_URL });
      const list = await request(fx.app).get('/api/v1/alerts?limit=1');
      alertId = list.body.items[0].id;
    });

    it('lists alerts with unread counts', async () => {
      const res = await request(fx.app).get('/api/v1/alerts');
      expect(res.status).toBe(200);
      expect(res.body.items.length).toBeGreaterThanOrEqual(1);
      expect(typeof res.body.unread).toBe('number');
    });

    it('marks a single alert as read', async () => {
      const res = await request(fx.app).post(`/api/v1/alerts/${alertId}/read`);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ id: alertId, is_read: true });
    });

    it('marks a missing alert as 404', async () => {
      const res = await request(fx.app).post('/api/v1/alerts/00000000-0000-0000-0000-000000000000/read');
      expect(res.status).toBe(404);
    });

    it('marks all alerts read and clears them', async () => {
      const allRead = await request(fx.app).post('/api/v1/alerts/read-all');
      expect(allRead.status).toBe(200);
      expect(typeof allRead.body.updated).toBe('number');

      const cleared = await request(fx.app).delete('/api/v1/alerts');
      expect(cleared.status).toBe(200);
      const empty = await request(fx.app).get('/api/v1/alerts');
      expect(empty.body.items).toHaveLength(0);
    });
  });

  describe('preferences', () => {
    it('returns defaults', async () => {
      const res = await request(fx.app).get('/api/v1/preferences');
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        notification_monitoring: expect.any(Boolean),
        background_protection: expect.any(Boolean),
        alert_notifications: expect.any(Boolean),
      });
    });

    it('merges a partial update and returns the whole record', async () => {
      const updated = await request(fx.app)
        .patch('/api/v1/preferences')
        .send({ alertNotifications: false });
      expect(updated.status).toBe(200);
      expect(updated.body.alert_notifications).toBe(false);

      const current = await request(fx.app).get('/api/v1/preferences');
      expect(current.body.alert_notifications).toBe(false);
    });

    it('rejects an empty patch', async () => {
      const res = await request(fx.app).patch('/api/v1/preferences').send({});
      expect(res.status).toBe(400);
    });
  });

  describe('rate limiting', () => {
    it('returns 429 after the configured ceiling', async () => {
      // Ensure the politeness clock (shared module state) cannot leak across
      // tests, then read its default env for speed.
      resetRateLimitClock();
      const limited = await makeApp({ RATE_LIMIT_MAX: '2' });
      try {
        await request(limited.app).get('/api/v1/preferences');
        await request(limited.app).get('/api/v1/preferences');
        const third = await request(limited.app).get('/api/v1/preferences');
        expect(third.status).toBe(429);
        expect(third.body.error.code).toBe('RATE_LIMITED');
        expect(String(third.headers['ratelimit'])).toContain('r=0');
      } finally {
        await limited.close();
      }
    });
  });

  describe('terminal handlers', () => {
    it('renders unmatched routes as the standard 404 envelope', async () => {
      const res = await request(fx.app).get('/api/v1/definitely-not-a-route');
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
      expect(res.body.error.message).toContain('/api/v1/definitely-not-a-route');
    });

    it('rejects requests over the JSON body cap', async () => {
      const padded = await makeApp();
      const big = { url: 'https://example.com/' + 'x'.repeat(2 * 1024 * 1024) };
      // Validator caps URL length at 2048, so use a different oversized path:
      // send a huge batch body. Cap is 1 MiB.
      const res = await request(padded.app)
        .post('/api/v1/scans/url/batch')
        .set('content-type', 'application/json')
        .send(JSON.stringify({ urls: Array.from({ length: 30 }, () => 'https://example.com/'.padEnd(60_000, 'x')) }));
      expect(res.status).toBe(413);
      expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
      await padded.close();
    });
  });
});