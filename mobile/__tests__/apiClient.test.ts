/* eslint-env jest */
import { scanUrl, scanFileHash, checkHealth, mapUrlScanToRecord } from '../src/api/client';
import { API_BASE_URL } from '../src/api/config';

/**
 * The mobile client and the backend are two separate programs that have to
 * agree on the wire format. They previously did not: the client called
 * `/api/v1/scan/url` while the backend serves `/api/v1/scans/url`, it sent
 * `{ hash }` where the backend validates `sha256`, and it expected a
 * camelCase body where the backend emits snake_case.
 *
 * These tests pin the request side of the contract (path, method, body) and
 * the response mapping. The response fixtures are verbatim shapes taken from
 * `backend/src/controllers/dto.ts`.
 */

const fetchMock = jest.fn();

beforeEach(() => {
  fetchMock.mockReset();
  (global as unknown as { fetch: jest.Mock }).fetch = fetchMock;
});

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

const URL_SCAN_RESPONSE = {
  scan_id: 'scan-1',
  url: 'https://example.com/login',
  domain: 'example.com',
  protocol: 'https',
  cached: false,
  duration_ms: 42,
  scanned_at: '2026-01-01T00:00:00.000Z',
  duplicate_alert: false,
  alert: null,
  verdict: {
    status: 'MALICIOUS',
    severity: 'HIGH',
    category: 'PHISHING',
    score: 91,
    definitive: true,
    recommended_action: 'Do not open this link.',
    reasons: [
      { code: 'URLHAUS_MATCH', message: 'Listed on URLhaus as a phishing host.', severity: 'HIGH' },
    ],
    detection_sources: [
      { source: 'urlhaus', label: 'URLhaus', status: 'MALICIOUS' },
    ],
  },
};

const FILE_SCAN_RESPONSE = {
  scan_id: 'scan-2',
  sha256: 'a'.repeat(64),
  file_name: 'invoice.pdf',
  duration_ms: 17,
  scanned_at: '2026-01-01T00:00:01.000Z',
  duplicate_alert: false,
  alert: null,
  verdict: {
    status: 'SAFE',
    severity: 'NONE',
    category: 'NONE',
    score: 0,
    definitive: false,
    recommended_action: 'No action needed.',
    reasons: [],
    detection_sources: [{ source: 'local-signature', label: 'Local threat signatures', status: 'SAFE' }],
  },
};

describe('api client — request contract', () => {
  it('posts a URL scan to the backend route that actually exists', async () => {
    fetchMock.mockResolvedValue(jsonResponse(URL_SCAN_RESPONSE));

    await scanUrl({ url: 'https://example.com/login' });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${API_BASE_URL}/api/v1/scans/url`);
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({ url: 'https://example.com/login' });
  });

  it('sends the API key header the backend authenticates with', async () => {
    fetchMock.mockResolvedValue(jsonResponse(URL_SCAN_RESPONSE));

    await scanUrl({ url: 'https://example.com/login' });

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers['X-API-Key']).toBeDefined();
    expect(init.headers['Content-Type']).toBe('application/json');
  });

  it('sends the file hash under the key the backend validates (sha256)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(FILE_SCAN_RESPONSE));

    await scanFileHash({ hash: 'a'.repeat(64), fileName: 'invoice.pdf', sizeBytes: 1024 });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${API_BASE_URL}/api/v1/scans/file`);
    expect(JSON.parse(init.body)).toEqual({
      sha256: 'a'.repeat(64),
      fileName: 'invoice.pdf',
      sizeBytes: 1024,
    });
  });

  it('calls the health endpoint at its real path', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        status: 'ok',
        version: '0.1.0',
        environment: 'development',
        uptime_seconds: 12,
        database: { client: 'sqlite', ok: true, latency_ms: 2 },
        intel_enabled: false,
      }),
    );

    const health = await checkHealth();

    expect(fetchMock.mock.calls[0][0]).toBe(`${API_BASE_URL}/api/v1/health`);
    expect(health.status).toBe('ok');
    expect(health.database?.ok).toBe(true);
  });
});

describe('api client — response mapping', () => {
  it('maps a URL scan verdict onto the shape the screens consume', async () => {
    fetchMock.mockResolvedValue(jsonResponse(URL_SCAN_RESPONSE));

    const result = await scanUrl({ url: 'https://example.com/login' });

    expect(result).toEqual({
      id: 'scan-1',
      scanType: 'url',
      target: 'https://example.com/login',
      status: 'completed',
      threatLevel: 'MALICIOUS',
      threatType: 'PHISHING',
      detectionReason: 'Listed on URLhaus as a phishing host.',
      scannedAt: '2026-01-01T00:00:00.000Z',
    });
  });

  it('maps a file scan verdict onto the shape the scanner consumes', async () => {
    fetchMock.mockResolvedValue(jsonResponse(FILE_SCAN_RESPONSE));

    const result = await scanFileHash({ hash: 'a'.repeat(64) });

    expect(result.id).toBe('scan-2');
    expect(result.scanType).toBe('file');
    expect(result.target).toBe('a'.repeat(64));
    expect(result.threatLevel).toBe('SAFE');
  });

  it('omits the detection reason when the backend reports no reasons', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        ...FILE_SCAN_RESPONSE,
        verdict: { ...FILE_SCAN_RESPONSE.verdict, reasons: [] },
      }),
    );

    const result = await scanFileHash({ hash: 'a'.repeat(64) });

    expect(result.detectionReason).toBeUndefined();
  });

  it('maps a scan result onto the local ScanRecord shape', async () => {
    fetchMock.mockResolvedValue(jsonResponse(URL_SCAN_RESPONSE));

    const result = await scanUrl({ url: 'https://example.com/login' });
    const record = mapUrlScanToRecord(result);

    expect(record.id).toBe('scan-1');
    expect(record.scanType).toBe('url');
    expect(record.threatLevel).toBe('MALICIOUS');
    expect(record.threatsFound).toBe(1);
    expect(record.source).toBe('backend');
  });

  it('counts no threat for a SAFE or UNKNOWN verdict', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ ...URL_SCAN_RESPONSE, verdict: { ...URL_SCAN_RESPONSE.verdict, status: 'UNKNOWN' } }),
    );

    const result = await scanUrl({ url: 'https://example.com/login' });
    expect(mapUrlScanToRecord(result).threatsFound).toBe(0);
  });
});

describe('api client — error handling', () => {
  it('raises an ApiError carrying the status and body', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ error: { code: 'VALIDATION_ERROR', message: 'bad request' } }, 400),
    );

    await expect(scanUrl({ url: 'not-a-url' })).rejects.toMatchObject({
      status: 400,
    });
  });
});
