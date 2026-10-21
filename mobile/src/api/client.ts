/**
 * Mobile ThreatGuard – API client for the ThreatGuard backend.
 *
 * The backend exposes (see `backend/src/routes/`):
 *   GET  /api/v1/health                              (no API key required)
 *   POST /api/v1/scans/url   { url }                 -> UrlScanDto
 *   POST /api/v1/scans/file  { sha256, ... }         -> FileScanDto
 *   POST /api/v1/scans/notification { text, ... }    -> NotificationScanDto
 *
 * The backend speaks snake_case; the app's internal model is camelCase. The
 * translation happens here, in one place, so the screens keep working against
 * the camelCase shape they already use and the wire format stays owned by
 * `backend/src/controllers/dto.ts`.
 *
 * This client is intentionally thin: it does not store third-party secrets.
 * The backend API key comes from `local-config.ts` or `THREATGUARD_API_KEY`;
 * Google Safe Browsing / URLhaus / VirusTotal keys never reach the device.
 */

import { API_BASE_URL, DEFAULT_API_KEY } from './config';

export interface ApiError extends Error {
  status?: number;
  body?: unknown;
}

export interface UrlScanRequest {
  url: string;
}

/**
 * The app-facing shape of a URL scan. This is what the screens consume
 * (`ReputationResult` in UrlScannerScreen) and what `mapUrlScanToRecord`
 * turns into the local `ScanRecord` shape.
 */
export interface UrlScanResponse {
  id: string;
  scanType: 'url';
  target: string;
  status: 'completed' | 'pending';
  threatLevel: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  threatType?: string;
  detectionReason?: string;
  scannedAt: string;
}

export interface FileScanRequest {
  /** SHA-256 of the file. The file bytes never leave the device. */
  hash: string;
  fileName?: string;
  sizeBytes?: number;
}

export interface FileScanResponse {
  id: string;
  scanType: 'file';
  target: string;
  status: 'completed' | 'pending';
  threatLevel: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  threatType?: string;
  detectionReason?: string;
  scannedAt: string;
}

export interface HealthResponse {
  status: 'ok' | 'unhealthy';
  version: string;
  environment?: string;
  uptimeSeconds?: number;
  database?: { client: string; ok: boolean; latencyMs?: number };
  intelEnabled?: boolean;
}

// ---------------------------------------------------------------------------
// Wire types (snake_case, exactly as the backend serialises them)
// ---------------------------------------------------------------------------

interface VerdictWire {
  status: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  severity: string;
  category?: string;
  score: number;
  definitive: boolean;
  recommended_action: string;
  reasons: Array<{ code: string; message: string; severity: string }>;
  detection_sources: Array<{
    source: string;
    label: string;
    status: string;
    detail?: string;
    error?: string;
  }>;
}

interface UrlScanWire {
  scan_id: string;
  url: string;
  domain: string;
  protocol: string;
  cached: boolean;
  duration_ms: number;
  scanned_at: string;
  duplicate_alert: boolean;
  alert: { id: string; threat_type: string; severity: string; detection_reason: string } | null;
  verdict: VerdictWire;
}

interface FileScanWire {
  scan_id: string;
  sha256: string;
  file_name?: string;
  duration_ms: number;
  scanned_at: string;
  duplicate_alert: boolean;
  alert: { id: string; threat_type: string; severity: string; detection_reason: string } | null;
  verdict: VerdictWire;
}

interface HealthWire {
  status: 'ok' | 'unhealthy';
  version: string;
  environment?: string;
  uptime_seconds?: number;
  database?: { client: string; ok: boolean; latency_ms?: number };
  intel_enabled?: boolean;
}

// ---------------------------------------------------------------------------

/**
 * Build the request headers. In a production build the API key is supplied at
 * build time via a Gradle/Metro constant or read from secure storage.
 */
function authHeaders(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'X-API-Key': DEFAULT_API_KEY,
  };
}

async function parseResponse<T>(response: Response): Promise<T> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = await response.text();
  }
  if (!response.ok) {
    const err = new Error(
      typeof body === 'string' ? body : JSON.stringify(body),
    ) as ApiError;
    err.status = response.status;
    err.body = body;
    throw err;
  }
  return body as T;
}

/**
 * The backend reports a verdict with a list of reasons; the app shows a
 * single line. The first reason wins, falling back to the recorded alert's
 * detection reason.
 *
 * The verdict's `recommended_action` is deliberately NOT used as a fallback:
 * it is an instruction ("do not open this link"), not a detection reason, and
 * showing it under a "detection reason" label would misreport why the scan
 * came back the way it did. A clean scan therefore has no reason line.
 */
function detectionReasonOf(wire: { verdict: VerdictWire; alert: { detection_reason: string } | null }): string | undefined {
  const reason = wire.verdict?.reasons?.[0]?.message;
  if (reason) return reason;
  if (wire.alert?.detection_reason) return wire.alert.detection_reason;
  return undefined;
}

export async function checkHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/health`, {
    headers: authHeaders(),
  });
  const wire = await parseResponse<HealthWire>(res);
  return {
    status: wire.status,
    version: wire.version,
    ...(wire.environment ? { environment: wire.environment } : {}),
    ...(wire.uptime_seconds !== undefined ? { uptimeSeconds: wire.uptime_seconds } : {}),
    ...(wire.database
      ? {
          database: {
            client: wire.database.client,
            ok: wire.database.ok,
            ...(wire.database.latency_ms !== undefined
              ? { latencyMs: wire.database.latency_ms }
              : {}),
          },
        }
      : {}),
    ...(wire.intel_enabled !== undefined ? { intelEnabled: wire.intel_enabled } : {}),
  };
}

export async function scanUrl(request: UrlScanRequest): Promise<UrlScanResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/scans/url`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ url: request.url }),
  });
  const wire = await parseResponse<UrlScanWire>(res);
  return {
    id: wire.scan_id,
    scanType: 'url',
    target: wire.url,
    status: 'completed',
    threatLevel: wire.verdict.status,
    ...(wire.verdict.category ? { threatType: wire.verdict.category } : {}),
    ...(detectionReasonOf(wire) ? { detectionReason: detectionReasonOf(wire) } : {}),
    scannedAt: wire.scanned_at,
  };
}

export async function scanFileHash(request: FileScanRequest): Promise<FileScanResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/scans/file`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({
      sha256: request.hash,
      ...(request.fileName ? { fileName: request.fileName } : {}),
      ...(request.sizeBytes !== undefined ? { sizeBytes: request.sizeBytes } : {}),
    }),
  });
  const wire = await parseResponse<FileScanWire>(res);
  return {
    id: wire.scan_id,
    scanType: 'file',
    target: wire.sha256,
    status: 'completed',
    threatLevel: wire.verdict.status,
    ...(wire.verdict.category ? { threatType: wire.verdict.category } : {}),
    ...(detectionReasonOf(wire) ? { detectionReason: detectionReasonOf(wire) } : {}),
    scannedAt: wire.scanned_at,
  };
}

/**
 * Helper to turn a `UrlScanResponse` into the internal `ScanRecord` shape.
 * The store layer will call this.
 */
export function mapUrlScanToRecord(response: UrlScanResponse) {
  return {
    id: response.id,
    scanType: 'url' as const,
    target: response.target,
    fileHash: undefined,
    fileName: undefined,
    scanStatus: response.status,
    threatLevel: response.threatLevel,
    threatsFound: response.threatLevel === 'SAFE' || response.threatLevel === 'UNKNOWN' ? 0 : 1,
    durationMs: 0,
    scannedAt: response.scannedAt,
    source: 'backend',
  };
}
