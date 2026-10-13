/**
 * Mobile ThreatGuard – API client for the ThreatGuard backend.
 *
 * The backend exposes:
 *   GET  /health
 *   POST /api/v1/scan/url   { url: string } -> { status, threatLevel?, threatType?, detectionReason?, ... }
 *   POST /api/v1/scan/file  { hash: string } -> { status, threatLevel?, ... }
 *   GET  /api/v1/threat/:id -> full threat record
 *
 * This client is intentionally thin: it does not store the API key in code.
 * The key comes from the app's settings (Phase 2 persistence) or a build-time
 * constant for local development.
 */

import { API_BASE_URL, DEFAULT_API_KEY } from './config';

export interface ApiError extends Error {
  status?: number;
  body?: unknown;
}

export interface UrlScanRequest {
  url: string;
}

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
  hash: string;
}

export interface FileScanResponse {
  id: string;
  scanType: 'file';
  target: string;
  status: 'completed' | 'pending';
  threatLevel: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  detectionReason?: string;
  scannedAt: string;
}

export interface HealthResponse {
  status: 'ok';
  version: string;
  timestamp: string;
}

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

export async function checkHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/health`, {
    headers: authHeaders(),
  });
  return parseResponse(res);
}

export async function scanUrl(request: UrlScanRequest): Promise<UrlScanResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/scan/url`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(request),
  });
  return parseResponse(res);
}

export async function scanFileHash(request: FileScanRequest): Promise<FileScanResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/scan/file`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(request),
  });
  return parseResponse(res);
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