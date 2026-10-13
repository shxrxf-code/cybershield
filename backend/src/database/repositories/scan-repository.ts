import { randomUUID } from 'node:crypto';
import type { Database } from '../adapter';
import type { Severity, VerdictStatus } from '../../domain/verdict';

export type ScanType =
  | 'quick'
  | 'full'
  | 'url'
  | 'file'
  | 'apk'
  | 'notification'
  | 'scheduled';

export interface ScanHistoryRecord {
  id: string;
  userId?: string;
  scanType: ScanType;
  target?: string;
  fileName?: string;
  fileHash?: string;
  scanStatus: 'completed' | 'failed' | 'cancelled';
  threatLevel: Severity;
  filesChecked: number;
  threatsFound: number;
  durationMs?: number;
  source?: string;
  details: Record<string, unknown>;
  scannedAt: string;
}

export interface CreateScanInput {
  userId?: string;
  scanType: ScanType;
  target?: string;
  fileName?: string;
  fileHash?: string;
  scanStatus?: 'completed' | 'failed' | 'cancelled';
  verdict: VerdictStatus;
  threatLevel: Severity;
  filesChecked?: number;
  threatsFound?: number;
  durationMs?: number;
  source?: string;
  details?: Record<string, unknown>;
  scannedAt?: string;
}

export interface ListScansQuery {
  limit?: number;
  offset?: number;
  scanType?: ScanType;
  threatLevel?: Severity;
  /** Free-text search across file name and target. */
  search?: string;
}

interface ScanRow {
  id: string;
  user_id: string | null;
  scan_type: string;
  target: string | null;
  file_name: string | null;
  file_hash: string | null;
  scan_status: string;
  threat_level: string;
  files_checked: number;
  threats_found: number;
  duration_ms: number | null;
  source: string | null;
  details: string;
  scanned_at: string;
}

function safeJsonParse(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function mapRow(row: ScanRow): ScanHistoryRecord {
  return {
    id: row.id,
    userId: row.user_id ?? undefined,
    scanType: row.scan_type as ScanType,
    target: row.target ?? undefined,
    fileName: row.file_name ?? undefined,
    fileHash: row.file_hash ?? undefined,
    scanStatus: row.scan_status as ScanHistoryRecord['scanStatus'],
    threatLevel: row.threat_level as Severity,
    filesChecked: row.files_checked,
    threatsFound: row.threats_found,
    durationMs: row.duration_ms ?? undefined,
    source: row.source ?? undefined,
    details: safeJsonParse(row.details),
    scannedAt: row.scanned_at,
  };
}

export class ScanRepository {
  constructor(private readonly db: Database) {}

  async create(input: CreateScanInput): Promise<ScanHistoryRecord> {
    const record: ScanHistoryRecord = {
      id: randomUUID(),
      userId: input.userId,
      scanType: input.scanType,
      target: input.target,
      fileName: input.fileName,
      fileHash: input.fileHash?.toLowerCase(),
      scanStatus: input.scanStatus ?? 'completed',
      threatLevel: input.threatLevel,
      filesChecked: input.filesChecked ?? 0,
      threatsFound: input.threatsFound ?? 0,
      durationMs: input.durationMs,
      source: input.source,
      details: input.details ?? {},
      scannedAt: input.scannedAt ?? new Date().toISOString(),
    };

    await this.db.execute(
      `INSERT INTO scan_history
        (id, user_id, scan_type, target, file_name, file_hash, scan_status, threat_level,
         files_checked, threats_found, duration_ms, source, details, scanned_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.id,
        record.userId ?? null,
        record.scanType,
        record.target ?? null,
        record.fileName ?? null,
        record.fileHash ?? null,
        record.scanStatus,
        record.threatLevel,
        record.filesChecked,
        record.threatsFound,
        record.durationMs ?? null,
        record.source ?? null,
        JSON.stringify(record.details),
        record.scannedAt,
      ],
    );
    return record;
  }

  async getById(id: string): Promise<ScanHistoryRecord | undefined> {
    const { rows } = await this.db.query<ScanRow>('SELECT * FROM scan_history WHERE id = ?', [id]);
    return rows[0] ? mapRow(rows[0]) : undefined;
  }

  async findLatestByHash(fileHash: string): Promise<ScanHistoryRecord | undefined> {
    const { rows } = await this.db.query<ScanRow>(
      'SELECT * FROM scan_history WHERE file_hash = ? ORDER BY scanned_at DESC LIMIT 1',
      [fileHash.toLowerCase()],
    );
    return rows[0] ? mapRow(rows[0]) : undefined;
  }

  async list(query: ListScansQuery = {}): Promise<{ items: ScanHistoryRecord[]; total: number }> {
    const limit = Math.min(Math.max(query.limit ?? 50, 1), 200);
    const offset = Math.max(query.offset ?? 0, 0);

    const clauses: string[] = [];
    const params: Array<string | number> = [];
    if (query.scanType) {
      clauses.push('scan_type = ?');
      params.push(query.scanType);
    }
    if (query.threatLevel) {
      clauses.push('threat_level = ?');
      params.push(query.threatLevel);
    }
    if (query.search) {
      clauses.push('(LOWER(COALESCE(file_name, \'\')) LIKE ? OR LOWER(COALESCE(target, \'\')) LIKE ?)');
      const needle = `%${query.search.toLowerCase()}%`;
      params.push(needle, needle);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';

    const countResult = await this.db.query<{ total: number }>(
      `SELECT COUNT(*) AS total FROM scan_history ${where}`,
      params,
    );
    const { rows } = await this.db.query<ScanRow>(
      `SELECT * FROM scan_history ${where} ORDER BY scanned_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset],
    );

    return { items: rows.map(mapRow), total: Number(countResult.rows[0]?.total ?? 0) };
  }

  async summary(): Promise<{ totalScans: number; totalThreats: number; lastScanAt?: string }> {
    const { rows } = await this.db.query<{ total_scans: number; total_threats: number; last_scan_at: string | null }>(
      `SELECT COUNT(*) AS total_scans,
              COALESCE(SUM(threats_found), 0) AS total_threats,
              MAX(scanned_at) AS last_scan_at
       FROM scan_history`,
    );
    const row = rows[0];
    return {
      totalScans: Number(row?.total_scans ?? 0),
      totalThreats: Number(row?.total_threats ?? 0),
      lastScanAt: row?.last_scan_at ?? undefined,
    };
  }

  async clear(): Promise<number> {
    const result = await this.db.execute('DELETE FROM scan_history');
    return result.changes;
  }
}
