/**
 * Mobile ThreatGuard — scan repository.
 *
 * Handles all database operations for scan records.
 */

import { generateId } from '../utils/format';
import { execute } from './service';
import type { ScanRecord as DomainScanRecord } from '../domain/types';
import type { ScanRecord as DbScanRecord } from './schema';
import type { Scalar } from '@op-engineering/op-sqlite';

export interface ScanRepository {
  create(scan: Omit<DomainScanRecord, 'id' | 'createdAt' | 'updatedAt'>): Promise<DomainScanRecord>;
  findById(id: string): Promise<DomainScanRecord | null>;
  findAll(options?: ScanFindOptions): Promise<DomainScanRecord[]>;
  findRecent(limit: number): Promise<DomainScanRecord[]>;
  findByType(scanType: string, limit?: number): Promise<DomainScanRecord[]>;
  findByHash(fileHash: string): Promise<DomainScanRecord | null>;
  update(id: string, updates: Partial<DomainScanRecord>): Promise<boolean>;
  delete(id: string): Promise<boolean>;
  deleteAll(): Promise<number>;
  count(): Promise<number>;
  countByThreatLevel(): Promise<Record<string, number>>;
}

export interface ScanFindOptions {
  scanType?: string;
  threatLevel?: string;
  limit?: number;
  offset?: number;
  orderBy?: 'scannedAt' | 'createdAt';
  orderDir?: 'ASC' | 'DESC';
}

const SCAN_COLUMNS = `
  id, scan_type, target, file_hash, file_name, file_size,
  scan_status, threat_level, threat_type, detection_reason,
  threats_found, files_checked, duration_ms, source,
  scanned_at, created_at, updated_at
`;

function mapDbToDomain(row: DbScanRecord): DomainScanRecord {
  return {
    id: row.id,
    scanType: row.scan_type as DomainScanRecord['scanType'],
    target: row.target ?? undefined,
    fileHash: row.file_hash ?? undefined,
    fileName: row.file_name ?? undefined,
    fileSize: row.file_size ?? undefined,
    scanStatus: row.scan_status as DomainScanRecord['scanStatus'],
    threatLevel: row.threat_level as DomainScanRecord['threatLevel'],
    threatType: row.threat_type ?? undefined,
    detectionReason: row.detection_reason ?? undefined,
    threatsFound: row.threats_found,
    filesChecked: row.files_checked,
    durationMs: row.duration_ms,
    source: row.source as DomainScanRecord['source'],
    scannedAt: row.scanned_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapDomainToDb(record: Omit<DomainScanRecord, 'id' | 'createdAt' | 'updatedAt'>): Record<string, Scalar> {
  return {
    scan_type: record.scanType,
    target: record.target ?? null,
    file_hash: record.fileHash ?? null,
    file_name: record.fileName ?? null,
    file_size: record.fileSize ?? null,
    scan_status: record.scanStatus,
    threat_level: record.threatLevel,
    threat_type: record.threatType ?? null,
    detection_reason: record.detectionReason ?? null,
    threats_found: record.threatsFound,
    files_checked: record.filesChecked,
    duration_ms: record.durationMs,
    source: record.source,
    scanned_at: record.scannedAt,
  };
}

// Type assertion helper to bypass strict generics
async function execRows<T>(query: string, params?: Scalar[]): Promise<T[]> {
  const result = await execute(query, params as Scalar[]);
  return result.rows as T[];
}

export const scanRepository: ScanRepository = {
  async create(scan) {
    const id = generateId();
    const now = new Date().toISOString();
    const dbRecord = mapDomainToDb(scan);

    const result = await execute(
      `INSERT INTO scans (
        id, scan_type, target, file_hash, file_name, file_size,
        scan_status, threat_level, threat_type, detection_reason,
        threats_found, files_checked, duration_ms, source,
        scanned_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        dbRecord.scan_type,
        dbRecord.target,
        dbRecord.file_hash,
        dbRecord.file_name,
        dbRecord.file_size,
        dbRecord.scan_status,
        dbRecord.threat_level,
        dbRecord.threat_type,
        dbRecord.detection_reason,
        dbRecord.threats_found,
        dbRecord.files_checked,
        dbRecord.duration_ms,
        dbRecord.source,
        dbRecord.scanned_at,
        now,
        now,
      ]
    );

    if (result.rowsAffected === 0) {
      throw new Error('Failed to insert scan record');
    }

    return this.findById(id) as Promise<DomainScanRecord>;
  },

  async findById(id) {
    const rows = await execRows<DbScanRecord>(
      `SELECT ${SCAN_COLUMNS} FROM scans WHERE id = ?`,
      [id]
    );
    return rows[0] ? mapDbToDomain(rows[0]) : null;
  },

  async findAll(options = {}) {
    const {
      scanType,
      threatLevel,
      limit = 100,
      offset = 0,
      orderBy = 'scannedAt',
      orderDir = 'DESC',
    } = options;

    let where = '1=1';
    const params: Scalar[] = [];

    if (scanType) {
      where += ' AND scan_type = ?';
      params.push(scanType);
    }
    if (threatLevel) {
      where += ' AND threat_level = ?';
      params.push(threatLevel);
    }

    const dbOrderBy = orderBy === 'scannedAt' ? 'scanned_at' : 'created_at';

    const query = `
      SELECT ${SCAN_COLUMNS}
      FROM scans
      WHERE ${where}
      ORDER BY ${dbOrderBy} ${orderDir}
      LIMIT ? OFFSET ?
    `;
    params.push(limit, offset);

    const rows = await execRows<DbScanRecord>(query, params);
    return rows.map(mapDbToDomain);
  },

  async findRecent(limit = 200) {
    return this.findAll({ limit, orderBy: 'scannedAt', orderDir: 'DESC' });
  },

  async findByType(scanType, limit = 50) {
    return this.findAll({ scanType, limit, orderBy: 'scannedAt', orderDir: 'DESC' });
  },

  async findByHash(fileHash) {
    const rows = await execRows<DbScanRecord>(
      `SELECT ${SCAN_COLUMNS} FROM scans WHERE file_hash = ? ORDER BY scanned_at DESC LIMIT 1`,
      [fileHash]
    );
    return rows[0] ? mapDbToDomain(rows[0]) : null;
  },

  async update(id, updates) {
    const allowedFields = [
      'target',
      'fileHash',
      'fileName',
      'fileSize',
      'scanStatus',
      'threatLevel',
      'threatType',
      'detectionReason',
      'threatsFound',
      'filesChecked',
      'durationMs',
      'source',
      'scannedAt',
    ];

    const setParts: string[] = [];
    const params: Scalar[] = [];

    for (const [key, value] of Object.entries(updates)) {
      const dbKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
      if (allowedFields.includes(key) && value !== undefined) {
        setParts.push(`${dbKey} = ?`);
        params.push(value ?? null);
      }
    }

    if (setParts.length === 0) return false;

    setParts.push('updated_at = datetime("now")');
    params.push(id);

    const result = await execute(
      `UPDATE scans SET ${setParts.join(', ')} WHERE id = ?`,
      params
    );
    return result.rowsAffected > 0;
  },

  async delete(id) {
    const result = await execute('DELETE FROM scans WHERE id = ?', [id]);
    return result.rowsAffected > 0;
  },

  async deleteAll() {
    const result = await execute('DELETE FROM scans');
    return result.rowsAffected;
  },

  async count() {
    const result = await execute<{ count: number }>('SELECT COUNT(*) as count FROM scans');
    return result.rows[0]?.count ?? 0;
  },

  async countByThreatLevel() {
    const result = await execute<{ threat_level: string; count: number }>(
      'SELECT threat_level, COUNT(*) as count FROM scans GROUP BY threat_level'
    );
    const counts: Record<string, number> = {};
    for (const row of result.rows) {
      counts[row.threat_level] = row.count;
    }
    return counts;
  },
};

/**
 * Insert a scan record directly from an API response.
 * Used when syncing backend scan results.
 */
export async function createScanFromAPI(data: {
  scanType: DomainScanRecord['scanType'];
  target: string;
  fileHash?: string;
  fileName?: string;
  threatLevel: DomainScanRecord['threatLevel'];
  threatType?: string;
  detectionReason?: string;
  durationMs: number;
  source: 'local' | 'backend';
}): Promise<DomainScanRecord> {
  const now = new Date().toISOString();
  const threatsFound = data.threatLevel === 'SAFE' || data.threatLevel === 'UNKNOWN' ? 0 : 1;

  return scanRepository.create({
    scanType: data.scanType,
    target: data.target,
    fileHash: data.fileHash ?? undefined,
    fileName: data.fileName ?? undefined,
    fileSize: undefined,
    scanStatus: 'completed',
    threatLevel: data.threatLevel,
    threatType: data.threatType ?? undefined,
    detectionReason: data.detectionReason ?? undefined,
    threatsFound,
    filesChecked: 1,
    durationMs: data.durationMs,
    source: data.source,
    scannedAt: now,
  });
}