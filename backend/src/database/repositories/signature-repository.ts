import { randomUUID } from 'node:crypto';
import type { Database } from '../adapter';
import type { SignatureStore } from '../../providers/local-signature.provider';

export type SignatureKind = 'url' | 'hash';

export interface ThreatSignatureRecord {
  id: string;
  kind: SignatureKind;
  value: string;
  label?: string;
  source?: string;
  createdAt: string;
}

interface SignatureRow {
  id: string;
  kind: string;
  value: string;
  label: string | null;
  source: string | null;
  created_at: string;
}

function mapRow(row: SignatureRow): ThreatSignatureRecord {
  return {
    id: row.id,
    kind: row.kind as SignatureKind,
    value: row.value,
    label: row.label ?? undefined,
    source: row.source ?? undefined,
    createdAt: row.created_at,
  };
}

export class SignatureRepository {
  constructor(private readonly db: Database) {}

  async add(input: { kind: SignatureKind; value: string; label?: string; source?: string }): Promise<ThreatSignatureRecord> {
    const record: ThreatSignatureRecord = {
      id: randomUUID(),
      kind: input.kind,
      value: input.value.trim().toLowerCase(),
      label: input.label,
      source: input.source,
      createdAt: new Date().toISOString(),
    };
    await this.db.execute(
      `INSERT INTO threat_signatures (id, kind, value, label, source, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (kind, value) DO UPDATE SET label = excluded.label, source = excluded.source`,
      [
        record.id,
        record.kind,
        record.value,
        record.label ?? null,
        record.source ?? null,
        record.createdAt,
      ],
    );
    return record;
  }

  async list(kind?: SignatureKind): Promise<ThreatSignatureRecord[]> {
    const { rows } = await this.db.query<SignatureRow>(
      kind ? 'SELECT * FROM threat_signatures WHERE kind = ? ORDER BY created_at DESC' : 'SELECT * FROM threat_signatures ORDER BY created_at DESC',
      kind ? [kind] : [],
    );
    return rows.map(mapRow);
  }

  async counts(): Promise<Record<string, number>> {
    const { rows } = await this.db.query<{ kind: string; total: number }>(
      'SELECT kind, COUNT(*) AS total FROM threat_signatures GROUP BY kind',
    );
    const out: Record<string, number> = {};
    for (const row of rows) out[row.kind] = Number(row.total);
    return out;
  }

  /**
   * Build an in-memory SignatureStore snapshot from the database so the
   * provider can answer without a query per lookup.
   */
  async snapshotStore(): Promise<SignatureStore> {
    const records = await this.list();
    const urls = records.filter((r) => r.kind === 'url').map((r) => r.value);
    const hashes = records.filter((r) => r.kind === 'hash').map((r) => r.value);
    // Imported lazily to avoid a cycle at module load time.
    const { InMemorySignatureStore } = await import('../../providers/local-signature.provider');
    return new InMemorySignatureStore({ urls, hashes });
  }
}
