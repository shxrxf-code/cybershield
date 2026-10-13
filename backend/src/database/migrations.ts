import type { Database } from './adapter';

/**
 * Schema migrations.
 *
 * The DDL is intentionally written to be valid on **both** SQLite and
 * PostgreSQL: text identifiers (generated in the application), TEXT
 * timestamps in ISO-8601, and INTEGER 0/1 booleans. That keeps a single schema
 * definition while remaining a normal, index-friendly PostgreSQL design.
 */

export interface Migration {
  id: string;
  description: string;
  sql: string;
}

export const MIGRATIONS: Migration[] = [
  {
    id: '001_init',
    description: 'core tables: users, scan history, alerts, settings, signatures, reputation cache',
    sql: `
CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY,
  created_at   TEXT NOT NULL,
  preferences  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS scan_history (
  id            TEXT PRIMARY KEY,
  user_id       TEXT REFERENCES users(id) ON DELETE SET NULL,
  scan_type     TEXT NOT NULL,
  target        TEXT,
  file_name     TEXT,
  file_hash     TEXT,
  scan_status   TEXT NOT NULL,
  threat_level  TEXT NOT NULL,
  files_checked INTEGER NOT NULL DEFAULT 0,
  threats_found INTEGER NOT NULL DEFAULT 0,
  duration_ms   INTEGER,
  source        TEXT,
  details       TEXT NOT NULL DEFAULT '{}',
  scanned_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history (scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_history_threat_level ON scan_history (threat_level);
CREATE INDEX IF NOT EXISTS idx_scan_history_file_hash ON scan_history (file_hash);

CREATE TABLE IF NOT EXISTS threat_alerts (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT REFERENCES users(id) ON DELETE SET NULL,
  scan_id             TEXT REFERENCES scan_history(id) ON DELETE SET NULL,
  threat_type         TEXT NOT NULL,
  severity            TEXT NOT NULL,
  category            TEXT,
  source_application  TEXT,
  detection_reason    TEXT NOT NULL,
  target              TEXT,
  recommended_action  TEXT,
  is_read             INTEGER NOT NULL DEFAULT 0,
  created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_created_at ON threat_alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_severity ON threat_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_is_read ON threat_alerts (is_read);

CREATE TABLE IF NOT EXISTS security_settings (
  id                      TEXT PRIMARY KEY,
  user_id                 TEXT UNIQUE,
  notification_monitoring INTEGER NOT NULL DEFAULT 0,
  background_protection   INTEGER NOT NULL DEFAULT 1,
  alert_notifications     INTEGER NOT NULL DEFAULT 1,
  privacy_preferences     TEXT NOT NULL DEFAULT '{}',
  updated_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_signatures (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  value      TEXT NOT NULL,
  label      TEXT,
  source     TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_threat_signatures_kind_value ON threat_signatures (kind, value);

CREATE TABLE IF NOT EXISTS reputation_cache (
  cache_key  TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  verdict    TEXT NOT NULL,
  provider   TEXT,
  payload    TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reputation_cache_expires_at ON reputation_cache (expires_at);
`,
  },
];

/**
 * Apply every migration that has not run yet. Returns the ids applied.
 * Each migration is applied inside a transaction.
 */
export async function runMigrations(db: Database): Promise<string[]> {
  await db.execRaw(
    `CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL);`,
  );
  const { rows } = await db.query<{ id: string }>('SELECT id FROM schema_migrations');
  const applied = new Set(rows.map((row) => row.id));
  const justApplied: string[] = [];

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.id)) continue;
    await db.transaction(async (tx) => {
      await tx.execRaw(migration.sql);
      await tx.execute('INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)', [
        migration.id,
        new Date().toISOString(),
      ]);
    });
    justApplied.push(migration.id);
  }
  return justApplied;
}
