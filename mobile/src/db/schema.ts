/**
 * Mobile ThreatGuard — database schema.
 *
 * This module defines the SQL schema for the local SQLite database.
 * All tables use INTEGER PRIMARY KEY for auto-incrementing IDs.
 * Timestamps are stored as TEXT (ISO 8601) for portability.
 */

const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
-- Scans table: stores all scan records (url, file, apk, device, notification)
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,                    -- UUID
  scan_type TEXT NOT NULL,                -- 'url' | 'file' | 'apk' | 'device' | 'notification' | 'quick' | 'full' | 'scheduled'
  target TEXT,                            -- URL, file path, package name, etc.
  file_hash TEXT,                         -- SHA-256 for file/apk scans
  file_name TEXT,                         -- Original file name for file scans
  file_size INTEGER,                      -- File size in bytes
  scan_status TEXT NOT NULL DEFAULT 'completed', -- 'pending' | 'running' | 'completed' | 'failed'
  threat_level TEXT NOT NULL DEFAULT 'UNKNOWN',  -- 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN'
  threat_type TEXT,                       -- e.g., 'malicious_url', 'suspicious_file', 'phishing_notification'
  detection_reason TEXT,                  -- Human-readable reason
  threats_found INTEGER NOT NULL DEFAULT 0,
  files_checked INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'local',   -- 'local' | 'backend'
  scanned_at TEXT NOT NULL,               -- ISO 8601 timestamp
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Alerts table: stores threat alerts
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,                    -- UUID
  threat_type TEXT NOT NULL,              -- e.g., 'malicious_url', 'phishing_notification'
  severity TEXT NOT NULL,                 -- 'critical' | 'high' | 'medium' | 'low' | 'info'
  category TEXT,                          -- 'phishing' | 'malware' | 'scam' | 'spam' | 'suspicious' | 'unwanted-software' | 'social-engineering' | 'none' | 'unknown'
  target TEXT,                            -- The URL, file, or message content
  source_application TEXT,                -- Package name of app that generated the notification
  detection_reason TEXT NOT NULL,         -- Why it was flagged
  recommended_action TEXT,                -- What the user should do
  is_read INTEGER NOT NULL DEFAULT 0,     -- 0 = unread, 1 = read
  scanned_at TEXT NOT NULL,               -- When the scan that created this alert ran
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  read_at TEXT                            -- When the user marked it read
);

-- Settings table: key-value store for app settings
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_threat_level ON scans(threat_level);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_file_hash ON scans(file_hash);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_is_read ON alerts(is_read);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts(threat_type);

-- Trigger to update updated_at timestamps
CREATE TRIGGER IF NOT EXISTS scans_updated_at
AFTER UPDATE ON scans
BEGIN
  UPDATE scans SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS settings_updated_at
AFTER UPDATE ON settings
BEGIN
  UPDATE settings SET updated_at = datetime('now') WHERE key = NEW.key;
END;
`;

/**
 * Split a SQL script into individual statements.
 *
 * Splitting on `;` alone is wrong: a `CREATE TRIGGER … BEGIN … END;` body
 * contains statement separators of its own, and a `;` can legitimately appear
 * inside a string literal or a `--` comment. This walker tracks string
 * literals, line comments and BEGIN…END trigger bodies and only breaks on a
 * top-level semicolon, so every statement it returns is complete and safe to
 * hand to `execute()` one at a time.
 */
export function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let word = '';
  let triggerDepth = 0;

  const flushWord = (): void => {
    if (word === '') return;
    const keyword = word.toUpperCase();
    if (keyword === 'BEGIN') triggerDepth += 1;
    else if (keyword === 'END') triggerDepth = Math.max(0, triggerDepth - 1);
    word = '';
  };

  /** Drop comment-only lines; a statement is handed to SQLite on its own. */
  const push = (chunk: string): void => {
    const statement = chunk
      .split('\n')
      .filter((line) => !/^\s*--/.test(line))
      .join('\n')
      .trim();
    if (statement.length > 0) statements.push(statement);
  };

  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];

    // String / identifier literal: copy verbatim, its contents never split.
    if (char === "'" || char === '"') {
      flushWord();
      const quote = char;
      current += char;
      i += 1;
      while (i < sql.length) {
        current += sql[i];
        if (sql[i] === quote) {
          if (sql[i + 1] === quote) {
            // Escaped quote ('' or "") – still part of the literal.
            current += sql[i + 1];
            i += 2;
            continue;
          }
          break;
        }
        i += 1;
      }
      continue;
    }

    // Line comment: copied through to the newline, never scanned for `;`.
    if (char === '-' && sql[i + 1] === '-') {
      flushWord();
      const newline = sql.indexOf('\n', i);
      if (newline === -1) {
        current += sql.slice(i);
        break;
      }
      current += sql.slice(i, newline + 1);
      i = newline;
      continue;
    }

    // Finish the pending word first so that the `END` of a trigger body is
    // accounted for before its terminating `;` is judged.
    if (/[A-Za-z_]/.test(char)) {
      word += char;
      current += char;
      continue;
    }
    flushWord();

    if (char === ';' && triggerDepth === 0) {
      push(current);
      current = '';
      continue;
    }

    current += char;
  }

  flushWord();
  push(current);

  return statements;
}

/**
 * Migration from version 0 (empty) to version 1 (initial schema).
 * Future migrations would be added here.
 */
export const MIGRATIONS: Array<{ from: number; to: number; sql: string }> = [
  {
    from: 0,
    to: SCHEMA_VERSION,
    sql: SCHEMA_SQL,
  },
];

/**
 * Type definitions matching the database schema.
 */
export interface ScanRecord {
  id: string;
  scan_type: string;
  target?: string;
  file_hash?: string;
  file_name?: string;
  file_size?: number;
  scan_status: string;
  threat_level: string;
  threat_type?: string;
  detection_reason?: string;
  threats_found: number;
  files_checked: number;
  duration_ms: number;
  source: string;
  scanned_at: string;
  created_at: string;
  updated_at: string;
}

export interface AlertRecord {
  id: string;
  threat_type: string;
  severity: string;
  category?: string;
  target?: string;
  source_application?: string;
  detection_reason: string;
  recommended_action?: string;
  is_read: number;
  scanned_at: string;
  created_at: string;
  read_at?: string;
}

export interface SettingRecord {
  key: string;
  value: string;
  updated_at: string;
}