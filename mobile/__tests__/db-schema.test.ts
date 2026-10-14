/* eslint-env jest */
import { MIGRATIONS, SCHEMA_SQL, splitSqlStatements } from '../src/db/schema';

/**
 * The migration runner hands each returned statement to op-sqlite one at a
 * time, so a statement that is cut in half is a hard failure at app start
 * ("incomplete input"). These tests pin the splitting rules that make that
 * impossible.
 */
describe('splitSqlStatements', () => {
  it('keeps a CREATE TRIGGER body in one piece', () => {
    const sql = [
      'CREATE TRIGGER IF NOT EXISTS scans_updated_at',
      'AFTER UPDATE ON scans',
      'BEGIN',
      "  UPDATE scans SET updated_at = datetime('now') WHERE id = NEW.id;",
      'END;',
    ].join('\n');

    const statements = splitSqlStatements(sql);

    expect(statements).toHaveLength(1);
    expect(statements[0]).toMatch(/END$/);
  });

  it('does not split on a semicolon inside a string literal', () => {
    expect(splitSqlStatements("INSERT INTO settings VALUES ('a;b');")).toHaveLength(1);
  });

  it('ignores semicolons in line comments', () => {
    expect(splitSqlStatements('-- a; b; c\nSELECT 1;')).toEqual(['SELECT 1']);
  });

  it('splits independent statements and drops empties', () => {
    expect(splitSqlStatements('SELECT 1; SELECT 2;')).toEqual(['SELECT 1', 'SELECT 2']);
    expect(splitSqlStatements('  ;\n\n;  ')).toEqual([]);
  });

  it('handles an escaped quote without swallowing the terminator', () => {
    const statements = splitSqlStatements("INSERT INTO t VALUES ('it''s; fine'); SELECT 2;");
    expect(statements).toHaveLength(2);
    expect(statements[1]).toBe('SELECT 2');
  });

  it('never leaves a statement with unbalanced BEGIN/END', () => {
    for (const migration of MIGRATIONS) {
      for (const statement of splitSqlStatements(migration.sql)) {
        const begins = (statement.match(/\bBEGIN\b/gi) ?? []).length;
        const ends = (statement.match(/\bEND\b/gi) ?? []).length;
        expect({ statement, begins, ends }).toMatchObject({ begins: ends });
      }
    }
  });
});

describe('schema script', () => {
  it('splits the initial schema into its 3 tables, 8 indexes and 2 triggers', () => {
    const statements = splitSqlStatements(SCHEMA_SQL);
    const count = (pattern: RegExp) =>
      statements.filter((statement) => pattern.test(statement)).length;

    expect(count(/^CREATE TABLE\b/i)).toBe(3);
    expect(count(/^CREATE INDEX\b/i)).toBe(8);
    expect(count(/^CREATE TRIGGER\b/i)).toBe(2);
    expect(statements).toHaveLength(13);
  });
});
