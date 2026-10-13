/**
 * CLI: apply pending database migrations.
 *
 *   npm run migrate
 */
import { getEnv } from '../config/env';
import { createDatabase } from './index';

async function main(): Promise<void> {
  const env = getEnv();
  const db = await createDatabase(env);
  // createDatabase already migrates; report the dialect we connected to.
  const { rows } = await db.query<{ id: string; applied_at: string }>(
    'SELECT id, applied_at FROM schema_migrations ORDER BY id',
  );
  console.log(`Database: ${db.dialect}`);
  console.log(`Applied migrations (${rows.length}):`);
  for (const row of rows) {
    console.log(`  - ${row.id}  (${row.applied_at})`);
  }
  await db.close();
}

main().catch((error) => {
  console.error('Migration failed:', error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
