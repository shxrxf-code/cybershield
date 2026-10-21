/**
 * Live integration check: runs the REAL mobile API client against the REAL
 * running backend. Proves the request paths, request bodies and response
 * mapping all line up — the thing that was broken before the client fix.
 *
 * Run with the backend up:
 *   cd backend && npx tsx src/server.ts      # in one shell
 *   npx tsx scripts/live-api-check.ts       # in another
 */
globalThis.__DEV__ = true;

const realFetch = globalThis.fetch;
const API_KEY = process.env.THREATGUARD_API_KEY ?? 'dev-key-change-me';

// The client is configured for an emulator (10.0.2.2 == host loopback), so
// rewrite the host to localhost when running the check on the dev machine.
globalThis.fetch = ((input: any, init: any) => {
  const url = typeof input === 'string' ? input : input.url;
  const rewritten = url.replace('http://10.0.2.2:8000', 'http://127.0.0.1:8000');
  const headers = { ...(init?.headers ?? {}), 'X-API-Key': API_KEY };
  return realFetch(rewritten, { ...init, headers });
}) as typeof fetch;

async function main() {
  const { scanUrl, scanFileHash, checkHealth, mapUrlScanToRecord } = await import(
    '../src/api/client'
  );

  const health = await checkHealth();
  console.log('health           :', health.status, '| db', health.database?.client, 'ok=', health.database?.ok);

  const url = await scanUrl({ url: 'https://example.com/login' });
  console.log('scanUrl          :', url.id, '|', url.threatLevel, '|', url.threatType);
  console.log('  target         :', url.target);
  console.log('  scannedAt      :', url.scannedAt);
  console.log('  reason         :', url.detectionReason);
  const record = mapUrlScanToRecord(url);
  console.log('  -> ScanRecord  :', record.scanType, record.threatLevel, 'threatsFound=' + record.threatsFound, 'source=' + record.source);

  const file = await scanFileHash({ hash: 'a'.repeat(64), fileName: 'invoice.pdf', sizeBytes: 2048 });
  console.log('scanFileHash     :', file.id, '|', file.threatLevel);
  console.log('  target         :', file.target.slice(0, 16) + '...');
  console.log('  scannedAt      :', file.scannedAt);
}

main().catch((err) => {
  console.error('FAILED:', err?.message ?? err);
  if (err?.body) console.error('body:', JSON.stringify(err.body));
  process.exit(1);
});
