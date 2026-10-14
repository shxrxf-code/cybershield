/**
 * @format
 */
/* eslint-env jest */

/**
 * Tests the merge between the local engine result and the optional reputation
 * lookup. Both the native module and the API client are mocked, so these tests
 * verify the logic in `useFileScanner` itself — especially that a failed or
 * disabled reputation lookup never turns into a "Safe" verdict.
 */

jest.mock('../src/native/FileScannerNative', () => ({
  scanFile: jest.fn(),
}));

jest.mock('../src/api/client', () => ({
  scanFileHash: jest.fn(),
}));

import { scanFile } from '../src/native/FileScannerNative';
import { scanFileHash } from '../src/api/client';
import { inspectFile } from '../src/hooks/useFileScanner';
import type { NativeFileScanResult } from '../src/native/FileScannerNative';

const scanFileMock = scanFile as jest.MockedFunction<typeof scanFile>;
const scanFileHashMock = scanFileHash as jest.MockedFunction<typeof scanFileHash>;

function engineResult(overrides: {
  status: NativeFileScanResult['scanResult']['status'];
  findings?: NativeFileScanResult['scanResult']['findings'];
}): NativeFileScanResult {
  return {
    uri: 'content://test/file',
    fileName: 'sample.pdf',
    fileSize: 1024,
    mimeType: 'application/pdf',
    extension: 'pdf',
    magicType: 'pdf',
    sha256: 'a'.repeat(64),
    truncated: false,
    durationMs: 12,
    scanResult: {
      status: overrides.status,
      details: 'details',
      findings: overrides.findings ?? [],
      threats: (overrides.findings ?? []).map((f) => f.code),
      truncated: false,
    },
  };
}

describe('inspectFile', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('reports a local signature match as MALICIOUS without a lookup', async () => {
    scanFileMock.mockResolvedValue(
      engineResult({
        status: 'threat',
        findings: [{ code: 'EICAR_TEST_FILE', message: 'EICAR', severity: 'high' }],
      }),
    );

    const outcome = await inspectFile('content://test/file', false);

    expect(outcome.verdict).toBe('MALICIOUS');
    expect(outcome.reputation).toBe('skipped');
    expect(scanFileHashMock).not.toHaveBeenCalled();
  });

  it('leaves a locally-clean file UNVERIFIED when reputation is off', async () => {
    scanFileMock.mockResolvedValue(engineResult({ status: 'clean' }));

    const outcome = await inspectFile('content://test/file', false);

    expect(outcome.verdict).toBe('UNKNOWN');
    expect(outcome.reputation).toBe('skipped');
    expect(scanFileHashMock).not.toHaveBeenCalled();
  });

  it('adopts an authoritative SAFE verdict when the lookup succeeds', async () => {
    scanFileMock.mockResolvedValue(engineResult({ status: 'clean' }));
    scanFileHashMock.mockResolvedValue({
      id: 'id',
      scanType: 'file',
      target: 'a'.repeat(64),
      status: 'completed',
      threatLevel: 'SAFE',
      detectionReason: 'Known clean',
      scannedAt: new Date().toISOString(),
    });

    const outcome = await inspectFile('content://test/file', true);

    expect(scanFileHashMock).toHaveBeenCalledWith({ hash: 'a'.repeat(64) });
    expect(outcome.verdict).toBe('SAFE');
    expect(outcome.reputation).toBe('checked');
    expect(outcome.reputationReason).toBe('Known clean');
  });

  it('falls back to UNKNOWN and flags the service when the lookup fails', async () => {
    scanFileMock.mockResolvedValue(engineResult({ status: 'clean' }));
    scanFileHashMock.mockRejectedValue(new Error('network down'));

    const outcome = await inspectFile('content://test/file', true);

    expect(outcome.verdict).toBe('UNKNOWN');
    expect(outcome.reputation).toBe('unavailable');
  });

  it('keeps a local suspicious finding even if the service says SAFE', async () => {
    scanFileMock.mockResolvedValue(
      engineResult({
        status: 'suspicious',
        findings: [{ code: 'PDF_JAVASCRIPT', message: 'JS', severity: 'medium' }],
      }),
    );
    scanFileHashMock.mockResolvedValue({
      id: 'id',
      scanType: 'file',
      target: 'a'.repeat(64),
      status: 'completed',
      threatLevel: 'SAFE',
      scannedAt: new Date().toISOString(),
    });

    const outcome = await inspectFile('content://test/file', true);

    expect(outcome.verdict).toBe('SUSPICIOUS');
    expect(outcome.findings).toHaveLength(1);
  });
});
