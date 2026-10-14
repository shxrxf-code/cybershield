/**
 * @format
 */
/* eslint-env jest */

import {
  findingLabel,
  findingTone,
  localStatusToVerdict,
  mergeVerdict,
  reputationLabel,
  reputationTone,
  scanStatusLabel,
  scanStatusTone,
} from '../src/domain/fileScan';
import {
  describeFileScannerError,
  isFileScannerAvailable,
  isPickCancelled,
  type ScanFinding,
} from '../src/native/FileScannerNative';

describe('localStatusToVerdict', () => {
  it('treats a signature match as malicious', () => {
    expect(localStatusToVerdict('threat')).toBe('MALICIOUS');
  });

  it('treats a heuristic finding as suspicious', () => {
    expect(localStatusToVerdict('suspicious')).toBe('SUSPICIOUS');
  });

  it('never reports a locally clean file as safe', () => {
    // A local scan that finds nothing proves nothing; only a reputation
    // service may lift a file to SAFE.
    expect(localStatusToVerdict('clean')).toBe('UNKNOWN');
  });

  it('treats a failed scan as unverified', () => {
    expect(localStatusToVerdict('error')).toBe('UNKNOWN');
  });
});

describe('mergeVerdict', () => {
  it('keeps the local verdict when the reputation check was skipped', () => {
    expect(mergeVerdict('UNKNOWN', 'skipped', undefined)).toBe('UNKNOWN');
  });

  it('keeps the local verdict when the reputation service was unavailable', () => {
    expect(mergeVerdict('UNKNOWN', 'unavailable', undefined)).toBe('UNKNOWN');
  });

  it('adopts an authoritative SAFE verdict for a locally-clean file', () => {
    expect(mergeVerdict('UNKNOWN', 'checked', 'SAFE')).toBe('SAFE');
  });

  it('lets the reputation service escalate a locally-clean file', () => {
    expect(mergeVerdict('UNKNOWN', 'checked', 'MALICIOUS')).toBe('MALICIOUS');
  });

  it('never lets a remote SAFE downgrade a local finding', () => {
    expect(mergeVerdict('SUSPICIOUS', 'checked', 'SAFE')).toBe('SUSPICIOUS');
    expect(mergeVerdict('MALICIOUS', 'checked', 'SAFE')).toBe('MALICIOUS');
  });
});

describe('finding presentation', () => {
  const finding = (code: string, severity: ScanFinding['severity'] = 'medium'): ScanFinding => ({
    code,
    message: `${code} message`,
    severity,
  });

  it('uses a friendly label for known finding codes', () => {
    expect(findingLabel(finding('PDF_JAVASCRIPT'))).toBe('Embedded JavaScript');
    expect(findingLabel(finding('EICAR_TEST_FILE', 'high'))).toBe(
      'EICAR anti-malware test signature',
    );
  });

  it('falls back to the engine message for unknown codes', () => {
    expect(findingLabel(finding('SOMETHING_NEW'))).toBe('SOMETHING_NEW message');
  });

  it('maps severity to a tone', () => {
    expect(findingTone('high')).toBe('malicious');
    expect(findingTone('medium')).toBe('suspicious');
    expect(findingTone('low')).toBe('info');
    expect(findingTone('info')).toBe('unknown');
  });
});

describe('scan status presentation', () => {
  it('does not paint a clean local result as safe', () => {
    expect(scanStatusTone('clean')).toBe('unknown');
    expect(scanStatusLabel('clean')).toBe('No known signatures');
  });

  it('paints threats and errors distinctly', () => {
    expect(scanStatusTone('threat')).toBe('malicious');
    expect(scanStatusTone('error')).toBe('info');
    expect(scanStatusLabel('threat')).toBe('Threat detected');
  });
});

describe('reputation presentation', () => {
  it('labels each reputation state', () => {
    expect(reputationLabel('checked')).toBe('Reputation checked');
    expect(reputationLabel('unavailable')).toBe('Reputation service unavailable');
    expect(reputationLabel('skipped')).toBe('Reputation check off');
  });

  it('flags an unavailable service rather than hiding it', () => {
    expect(reputationTone('unavailable')).toBe('suspicious');
    expect(reputationTone('checked')).toBe('info');
  });
});

describe('native bridge helpers', () => {
  it('reports the native module as unavailable in the Jest environment', () => {
    // The Android module is not present in unit tests, so availability is false
    // and every helper must degrade safely instead of throwing.
    expect(isFileScannerAvailable()).toBe(false);
  });

  it('maps known error codes to friendly messages', () => {
    expect(describeFileScannerError({ code: 'E_FILE_TOO_LARGE' })).toBe(
      'That file is larger than the scan limit.',
    );
    expect(describeFileScannerError({ code: 'E_CANCELLED' })).toBe('The scan was cancelled.');
  });

  it('passes through an unknown but explicit message', () => {
    expect(describeFileScannerError({ code: 'E_OTHER', message: 'boom' })).toBe('boom');
  });

  it('falls back to a generic message for anything else', () => {
    expect(describeFileScannerError(undefined)).toMatch(/went wrong/i);
  });

  it('treats a dismissed picker as a normal outcome', () => {
    expect(isPickCancelled({ code: 'E_PICK_CANCELLED' })).toBe(true);
    expect(isPickCancelled({ code: 'E_PICK_EMPTY' })).toBe(true);
    expect(isPickCancelled({ code: 'E_SCAN_FAILED' })).toBe(false);
    expect(isPickCancelled(undefined)).toBe(false);
  });
});
