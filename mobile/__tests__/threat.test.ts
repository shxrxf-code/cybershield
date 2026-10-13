import {
  SEVERITY_ORDER,
  categoryLabel,
  isThreat,
  scanTypeLabel,
  severityLabel,
  severityTone,
  statusLabel,
  statusTone,
  threatTypeLabel,
  toneDotRole,
} from '../src/domain/threat';

describe('verdict wording', () => {
  it('never calls an UNKNOWN verdict "safe"', () => {
    expect(statusLabel('UNKNOWN')).toBe('Unverified');
    expect(statusLabel('UNKNOWN')).not.toBe('Safe');
  });

  it('labels the known verdicts', () => {
    expect(statusLabel('SAFE')).toBe('Safe');
    expect(statusLabel('SUSPICIOUS')).toBe('Suspicious');
    expect(statusLabel('MALICIOUS')).toBe('Malicious');
  });

  it('maps verdicts to tones', () => {
    expect(statusTone('SAFE')).toBe('safe');
    expect(statusTone('SUSPICIOUS')).toBe('suspicious');
    expect(statusTone('MALICIOUS')).toBe('malicious');
    expect(statusTone('UNKNOWN')).toBe('unknown');
  });

  it('flags only suspicious and malicious as threats', () => {
    expect(isThreat('MALICIOUS')).toBe(true);
    expect(isThreat('SUSPICIOUS')).toBe(true);
    expect(isThreat('SAFE')).toBe(false);
    expect(isThreat('UNKNOWN')).toBe(false);
  });
});

describe('severity helpers', () => {
  it('orders severities from most to least serious', () => {
    expect(SEVERITY_ORDER.critical).toBeGreaterThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeGreaterThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeGreaterThan(SEVERITY_ORDER.low);
    expect(SEVERITY_ORDER.low).toBeGreaterThan(SEVERITY_ORDER.info);
  });

  it('maps severity to a tone', () => {
    expect(severityTone('critical')).toBe('malicious');
    expect(severityTone('high')).toBe('suspicious');
    expect(severityTone('medium')).toBe('suspicious');
    expect(severityTone('low')).toBe('info');
    expect(severityTone('info')).toBe('unknown');
  });

  it('labels severities', () => {
    expect(severityLabel('critical')).toBe('Critical');
    expect(severityLabel('info')).toBe('Info');
  });
});

describe('label lookups', () => {
  it('labels known categories', () => {
    expect(categoryLabel('phishing')).toBe('Phishing');
    expect(categoryLabel('unwanted-software')).toBe('Unwanted software');
  });

  it('labels known threat types and falls back to the raw key', () => {
    expect(threatTypeLabel('malicious_url')).toBe('Malicious link');
    expect(threatTypeLabel('some_new_thing')).toBe('some new thing');
  });

  it('labels known scan types and passes unknown ones through', () => {
    expect(scanTypeLabel('url')).toBe('Link check');
    expect(scanTypeLabel('custom')).toBe('custom');
  });
});

describe('toneDotRole', () => {
  it('routes info to the neutral dot colour', () => {
    expect(toneDotRole('info')).toBe('unknown');
  });

  it('passes the concrete roles through unchanged', () => {
    expect(toneDotRole('safe')).toBe('safe');
    expect(toneDotRole('suspicious')).toBe('suspicious');
    expect(toneDotRole('malicious')).toBe('malicious');
    expect(toneDotRole('unknown')).toBe('unknown');
  });
});
