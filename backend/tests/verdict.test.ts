import {
  mergeVerdicts,
  scoreFromWeights,
  severityFromScore,
  isThreat,
  type SourceResult,
} from '../src/domain/verdict';

function source(partial: Partial<SourceResult> & Pick<SourceResult, 'source' | 'status'>): SourceResult {
  return { reasons: [], ...partial };
}

describe('scoreFromWeights', () => {
  it('is zero with no positive weights', () => {
    expect(scoreFromWeights([])).toBe(0);
    expect(scoreFromWeights([0, 0])).toBe(0);
  });

  it('grows monotonically and saturates below 100', () => {
    const small = scoreFromWeights([10]);
    const medium = scoreFromWeights([40]);
    const large = scoreFromWeights([500]);
    expect(small).toBeLessThan(medium);
    expect(medium).toBeLessThan(large);
    expect(large).toBeLessThanOrEqual(100);
  });
});

describe('severityFromScore', () => {
  it('maps score bands to severities', () => {
    expect(severityFromScore(0)).toBe('info');
    expect(severityFromScore(15)).toBe('low');
    expect(severityFromScore(40)).toBe('medium');
    expect(severityFromScore(60)).toBe('high');
    expect(severityFromScore(90)).toBe('critical');
  });
});

describe('mergeVerdicts', () => {
  it('returns UNKNOWN when nothing answered', () => {
    const merged = mergeVerdicts([]);
    expect(merged.status).toBe('UNKNOWN');
    expect(merged.definitive).toBe(false);
    expect(isThreat(merged.status)).toBe(false);
  });

  it('never turns "heuristics found nothing" into SAFE', () => {
    const merged = mergeVerdicts([source({ source: 'local-url-heuristics', status: 'UNKNOWN' })]);
    expect(merged.status).toBe('UNKNOWN');
    expect(merged.definitive).toBe(false);
  });

  it('honours a heuristic suspicion on its own', () => {
    const merged = mergeVerdicts([
      source({
        source: 'local-url-heuristics',
        status: 'SUSPICIOUS',
        reasons: [{ code: 'punycode-host', message: 'look-alike', weight: 45, severity: 'high' }],
      }),
    ]);
    expect(merged.status).toBe('SUSPICIOUS');
    expect(merged.category).toBe('suspicious');
  });

  it('lets an authoritative SAFE answer produce SAFE', () => {
    const merged = mergeVerdicts([
      source({ source: 'google-safe-browsing', status: 'SAFE' }),
      source({ source: 'local-url-heuristics', status: 'UNKNOWN' }),
    ]);
    expect(merged.status).toBe('SAFE');
    expect(merged.definitive).toBe(true);
  });

  it('lets MALICIOUS win over a SAFE answer', () => {
    const merged = mergeVerdicts([
      source({ source: 'google-safe-browsing', status: 'SAFE' }),
      source({ source: 'urlhaus', status: 'MALICIOUS', categories: ['malware'] }),
    ]);
    expect(merged.status).toBe('MALICIOUS');
    expect(merged.severity).toBe('critical');
    expect(merged.category).toBe('malware');
  });

  it('prefers MALICIOUS over SUSPICIOUS', () => {
    const merged = mergeVerdicts([
      source({ source: 'virustotal', status: 'SUSPICIOUS' }),
      source({ source: 'local-signature', status: 'MALICIOUS' }),
    ]);
    expect(merged.status).toBe('MALICIOUS');
  });

  it('does not treat a degraded provider as an answer', () => {
    const merged = mergeVerdicts([
      source({ source: 'urlhaus', status: 'UNKNOWN', error: 'timeout' }),
    ]);
    expect(merged.status).toBe('UNKNOWN');
  });
});
