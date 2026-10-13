import { analyzeScamText, analyzeTextAsSource } from '../src/detection/text/scam';

describe('analyzeScamText', () => {
  it('flags the canonical bank-phishing notification', () => {
    const result = analyzeScamText({
      text: 'Your bank account will be blocked. Verify immediately: suspicious-example.com',
      sourceApp: 'WhatsApp',
    });
    expect(result.status).toBe('SUSPICIOUS');
    expect(result.score).toBeGreaterThanOrEqual(30);
    expect(result.urls.some((u) => u.includes('suspicious-example.com'))).toBe(true);
    const codes = result.reasons.map((r) => r.code);
    expect(codes).toContain('text-urgency');
    expect(codes).toContain('text-threat');
    expect(codes).toContain('text-contains-link');
  });

  it('leaves an ordinary message alone', () => {
    const result = analyzeScamText({ text: 'Hey, still on for dinner at 8?', sourceApp: 'WhatsApp' });
    expect(result.status).toBe('UNKNOWN');
    expect(result.reasons).toEqual([]);
  });

  it('does not flag a legitimate one-time-password message', () => {
    const result = analyzeScamText({
      text: 'Your OTP is 4821. Do not share it with anyone. -Your Bank',
      sourceApp: 'SMS',
    });
    expect(result.status).toBe('UNKNOWN');
  });

  it('flags a request to send an OTP', () => {
    const result = analyzeScamText({ text: 'Please share your OTP to complete verification.' });
    expect(result.reasons.map((r) => r.code)).toContain('text-credential-request');
  });

  it('flags a prize scam with urgency', () => {
    const result = analyzeScamText({
      text: 'Congratulations! You have won a prize of Rs 50,000. Claim now within 24 hours!',
    });
    expect(result.status).toBe('SUSPICIOUS');
    const codes = result.reasons.map((r) => r.code);
    expect(codes).toContain('text-reward');
    expect(codes).toContain('text-urgency');
  });

  it('flags a crypto payment request', () => {
    const result = analyzeScamText({
      text: 'Send 0.5 BTC to this wallet address to unlock your funds.',
    });
    expect(result.reasons.map((r) => r.code)).toContain('text-payment-request');
  });

  it('handles empty input safely', () => {
    const result = analyzeScamText({ text: '' });
    expect(result.status).toBe('UNKNOWN');
    expect(result.score).toBe(0);
  });
});

describe('analyzeTextAsSource', () => {
  it('produces a verdict source carrying the local-text-heuristics id', () => {
    const source = analyzeTextAsSource({
      text: 'Your account will be suspended. Update your KYC now: http://fake-bank.tk/kyc',
    });
    expect(source.source).toBe('local-text-heuristics');
    expect(source.status).toBe('SUSPICIOUS');
    expect(source.categories).toContain('scam');
  });
});
