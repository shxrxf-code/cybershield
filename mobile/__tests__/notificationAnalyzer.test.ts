/**
 * @format
 */
/* eslint-env jest */

import {
  ALERT_THRESHOLD,
  analyzeNotification,
  buildNotificationAlert,
  extractUrls,
  hashNotificationContent,
  redactNotificationText,
  shouldAlert,
  type NotificationContent,
} from '../src/domain/notificationAnalyzer';

function content(overrides: Partial<NotificationContent> = {}): NotificationContent {
  return { packageName: 'com.example.app', ...overrides };
}

describe('extractUrls', () => {
  it('finds links with and without a scheme', () => {
    const urls = extractUrls('Pay here https://paypa1-login.xyz/verify or at www.example.com/pay');
    expect(urls).toContain('https://paypa1-login.xyz/verify');
    expect(urls).toContain('https://www.example.com/pay');
  });

  it('does not mistake prices or plain numbers for links', () => {
    expect(extractUrls('Total is 24.99 and the code is 1234.')).toEqual([]);
  });

  it('finds IPv4-literal links', () => {
    expect(extractUrls('open http://192.168.0.1/admin now')).toContain('http://192.168.0.1/admin');
  });

  it('de-duplicates the same link written twice', () => {
    expect(extractUrls('go to example.com then example.com again')).toHaveLength(1);
  });
});

describe('redactNotificationText', () => {
  it('reduces links to their host', () => {
    const redacted = redactNotificationText('Verify at https://evil.example.co/secure/login?token=abc');
    expect(redacted).toBe('Verify at [link: evil.example.co]');
  });

  it('masks emails and long numbers', () => {
    const redacted = redactNotificationText('Call 555 123 4567 or email a.user+tag@example.com');
    expect(redacted).toContain('[number]');
    expect(redacted).toContain('[email]');
    expect(redacted).not.toContain('a.user+tag@example.com');
  });

  it('strips zero-width characters and collapses whitespace', () => {
    const redacted = redactNotificationText('Win\u200B   big\nnow');
    expect(redacted).toBe('Win big now');
  });

  it('truncates long previews', () => {
    const redacted = redactNotificationText('x'.repeat(300), 50);
    expect(redacted.length).toBeLessThanOrEqual(50);
    expect(redacted.endsWith('…')).toBe(true);
  });
});

describe('hashNotificationContent', () => {
  it('is stable for the same content', () => {
    const input = content({ title: 'Hi', text: 'There' });
    expect(hashNotificationContent(input)).toBe(hashNotificationContent({ ...input }));
  });

  it('changes when the message changes', () => {
    expect(hashNotificationContent(content({ text: 'one' }))).not.toBe(
      hashNotificationContent(content({ text: 'two' })),
    );
  });
});

describe('analyzeNotification', () => {
  it('reports a benign message as UNKNOWN, never SAFE', () => {
    const analysis = analyzeNotification(content({ title: 'Mum', text: 'Dinner at 7pm?' }));
    expect(analysis.verdict.status).toBe('UNKNOWN');
    expect(analysis.score).toBe(0);
    expect(shouldAlert(analysis)).toBe(false);
  });

  it('never returns MALICIOUS from text alone', () => {
    const analysis = analyzeNotification(
      content({
        title: 'ALERT',
        text: 'URGENT! Your account is suspended. Verify your account and share the one-time code now: http://192.168.0.1/verify',
      }),
    );
    expect(analysis.verdict.status).toBe('SUSPICIOUS');
    expect(analysis.verdict.definitive).toBe(false);
  });

  it('flags a credential/OTP phishing message with the right category', () => {
    const analysis = analyzeNotification(
      content({
        title: 'Bank Security',
        text: 'Your account will be blocked. Verify your account and share the verification code at http://secure-kyc-update.top/login',
      }),
    );
    expect(analysis.verdict.status).toBe('SUSPICIOUS');
    expect(analysis.category).toBe('phishing');
    expect(analysis.threatType).toBe('phishing_notification');
    expect(analysis.signals.map((s) => s.code)).toEqual(
      expect.arrayContaining(['TEXT_OTP_REQUEST', 'TEXT_CREDENTIAL_REQUEST', 'URL_SUSPICIOUS_TLD']),
    );
  });

  it('flags an IP-literal link', () => {
    const analysis = analyzeNotification(content({ text: 'Click http://10.0.0.5/bill to pay' }));
    expect(analysis.signals.map((s) => s.code)).toContain('URL_IP_HOST');
  });

  it('detects a brand named in the text but linked elsewhere', () => {
    const analysis = analyzeNotification(
      content({ title: 'PayPal', text: 'Confirm your account at http://paypal-secure.xyz/login' }),
    );
    expect(analysis.signals.map((s) => s.code)).toContain('TEXT_BRAND_LINK_MISMATCH');
  });

  it('does not flag a brand that is linked on its own domain', () => {
    const analysis = analyzeNotification(
      content({ title: 'PayPal', text: 'Your receipt is at https://www.paypal.com/receipt' }),
    );
    expect(analysis.signals.map((s) => s.code)).not.toContain('TEXT_BRAND_LINK_MISMATCH');
  });

  it('flags a gift-card / money scam', () => {
    const analysis = analyzeNotification(
      content({ text: 'Final notice: pay the customs fee with a gift card today' }),
    );
    expect(analysis.verdict.status).toBe('SUSPICIOUS');
    expect(analysis.category).toBe('scam');
  });

  it('flags a lottery scam', () => {
    const analysis = analyzeNotification(
      content({ text: "You've won the jackpot! Claim your prize now, just pay the small processing fee." }),
    );
    expect(analysis.verdict.status).toBe('SUSPICIOUS');
    expect(analysis.category).toBe('scam');
  });

  it('detects hidden zero-width characters', () => {
    const analysis = analyzeNotification(content({ text: 'Login\u200B to your account\u200B' }));
    expect(analysis.signals.map((s) => s.code)).toContain('TEXT_ZERO_WIDTH');
  });

  it('caps the score at 100', () => {
    const analysis = analyzeNotification(
      content({
        title: 'URGENT!!! VERIFY NOW',
        text: 'Your bank account will be blocked. Verify your account, share the OTP and pay the customs fee with a gift card at http://192.168.0.1/verify?x='.padEnd(140, 'a'),
      }),
    );
    expect(analysis.score).toBe(100);
  });

  it('keeps a redacted preview that never contains the link path', () => {
    const analysis = analyzeNotification(
      content({ text: 'Verify at http://evil.example.co/steal/credentials?token=secret' }),
    );
    expect(analysis.redactedPreview).toContain('evil.example.co');
    expect(analysis.redactedPreview).not.toContain('secret');
    expect(analysis.redactedPreview).not.toContain('/steal/credentials');
  });

  it('exposes a single, non-authoritative source', () => {
    const analysis = analyzeNotification(content({ text: 'hello there' }));
    expect(analysis.verdict.sources).toHaveLength(1);
    expect(analysis.verdict.sources[0].source).toBe('local-text-heuristics');
    expect(analysis.verdict.sources[0].status).toBe('UNKNOWN');
  });
});

describe('buildNotificationAlert', () => {
  it('stores a redacted target and never the message body', () => {
    const input = content({
      packageName: 'com.whatsapp',
      appLabel: 'WhatsApp',
      title: 'Bank',
      text: 'Urgent: verify your account at http://evil.example.co/secret-path',
    });
    const analysis = analyzeNotification(input);
    const alert = buildNotificationAlert(input, analysis);
    expect(alert.sourceApplication).toBe('WhatsApp');
    expect(alert.target).not.toContain('secret-path');
    expect(alert.target).toContain('[link: evil.example.co]');
    expect(alert.severity === 'medium' || alert.severity === 'high').toBe(true);
    expect(alert.detectionReason.length).toBeGreaterThan(0);
  });

  it('falls back to the package name when there is no label', () => {
    const input = content({ packageName: 'com.unknown.app', text: 'share the verification code with us' });
    const alert = buildNotificationAlert(input, analyzeNotification(input));
    expect(alert.sourceApplication).toBe('com.unknown.app');
  });
});

describe('thresholds', () => {
  it('only alerts at or above the medium threshold', () => {
    const weak = analyzeNotification(content({ text: 'WIN BIG!!!' }));
    expect(weak.score).toBeLessThan(ALERT_THRESHOLD);
    expect(shouldAlert(weak)).toBe(false);
  });
});
