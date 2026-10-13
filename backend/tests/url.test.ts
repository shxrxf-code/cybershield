import { normalizeUrl, registrableDomain, extractUrls, InvalidUrlError } from '../src/detection/url/normalize';
import { analyzeUrlHeuristics, shannonEntropy } from '../src/detection/url/heuristics';

describe('registrableDomain', () => {
  it('uses the last two labels for ordinary domains', () => {
    expect(registrableDomain('www.example.com')).toBe('example.com');
    expect(registrableDomain('example.com')).toBe('example.com');
    expect(registrableDomain('localhost')).toBe('localhost');
  });

  it('handles multi-label public suffixes', () => {
    expect(registrableDomain('shop.example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('a.b.example.com.au')).toBe('example.com.au');
  });

  it('keeps IP literals intact', () => {
    expect(registrableDomain('192.168.0.1')).toBe('192.168.0.1');
  });
});

describe('normalizeUrl', () => {
  it('normalises a plain https URL', () => {
    const url = normalizeUrl('https://Example.COM/Path?q=1#frag');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('example.com');
    expect(url.domain).toBe('example.com');
    expect(url.isWeb).toBe(true);
    expect(url.canonical).toBe('https://example.com/Path?q=1');
  });

  it('assumes https for a bare host', () => {
    const url = normalizeUrl('example.com/login');
    expect(url.protocol).toBe('https:');
    expect(url.path).toBe('/login');
  });

  it('exposes punycode and its unicode form', () => {
    const url = normalizeUrl('http://xn--pypal-4ve.com/');
    expect(url.asciiHost).toBe('xn--pypal-4ve.com');
    expect(url.unicodeHost).not.toBe(url.asciiHost);
  });

  it('flags IP literals and userinfo', () => {
    expect(normalizeUrl('http://10.0.0.5/x').isIpLiteral).toBe(true);
    expect(normalizeUrl('http://user:pass@example.com/').hasUserInfo).toBe(true);
  });

  it('keeps non-web schemes but marks them as not web', () => {
    const url = normalizeUrl('javascript:alert(1)');
    expect(url.isWeb).toBe(false);
    expect(url.protocol).toBe('javascript:');
  });

  it('rejects empty and malformed input', () => {
    expect(() => normalizeUrl('   ')).toThrow(InvalidUrlError);
    expect(() => normalizeUrl('http://exa mple.com')).toThrow(InvalidUrlError);
  });
});

describe('extractUrls', () => {
  it('finds URLs and bare domains in message text', () => {
    const urls = extractUrls('Verify now at https://bad.example.com/x and also evil.test/login.');
    expect(urls).toContain('https://bad.example.com/x');
    expect(urls.some((u) => u.startsWith('evil.test'))).toBe(true);
  });

  it('returns nothing for plain prose', () => {
    expect(extractUrls('see you at six o clock')).toEqual([]);
  });
});

describe('analyzeUrlHeuristics', () => {
  const statusFor = (raw: string) => analyzeUrlHeuristics(normalizeUrl(raw));
  const codesFor = (raw: string) => statusFor(raw).reasons.map((r) => r.code);

  it('returns UNKNOWN (never SAFE) when it finds nothing', () => {
    const result = statusFor('https://www.google.com/search?q=weather');
    expect(result.status).toBe('UNKNOWN');
    expect(result.reasons).toEqual([]);
  });

  it('flags a punycode look-alike host', () => {
    expect(codesFor('http://xn--pypal-4ve.com/login')).toContain('punycode-host');
  });

  it('flags an IP-literal host', () => {
    expect(codesFor('http://203.0.113.7/login')).toContain('ip-literal-host');
  });

  it('flags credentials embedded before the host', () => {
    const result = statusFor('http://paypal.com@evil.example/login');
    expect(codesFor('http://paypal.com@evil.example/login')).toContain('credentials-in-url');
    expect(result.status).toBe('SUSPICIOUS');
  });

  it('flags brand impersonation via a planted sub-domain', () => {
    expect(codesFor('http://paypal.com.secure-login.tk/verify')).toContain('brand-impersonation');
  });

  it('flags typosquatted brands', () => {
    expect(codesFor('https://paypa1.com/login')).toContain('brand-impersonation');
  });

  it('does NOT flag the genuine brand domain', () => {
    expect(codesFor('https://www.paypal.com/signin')).not.toContain('brand-impersonation');
  });

  it('does not false-positive on words that merely contain a brand', () => {
    expect(codesFor('https://pineapple.example.com/')).not.toContain('brand-impersonation');
  });

  it('flags a dangerous direct download', () => {
    expect(codesFor('http://files.example.com/setup.exe')).toContain('dangerous-file-download');
  });

  it('flags a javascript: scheme URL', () => {
    const result = statusFor('javascript:alert(document.cookie)');
    expect(result.reasons.map((r) => r.code)).toEqual(
      expect.arrayContaining(['non-web-scheme', 'script-scheme']),
    );
    expect(result.status).toBe('SUSPICIOUS');
  });
});

describe('shannonEntropy', () => {
  it('is zero for a single repeated character and high for random text', () => {
    expect(shannonEntropy('aaaaaa')).toBe(0);
    expect(shannonEntropy('q3x9v7z2')).toBeGreaterThan(2.5);
  });
});
