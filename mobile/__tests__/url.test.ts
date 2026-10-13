/* eslint-env jest */
import { parseWebUrl, formatParsedUrl } from '../src/utils/url';

/**
 * The URL parser is the offline first line of defence for the link checker, so
 * its behaviour is pinned down here: what counts as a well-formed http(s)
 * address, and the exact reason given when it is not.
 */
describe('parseWebUrl', () => {
  it('accepts a plain https URL and returns its parts', () => {
    const result = parseWebUrl('https://example.com/login?next=/home');
    expect(result.ok).toBe(true);
    expect(result.url).toEqual({
      scheme: 'https',
      host: 'example.com',
      path: '/login',
      query: 'next=/home',
    });
  });

  it('assumes https when no scheme is given', () => {
    const result = parseWebUrl('example.com');
    expect(result.ok).toBe(true);
    expect(result.url?.scheme).toBe('https');
    expect(result.url?.host).toBe('example.com');
    expect(result.url?.path).toBe('/');
  });

  it('lowers the case of the host but keeps the path case', () => {
    const result = parseWebUrl('HTTP://EXAMPLE.COM/CaseSensitive');
    expect(result.ok).toBe(true);
    expect(result.url?.host).toBe('example.com');
    expect(result.url?.path).toBe('/CaseSensitive');
  });

  it('extracts and validates a port', () => {
    const result = parseWebUrl('http://example.com:8080/status');
    expect(result.ok).toBe(true);
    expect(result.url?.port).toBe('8080');
  });

  it('accepts an IPv4 host', () => {
    expect(parseWebUrl('http://192.168.0.10/').ok).toBe(true);
  });

  it('accepts localhost', () => {
    expect(parseWebUrl('http://localhost:3000/health').ok).toBe(true);
  });

  it('strips userinfo from the authority', () => {
    const result = parseWebUrl('https://user:pass@example.com/');
    expect(result.ok).toBe(true);
    expect(result.url?.host).toBe('example.com');
  });

  it('rejects an empty input', () => {
    const result = parseWebUrl('   ');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/enter a web address/i);
  });

  it('rejects an address containing a space', () => {
    const result = parseWebUrl('https://exa mple.com');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/cannot contain spaces/i);
  });

  it('rejects a non-http(s) scheme', () => {
    const result = parseWebUrl('javascript:alert(1)');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/only http and https/i);
  });

  it('rejects a host without a dot', () => {
    const result = parseWebUrl('https://notahost');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/not a valid host/i);
  });

  it('rejects a bad port', () => {
    const result = parseWebUrl('https://example.com:99999x/');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/port/i);
  });

  it('never reports a result for an invalid input', () => {
    const result = parseWebUrl('::::');
    expect(result.ok).toBe(false);
    expect(result.url).toBeUndefined();
  });
});

describe('formatParsedUrl', () => {
  it('renders host, port and path together', () => {
    const result = parseWebUrl('http://example.com:8443/a/b');
    expect(result.url).toBeDefined();
    expect(formatParsedUrl(result.url!)).toBe('example.com:8443/a/b');
  });
});
