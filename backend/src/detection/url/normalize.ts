/**
 * URL normalisation.
 *
 * Normalisation is best-effort and *never* widens what we would fetch: the
 * original string is always preserved and reported back to the user, and only
 * http/https URLs are ever eligible for external reputation lookups.
 */

export interface NormalizedUrl {
  original: string;
  /** Canonical serialisation used for caching and comparison. */
  canonical: string;
  protocol: string;
  host: string;
  /** Registrable domain as best we can determine (see registrableDomain). */
  domain: string;
  port: number;
  path: string;
  query: string;
  fragment: string;
  /** True for http/https only. */
  isWeb: boolean;
  /** Decoded ASCII host, exposing any punycode for inspection. */
  asciiHost: string;
  /** Unicode form of the host, if it differs from the ASCII form. */
  unicodeHost: string;
  isIpLiteral: boolean;
  hasUserInfo: boolean;
}

const DEFAULT_PORTS: Record<string, number> = { 'http:': 80, 'https:': 443 };

export class InvalidUrlError extends Error {
  readonly input: string;
  constructor(input: string, reason: string) {
    super(reason);
    this.name = 'InvalidUrlError';
    this.input = input;
  }
}

/**
 * A deliberately small public-suffix list. It is NOT complete – the docs call
 * this out – but it covers the suffixes that actually matter for phishing
 * analysis on the common multi-label registries. Anything else falls back to
 * the last two labels.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'me.uk',
  'net.uk',
  'sch.uk',
  'co.jp',
  'or.jp',
  'ne.jp',
  'ac.jp',
  'go.jp',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'co.nz',
  'net.nz',
  'org.nz',
  'govt.nz',
  'co.in',
  'net.in',
  'org.in',
  'gen.in',
  'firm.in',
  'gov.in',
  'ac.in',
  'edu.in',
  'co.za',
  'org.za',
  'net.za',
  'gov.za',
  'com.br',
  'net.br',
  'org.br',
  'gov.br',
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'com.mx',
  'com.tr',
  'com.sg',
  'com.hk',
  'com.tw',
  'com.my',
  'com.pk',
  'com.bd',
  'com.ng',
  'com.eg',
  'com.sa',
  'com.ar',
  'com.co',
  'co.kr',
  'or.kr',
  'co.id',
  'co.th',
  'co.il',
  'com.ph',
  'com.vn',
  'com.ua',
  'com.pl',
  'github.io',
  'appspot.com',
]);

export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host.length === 0) return host;
  if (isIpLiteral(host)) return host;

  const labels = host.split('.');
  if (labels.length <= 2) return host;

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

export function isIpLiteral(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) return true; // IPv4
  if (bare.includes(':')) return true; // IPv6 (loose but adequate for flagging)
  return false;
}

function decodePunycodeHost(host: string): string {
  try {
    // WHATWG URL already stores the ASCII form; `domainToUnicode` lives in
    // node:url and gives us the readable form for homograph display.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { domainToUnicode } = require('node:url') as typeof import('node:url');
    return domainToUnicode(host);
  } catch {
    return host;
  }
}

/**
 * Normalise an arbitrary string into a URL we can reason about.
 * Throws `InvalidUrlError` when the input cannot be a web URL at all.
 */
export function normalizeUrl(raw: string): NormalizedUrl {
  const trimmed = (raw ?? '').trim();
  if (trimmed.length === 0) throw new InvalidUrlError(raw, 'Empty URL');
  if (trimmed.length > 2048) throw new InvalidUrlError(raw, 'URL is too long');
  if (/[\s\u0000-\u001f]/.test(trimmed)) {
    throw new InvalidUrlError(raw, 'URL contains whitespace or control characters');
  }

  // A scheme is required for us to have an opinion about the protocol.
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(trimmed);
  const scheme = schemeMatch?.[1]?.toLowerCase();

  let candidate = trimmed;
  if (!scheme) {
    // Bare host or host/path: assume https for analysis purposes.
    candidate = `https://${trimmed}`;
  } else if (scheme !== 'http' && scheme !== 'https' && scheme !== 'ftp' && !trimmed.startsWith(`${scheme}://`)) {
    // e.g. `javascript:alert(1)` or `data:text/html,…` – keep as-is.
    candidate = trimmed;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new InvalidUrlError(raw, 'Not a valid URL');
  }

  const protocol = url.protocol.toLowerCase();
  const isWeb = protocol === 'http:' || protocol === 'https:';
  const defaultPort = DEFAULT_PORTS[protocol] ?? 0;
  const host = url.hostname.toLowerCase();

  if (isWeb && host.length === 0) throw new InvalidUrlError(raw, 'URL has no host');

  const canonical = (() => {
    if (!isWeb) return url.toString();
    const portPart = url.port && Number(url.port) !== defaultPort ? `:${url.port}` : '';
    const path = url.pathname === '' ? '/' : url.pathname;
    return `${protocol}//${host}${portPart}${path}${url.search}`;
  })();

  const asciiHost = host;
  const unicodeHost = asciiHost.includes('xn--') ? decodePunycodeHost(asciiHost) : asciiHost;

  return {
    original: trimmed,
    canonical,
    protocol,
    host,
    domain: registrableDomain(host),
    port: url.port ? Number(url.port) : defaultPort,
    path: url.pathname,
    query: url.search,
    fragment: url.hash,
    isWeb,
    asciiHost,
    unicodeHost,
    isIpLiteral: isIpLiteral(host),
    hasUserInfo: url.username.length > 0 || url.password.length > 0,
  };
}

/** Best-effort extraction of every URL present in a blob of text. */
export function extractUrls(text: string): string[] {
  const matches = text.match(/\b(?:https?:\/\/|www\.)[^\s<>"'()]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[^\s<>"'()]*)?/gi);
  if (!matches) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const match of matches) {
    const cleaned = match.replace(/[.,;:!?)\]]+$/, '');
    if (cleaned.length < 4) continue;
    if (seen.has(cleaned.toLowerCase())) continue;
    seen.add(cleaned.toLowerCase());
    out.push(cleaned);
  }
  return out;
}
