/**
 * A small, dependency-free web-address parser.
 *
 * React Native's built-in `URL` implementation is incomplete, so we do the
 * syntax work ourselves. This is deliberately conservative: it extracts the
 * pieces we can be sure about and reports a clear reason when the input is not
 * a usable http(s) address. It performs no network access and makes no
 * judgement about whether a link is safe — that is the reputation layer's job.
 */

export interface ParsedUrl {
  scheme: 'http' | 'https';
  host: string;
  port?: string;
  path: string;
  query?: string;
}

export interface UrlParseResult {
  ok: boolean;
  /** A user-facing reason when `ok` is false. */
  reason?: string;
  url?: ParsedUrl;
}

const URL_PATTERN = /^(?:([a-zA-Z][a-zA-Z0-9+.-]*):\/\/)?([^/?#\s]+)(\/[^?#\s]*)?(?:\?([^#\s]*))?/;

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** True when `host` looks like a hostname or IPv4 address. */
function isPlausibleHost(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  if (host === 'localhost') return true;
  if (IPV4.test(host)) return true;
  // A hostname needs at least one dot and valid label characters.
  if (!host.includes('.')) return false;
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host);
}

/** A leading `token:` that is a URI scheme rather than a `host:port` pair. */
function readLeadingScheme(value: string): { scheme: string; rest: string } | null {
  const bare = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(value);
  if (!bare) return null;
  const scheme = bare[1].toLowerCase();
  const rest = bare[2] ?? '';
  // A digits-only tail after the colon (`localhost:3000`) is a port, and a dot
  // in the token (`example.com:443`) makes it a host — neither is a scheme.
  const looksLikePort = /^\d{1,5}([/?#]|$)/.test(rest);
  if (scheme.includes('.') || looksLikePort) return null;
  return { scheme, rest };
}

export function parseWebUrl(input: string): UrlParseResult {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return { ok: false, reason: 'Enter a web address to check.' };
  }
  if (/\s/.test(trimmed)) {
    return { ok: false, reason: 'A web address cannot contain spaces.' };
  }

  // Reject non-web schemes up front (javascript:, data:, intent:, mailto: …)
  // and normalise a bare http(s) scheme to the `scheme://` form we parse below.
  let working = trimmed;
  const leading = readLeadingScheme(trimmed);
  if (leading) {
    if (leading.scheme !== 'http' && leading.scheme !== 'https') {
      return {
        ok: false,
        reason: `Only http and https links can be checked (found "${leading.scheme}").`,
      };
    }
    working = leading.rest.startsWith('//')
      ? `${leading.scheme}:${leading.rest}`
      : `${leading.scheme}://${leading.rest}`;
  }

  const match = URL_PATTERN.exec(working);
  if (!match) {
    return { ok: false, reason: 'That does not look like a web address.' };
  }

  const scheme = (match[1] ?? 'https').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return { ok: false, reason: `Only http and https links can be checked (found "${scheme}").` };
  }

  const authority = match[2] ?? '';
  // Drop any userinfo ("user:pass@host") — it is never part of the host.
  const atIndex = authority.lastIndexOf('@');
  const hostPort = atIndex >= 0 ? authority.slice(atIndex + 1) : authority;

  let host = hostPort;
  let port: string | undefined;
  const colon = hostPort.lastIndexOf(':');
  if (colon > 0 && hostPort.indexOf(']') < colon) {
    host = hostPort.slice(0, colon);
    port = hostPort.slice(colon + 1);
    if (!/^\d{1,5}$/.test(port)) {
      return { ok: false, reason: 'The port in that address is not valid.' };
    }
  }

  host = host.toLowerCase();
  if (!isPlausibleHost(host)) {
    return { ok: false, reason: `"${host}" is not a valid host name.` };
  }

  const path = match[3] && match[3].length > 0 ? match[3] : '/';
  const query = match[4] && match[4].length > 0 ? match[4] : undefined;

  const url: ParsedUrl = { scheme, host, path };
  if (port !== undefined) url.port = port;
  if (query !== undefined) url.query = query;

  return { ok: true, url };
}

/** A compact, human-readable host:path for result rows. */
export function formatParsedUrl(parsed: ParsedUrl): string {
  const port = parsed.port ? `:${parsed.port}` : '';
  return `${parsed.host}${port}${parsed.path}`;
}
