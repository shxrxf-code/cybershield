import type { DetectionReason, SourceResult } from '../../domain/verdict';
import { registrableDomain, type NormalizedUrl } from './normalize';

/**
 * Local, offline URL heuristics.
 *
 * IMPORTANT: this analyzer returns `UNKNOWN` when it finds nothing, never
 * `SAFE`. Heuristics can raise suspicion, but only an authoritative reputation
 * source (Safe Browsing / URLhaus / VirusTotal) or a local known-bad signature
 * may declare a URL clean. This is what stops "we did not detect anything" from
 * being reported to the user as "this is safe".
 */

interface Heuristic {
  code: string;
  message: string;
  weight: number;
  severity: DetectionReason['severity'];
  test: (ctx: HeuristicContext) => boolean;
}

interface HeuristicContext {
  url: NormalizedUrl;
  sld: string; // second-level label of the registrable domain
  hostLabels: string[];
  pathAndQuery: string;
  decodedPath: string;
}

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'link', 'work', 'buzz', 'rest', 'quest',
  'monster', 'sbs', 'cfd', 'icu', 'cam', 'zip', 'mov', 'review', 'country', 'kim', 'loan',
  'download', 'racing', 'win', 'bid', 'stream', 'gdn', 'men', 'party', 'date', 'faith',
  'science', 'cricket', 'accountant', 'agency', 'digital',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 'bit.do', 'adf.ly', 't.ly', 's.id', 'clck.ru',
  'shorte.st', 'lnkd.in', 'db.tt', 'qr.ae', 'u.to', 'v.gd',
]);

const DANGEROUS_EXTENSIONS = [
  'exe', 'apk', 'scr', 'bat', 'cmd', 'msi', 'jar', 'vbs', 'hta', 'ps1', 'dll',
  'com', 'pif', 'cpl', 'js', 'jse', 'wsf', 'wsh', 'lnk', 'reg', 'iso', 'img',
];

const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'account', 'secure', 'update',
  'confirm', 'password', 'billing', 'invoice', 'payment', 'wallet', 'recovery', 'unlock',
  'suspended', 'alert', 'bank', 'otp', 'kyc', 'refund', 'unlock', 'validate', 'authorize',
];

/**
 * Brands commonly impersonated, mapped to the registrable domains that are
 * genuinely theirs. A brand token appearing on any other registrable domain is
 * treated as impersonation.
 */
const PROTECTED_BRANDS: Record<string, string[]> = {
  paypal: ['paypal.com', 'paypal.me'],
  apple: ['apple.com', 'icloud.com'],
  google: ['google.com', 'google.co.uk', 'gmail.com', 'youtube.com', 'googleusercontent.com'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazonaws.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com', 'meta.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  telegram: ['telegram.org', 't.me', 'telegram.me'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  chase: ['chase.com'],
  hsbc: ['hsbc.com', 'hsbc.co.uk', 'hsbc.com.au'],
  'bank of america': ['bankofamerica.com'],
  bankofamerica: ['bankofamerica.com'],
  wellsfargo: ['wellsfargo.com'],
  dhl: ['dhl.com'],
  fedex: ['fedex.com'],
  usps: ['usps.com'],
  linkedin: ['linkedin.com'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  roblox: ['roblox.com'],
  discord: ['discord.com', 'discord.gg'],
  spotify: ['spotify.com'],
  alibaba: ['alibaba.com'],
  sbi: ['onlinesbi.sbi', 'sbi.co.in', 'sbicard.com'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  gpay: ['google.com'],
  netbanking: [],
};

const BRAND_TOKENS = Object.keys(PROTECTED_BRANDS);

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        (current[j - 1] ?? 0) + 1,
        (previous[j] ?? 0) + 1,
        (previous[j - 1] ?? 0) + cost,
      );
    }
    previous = current;
  }
  return previous[b.length] ?? Math.max(a.length, b.length);
}

function looksBrandImpersonating(
  domain: string,
  hostLabels: string[],
  token: string,
  allowed: string[],
): boolean {
  if (allowed.some((allowedDomain) => domain === allowedDomain || domain.endsWith(`.${allowedDomain}`))) {
    return false;
  }
  const sld = domain.split('.')[0] ?? '';

  // A whole host label equal to the brand is the classic
  // `paypal.com.secure-login.tk` construction.
  if (hostLabels.some((label) => label === token)) return true;

  // Otherwise look for the token at a word boundary inside the registrable
  // domain's own label (`paypal-login`, `login-paypal`, `paypal123`). A plain
  // substring match is intentionally NOT enough, so words like "pineapple"
  // do not trip the rule.
  const boundary = new RegExp(`(^|[^a-z0-9])${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z]|$)`);
  if (boundary.test(sld)) return true;

  // Typosquatting: a single-character edit from the brand, restricted so
  // ordinary words are not swept up (`stream` must not flag `steam`).
  if (token.length >= 5 && Math.abs(sld.length - token.length) === 1) {
    const longer = sld.length > token.length ? sld : token;
    const shorter = sld.length > token.length ? token : sld;
    if (levenshtein(sld, token) === 1 && longer.slice(0, 4) === shorter.slice(0, 4)) return true;
  }
  if (token.length >= 5 && sld.length === token.length && levenshtein(sld, token) === 1) {
    return true;
  }
  return false;
}

function buildHeuristics(): Heuristic[] {
  return [
    {
      code: 'non-web-scheme',
      message: 'The link does not use a normal web address (http or https).',
      weight: 45,
      severity: 'high',
      test: (ctx) => !ctx.url.isWeb,
    },
    {
      code: 'script-scheme',
      message: 'The link tries to run code in the browser instead of opening a website.',
      weight: 60,
      severity: 'high',
      test: (ctx) => ['javascript:', 'data:', 'vbscript:', 'file:'].includes(ctx.url.protocol),
    },
    {
      code: 'ip-literal-host',
      message: 'The link points at a raw IP address rather than a named website.',
      weight: 30,
      severity: 'medium',
      test: (ctx) => ctx.url.isIpLiteral,
    },
    {
      code: 'credentials-in-url',
      message: 'The link hides an account name before the real website address.',
      weight: 45,
      severity: 'high',
      test: (ctx) => ctx.url.hasUserInfo,
    },
    {
      code: 'punycode-host',
      message: 'The website name uses look-alike characters that can imitate a real brand.',
      weight: 45,
      severity: 'high',
      test: (ctx) => ctx.url.asciiHost.includes('xn--'),
    },
    {
      code: 'non-standard-port',
      message: 'The link uses an unusual network port.',
      weight: 12,
      severity: 'low',
      test: (ctx) =>
        ctx.url.isWeb && ctx.url.port !== 80 && ctx.url.port !== 443 && !Number.isNaN(ctx.url.port),
    },
    {
      code: 'suspicious-tld',
      message: 'The website uses a top-level domain frequently abused for scams.',
      weight: 28,
      severity: 'medium',
      test: (ctx) => {
        const tld = ctx.url.host.split('.').pop() ?? '';
        return SUSPICIOUS_TLDS.has(tld.toLowerCase());
      },
    },
    {
      code: 'url-shortener',
      message: 'The link is shortened, so the real destination is hidden.',
      weight: 18,
      severity: 'low',
      test: (ctx) => URL_SHORTENERS.has(ctx.url.domain),
    },
    {
      code: 'excessive-subdomains',
      message: 'The link is buried under an unusually large number of sub-domains.',
      weight: 15,
      severity: 'low',
      test: (ctx) => ctx.hostLabels.length - ctx.url.domain.split('.').length >= 3,
    },
    {
      code: 'hyphen-heavy-domain',
      message: 'The website name contains an unusual number of hyphens.',
      weight: 18,
      severity: 'low',
      test: (ctx) => (ctx.sld.match(/-/g)?.length ?? 0) >= 3,
    },
    {
      code: 'numeric-domain',
      message: 'The website name is mostly numbers, which is uncommon for real brands.',
      weight: 20,
      severity: 'medium',
      test: (ctx) => {
        const digits = (ctx.sld.match(/\d/g)?.length ?? 0);
        return ctx.sld.length >= 6 && digits / ctx.sld.length >= 0.4;
      },
    },
    {
      code: 'high-entropy-domain',
      message: 'The website name looks randomly generated.',
      weight: 22,
      severity: 'medium',
      test: (ctx) =>
        ctx.sld.length >= 12 && shannonEntropy(ctx.sld) >= 3.7 && !/[aeiou]{2}/.test(ctx.sld),
    },
    {
      code: 'brand-impersonation',
      message: 'The link imitates a well-known brand but is not hosted on that brand’s real website.',
      weight: 55,
      severity: 'high',
      test: (ctx) =>
        BRAND_TOKENS.some((token) =>
          looksBrandImpersonating(ctx.url.domain, ctx.hostLabels, token, PROTECTED_BRANDS[token] ?? []),
        ),
    },
    {
      code: 'sensitive-keywords',
      message: 'The link uses words commonly found in phishing, such as “verify” or “account”.',
      weight: 20,
      severity: 'medium',
      test: (ctx) => {
        const inHost = SENSITIVE_KEYWORDS.some((word) => ctx.url.host.toLowerCase().includes(word));
        const inPath = SENSITIVE_KEYWORDS.some((word) => ctx.decodedPath.toLowerCase().includes(word));
        return inHost || inPath;
      },
    },
    {
      code: 'dangerous-file-download',
      message: 'The link points directly at a downloadable program or installer.',
      weight: 35,
      severity: 'high',
      test: (ctx) => {
        const extension = /\.([a-z0-9]+)(?:[?#]|$)/i.exec(ctx.url.path)?.[1]?.toLowerCase();
        return extension !== undefined && DANGEROUS_EXTENSIONS.includes(extension);
      },
    },
    {
      code: 'redirect-parameter',
      message: 'The link appears to redirect you to another website.',
      weight: 15,
      severity: 'low',
      test: (ctx) =>
        /[?&](url|redirect|redirect_uri|next|continue|target|dest|destination|goto)=/i.test(
          ctx.url.query,
        ),
    },
    {
      code: 'encoded-characters',
      message: 'The link contains heavily encoded characters, which can hide its real target.',
      weight: 15,
      severity: 'low',
      test: (ctx) => (ctx.pathAndQuery.match(/%[0-9a-f]{2}/gi)?.length ?? 0) >= 6,
    },
    {
      code: 'very-long-url',
      message: 'The link is exceptionally long, a common way to hide the real destination.',
      weight: 10,
      severity: 'info',
      test: (ctx) => ctx.url.original.length > 160,
    },
  ];
}

const HEURISTICS = buildHeuristics();

/**
 * External reputation sources that are allowed to declare a URL clean.
 * Exported so callers can reason about "did anything authoritative answer?".
 */
export const AUTHORITATIVE_URL_SOURCES = [
  'google-safe-browsing',
  'urlhaus',
  'virustotal',
  'local-signature',
] as const;

export function analyzeUrlHeuristics(url: NormalizedUrl): SourceResult {
  const started = Date.now();
  const labels = url.host.split('.').filter(Boolean);
  const pathAndQuery = `${url.path}${url.query}`;
  let decodedPath = url.path;
  try {
    decodedPath = decodeURIComponent(url.path);
  } catch {
    /* leave as-is */
  }

  const ctx: HeuristicContext = {
    url,
    sld: (registrableDomain(url.host).split('.')[0] ?? url.host),
    hostLabels: labels,
    pathAndQuery,
    decodedPath,
  };

  const reasons: DetectionReason[] = [];
  for (const heuristic of HEURISTICS) {
    let hit = false;
    try {
      hit = heuristic.test(ctx);
    } catch {
      hit = false;
    }
    if (hit) {
      reasons.push({
        code: heuristic.code,
        message: heuristic.message,
        weight: heuristic.weight,
        severity: heuristic.severity,
      });
    }
  }

  const totalWeight = reasons.reduce((sum, reason) => sum + reason.weight, 0);
  const status = totalWeight >= 45 ? 'SUSPICIOUS' : 'UNKNOWN';

  return {
    source: 'local-url-heuristics',
    status,
    reasons,
    detail:
      reasons.length === 0
        ? 'No local warning signs found. This is not a clean bill of health on its own.'
        : `${reasons.length} local warning sign(s) detected.`,
    durationMs: Date.now() - started,
  };
}
