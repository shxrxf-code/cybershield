/**
 * On-device scam / phishing heuristics for notification content.
 *
 * This module is intentionally **pure**: it takes the text Android exposes for
 * a notification and returns a scored analysis. It performs no network access,
 * touches no storage and is fully unit-tested.
 *
 * Two honesty rules shape it:
 *
 *  - Text heuristics can never confirm a message is *safe*. A message with no
 *    signals is `UNKNOWN` ("Unverified"), never `SAFE`.
 *  - Text heuristics can never *prove* malice either. The strongest verdict a
 *    message can reach here is `SUSPICIOUS`; only a reputation service (which we
 *    deliberately do not contact for message content) could escalate further.
 *
 * Privacy: the full message text is analysed in memory and discarded. Only a
 * redacted preview (links reduced to their host, emails and long numbers masked)
 * is ever handed to the caller for storage.
 */

import { parseWebUrl, type ParsedUrl } from '../utils/url';
import type {
  DetectionReason,
  Severity,
  ThreatAlert,
  ThreatCategory,
  Verdict,
} from './types';

/** The subset of a notification that the engine analyses. */
export interface NotificationContent {
  /** Package that posted the notification (e.g. `com.whatsapp`). */
  packageName: string;
  /** Human-readable app label, when the listener could resolve it. */
  appLabel?: string;
  title?: string;
  text?: string;
  /** `subText`, big-text or summary text when present. */
  subText?: string;
  /** ISO timestamp from the notification, when available. */
  postedAt?: string;
  /** The platform notification key, used only for de-duplication. */
  key?: string;
}

export interface AnalyzedUrl {
  /** The URL as it appeared in the message. */
  raw: string;
  host: string;
  /** Reason codes that applied to this URL (see {@link SIGNALS}). */
  reasons: string[];
}

export interface NotificationSignal {
  code: string;
  label: string;
  weight: number;
  category: ThreatCategory;
}

export interface NotificationAnalysis {
  /** 0–100, the sum of matched signal weights (capped). */
  score: number;
  severity: Severity;
  category: ThreatCategory;
  threatType: string;
  signals: NotificationSignal[];
  urls: AnalyzedUrl[];
  recommendedAction: string;
  /** Content-free preview that is safe to persist. */
  redactedPreview: string;
  /** Stable hash of the normalised content, for de-duplication. */
  contentHash: string;
  verdict: Verdict;
}

interface SignalDef {
  code: string;
  label: string;
  weight: number;
  category: ThreatCategory;
}

/** Every signal the engine can raise, with its weight and category. */
const SIGNALS: Record<string, SignalDef> = {
  // --- URL shape -----------------------------------------------------------
  URL_IP_HOST: { code: 'URL_IP_HOST', label: 'Link points at a raw IP address', weight: 25, category: 'phishing' },
  URL_CREDENTIAL_IN_URL: { code: 'URL_CREDENTIAL_IN_URL', label: 'Link hides its real host behind a user-info prefix', weight: 30, category: 'phishing' },
  URL_PUNYCODE: { code: 'URL_PUNYCODE', label: 'Link uses an internationalised (punycode) host', weight: 20, category: 'phishing' },
  URL_SUSPICIOUS_TLD: { code: 'URL_SUSPICIOUS_TLD', label: 'Link uses a frequently abused top-level domain', weight: 18, category: 'phishing' },
  URL_SHORTENER: { code: 'URL_SHORTENER', label: 'Link is shortened so its destination is hidden', weight: 12, category: 'suspicious' },
  URL_MANY_SUBDOMAINS: { code: 'URL_MANY_SUBDOMAINS', label: 'Link uses an unusual number of sub-domains', weight: 15, category: 'phishing' },
  URL_LONG_HOST: { code: 'URL_LONG_HOST', label: 'Link host name is unusually long', weight: 12, category: 'suspicious' },
  URL_NONSTANDARD_PORT: { code: 'URL_NONSTANDARD_PORT', label: 'Link uses a non-standard port', weight: 15, category: 'suspicious' },
  URL_EXCESSIVE_LENGTH: { code: 'URL_EXCESSIVE_LENGTH', label: 'Link is unusually long', weight: 10, category: 'suspicious' },
  URL_HYPHEN_DIGIT_HEAVY: { code: 'URL_HYPHEN_DIGIT_HEAVY', label: 'Link host mixes many hyphens and digits', weight: 10, category: 'suspicious' },

  // --- Credential / OTP theft ---------------------------------------------
  TEXT_OTP_REQUEST: { code: 'TEXT_OTP_REQUEST', label: 'Message asks for a one-time or verification code', weight: 40, category: 'phishing' },
  TEXT_CREDENTIAL_REQUEST: { code: 'TEXT_CREDENTIAL_REQUEST', label: 'Message asks you to confirm login or payment details', weight: 35, category: 'phishing' },
  TEXT_BANK_IMPERSONATION: { code: 'TEXT_BANK_IMPERSONATION', label: 'Message imitates a bank or KYC process', weight: 20, category: 'phishing' },
  TEXT_BRAND_LINK_MISMATCH: { code: 'TEXT_BRAND_LINK_MISMATCH', label: 'Message names a brand but links to a different domain', weight: 25, category: 'phishing' },

  // --- Social engineering --------------------------------------------------
  TEXT_URGENCY: { code: 'TEXT_URGENCY', label: 'Message uses urgency to rush you', weight: 15, category: 'social-engineering' },
  TEXT_THREAT: { code: 'TEXT_THREAT', label: 'Message threatens account loss or legal action', weight: 20, category: 'social-engineering' },
  TEXT_MONEY_REQUEST: { code: 'TEXT_MONEY_REQUEST', label: 'Message asks for a payment or transfer', weight: 25, category: 'scam' },
  TEXT_PRIZE_LOTTERY: { code: 'TEXT_PRIZE_LOTTERY', label: 'Message claims you have won a prize', weight: 25, category: 'scam' },
  TEXT_INVESTMENT_SCAM: { code: 'TEXT_INVESTMENT_SCAM', label: 'Message promises guaranteed investment returns', weight: 22, category: 'scam' },
  TEXT_DELIVERY_SCAM: { code: 'TEXT_DELIVERY_SCAM', label: 'Message claims a parcel is held or needs a fee', weight: 15, category: 'scam' },
  TEXT_JOB_SCAM: { code: 'TEXT_JOB_SCAM', label: 'Message offers easy money for little work', weight: 15, category: 'scam' },

  // --- Presentation tricks -------------------------------------------------
  TEXT_ZERO_WIDTH: { code: 'TEXT_ZERO_WIDTH', label: 'Message contains hidden zero-width characters', weight: 20, category: 'suspicious' },
  TEXT_EXCESSIVE_CAPS: { code: 'TEXT_EXCESSIVE_CAPS', label: 'Message is written mostly in capitals', weight: 5, category: 'suspicious' },
  TEXT_REPEATED_PUNCT: { code: 'TEXT_REPEATED_PUNCT', label: 'Message uses repeated dramatic punctuation', weight: 5, category: 'suspicious' },
};

/** Phrases (lower-cased) that raise a phrase signal when present. */
const PHRASE_SIGNALS: Array<{ code: string; phrases: string[] }> = [
  {
    code: 'TEXT_OTP_REQUEST',
    phrases: [
      'one-time code', 'one time code', 'one-time password', 'verification code',
      'security code', 'authentication code', 'code you received', 'code we sent',
      'share the code', 'read out the code', 'send me the code', 'forward the code',
      'otp', '6-digit code', '6 digit code',
    ],
  },
  {
    code: 'TEXT_CREDENTIAL_REQUEST',
    phrases: [
      'verify your account', 'confirm your account', 'verify your identity',
      'confirm your password', 're-enter your password', 'update your payment',
      'update your card', 'confirm your card', 'validate your account',
      'unusual sign-in', 'unusual login', 'sign in to verify', 'login to verify',
      'card number', 'cvv', 'social security number', 'ssn', 'pin number',
    ],
  },
  {
    code: 'TEXT_BANK_IMPERSONATION',
    phrases: [
      'kyc', 'net banking', 'debit card', 'credit card', 'bank account',
      'your account will be', 'account has been limited', 'suspicious transaction',
      'blocked by your bank', 'bank security',
    ],
  },
  {
    code: 'TEXT_URGENCY',
    phrases: [
      'urgent', 'immediately', 'act now', 'right away', 'within 24 hours',
      'within 48 hours', 'final notice', 'last warning', 'expires today',
      'expires soon', 'limited time', 'as soon as possible',
    ],
  },
  {
    code: 'TEXT_THREAT',
    phrases: [
      'account suspended', 'account will be blocked', 'account will be closed',
      'will be deactivated', 'legal action', 'lawyer', 'lawsuit', 'arrest',
      'penalty', 'terminated', 'court', 'police case',
    ],
  },
  {
    code: 'TEXT_MONEY_REQUEST',
    phrases: [
      'wire transfer', 'bank transfer', 'gift card', 'itunes card', 'google play card',
      'bitcoin', 'crypto', 'usdt', 'send money', 'send funds', 'processing fee',
      'customs fee', 'clearance fee', 'redelivery fee', 'payment required',
      'make a payment', 'transfer the amount',
    ],
  },
  {
    code: 'TEXT_PRIZE_LOTTERY',
    phrases: [
      'you won', "you've won", 'you have won', 'claim your prize', 'claim your reward',
      'lottery', 'jackpot', 'lucky winner', 'selected winner', 'free gift',
      'congratulations, you',
    ],
  },
  {
    code: 'TEXT_INVESTMENT_SCAM',
    phrases: [
      'guaranteed returns', 'guaranteed profit', 'double your money', 'double your investment',
      'risk-free investment', 'investment opportunity', 'high returns', 'quick profit',
    ],
  },
  {
    code: 'TEXT_DELIVERY_SCAM',
    phrases: [
      'parcel', 'package is waiting', 'delivery failed', 'could not be delivered',
      'reschedule delivery', 'redeliver', 'shipment is on hold', 'customs clearance',
    ],
  },
  {
    code: 'TEXT_JOB_SCAM',
    phrases: [
      'work from home', 'earn daily', 'earn from home', 'part time job', 'part-time job',
      'salary daily', 'easy money', 'no experience needed', 'online job',
    ],
  },
];

/** Frequently abused top-level domains (a weak, generic signal). */
const RISKY_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'gq', 'cf', 'tk', 'ml', 'ga',
  'work', 'support', 'rest', 'bar', 'cam', 'surf', 'monster', 'quest', 'cyou',
  'sbs', 'icu', 'lol', 'best', 'buzz', 'bid', 'men', 'win', 'loan', 'racing',
  'download', 'stream', 'review', 'country', 'press', 'host', 'ooo', 'gdn',
  'party', 'date', 'faith', 'science', 'accountant',
]);

/** Well-known link shorteners. */
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in',
  'trib.al', 'bl.ink', 'v.gd', 'urlz.fr', 'adf.ly', 'shorte.st', 'bc.vc',
]);

/** Brands commonly impersonated in phishing. */
const BRANDS = [
  'paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'dhl', 'fedex', 'ups', 'usps', 'royal mail', 'irs',
  'hmrc', 'chase', 'wells fargo', 'hsbc', 'citibank', 'maybank', 'cimb',
];

const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/;
const URL_SPLIT = /[\s<>"'`()[\]{}]+/;
const TRAILING_PUNCT = /[.,;:!?)\]}>"']+$/;
const LONG_NUMBER = /\d[\d\s.-]{4,}\d/g;
const EMAIL = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
const BARE_HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}([/:?#].*)?$/i;
const IPV4_HOST = /^\d{1,3}(\.\d{1,3}){3}([/:?#].*)?$/;

/** A score at or above this creates an alert. Set so a single high-signal
 * phrase (e.g. an OTP request, weight 40) alerts on its own, while weak
 * presentation signals never do. */
export const ALERT_THRESHOLD = 40;

/** Aggregates the analysis text from the notification fields. */
function joinText(content: NotificationContent): string {
  return [content.title, content.text, content.subText]
    .filter((part): part is string => typeof part === 'string' && part.length > 0)
    .join('\n');
}

function severityForScore(score: number): Severity {
  if (score >= 70) return 'high';
  if (score >= ALERT_THRESHOLD) return 'medium';
  if (score >= 25) return 'low';
  return 'info';
}

function severityForWeight(weight: number): Severity {
  if (weight >= 30) return 'high';
  if (weight >= 20) return 'medium';
  if (weight >= 10) return 'low';
  return 'info';
}

/** True for a plain IPv4 or IPv6 literal host. */
function isIpHost(host: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  return host.includes(':') || /^\[[0-9a-f:]+\]$/i.test(host);
}

function labelCount(host: string): number {
  return host.split('.').filter(Boolean).length;
}

function topLevelDomain(host: string): string {
  const parts = host.split('.').filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : '';
}

/** Turns a raw token into a parsable URL, adding a scheme when needed. */
function toCandidate(token: string): string | null {
  if (/^https?:\/\//i.test(token)) return token;
  if (/^www\./i.test(token)) return `https://${token}`;
  // A bare host or host/path. A schemeless token must end in an alphabetic TLD
  // (or be an IPv4 literal) so everyday numbers like "24.99" are not treated as
  // links.
  if (BARE_HOST.test(token)) return `https://${token}`;
  if (IPV4_HOST.test(token)) return `https://${token}`;
  return null;
}

interface UrlToken {
  /** The link exactly as it appeared in the message. */
  raw: string;
  /** A canonical `scheme://host/path` form, for de-duplication. */
  normalized: string;
  parsed: ParsedUrl;
}

/** Extracts the http(s) links contained in a message, keeping the raw spelling. */
function parseUrlTokens(text: string): UrlToken[] {
  const seen = new Set<string>();
  const out: UrlToken[] = [];
  for (const rawSplit of text.split(URL_SPLIT)) {
    const raw = rawSplit.replace(TRAILING_PUNCT, '');
    if (raw.length < 4) continue;
    const candidate = toCandidate(raw);
    if (!candidate) continue;
    const parsed = parseWebUrl(candidate);
    if (!parsed.ok || !parsed.url) continue;
    const normalized = `${parsed.url.scheme}://${parsed.url.host}${parsed.url.path}`;
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push({ raw, normalized, parsed: parsed.url });
  }
  return out;
}

/** The canonical http(s) links contained in a message. */
export function extractUrls(text: string): string[] {
  return parseUrlTokens(text).map((token) => token.normalized);
}

function reasonsForUrl(url: ParsedUrl, raw: string): string[] {
  const reasons: string[] = [];
  const host = url.host;

  if (isIpHost(host)) reasons.push('URL_IP_HOST');
  if (/@/.test(raw)) reasons.push('URL_CREDENTIAL_IN_URL');
  if (host.includes('xn--')) reasons.push('URL_PUNYCODE');
  if (SHORTENERS.has(host)) reasons.push('URL_SHORTENER');
  if (RISKY_TLDS.has(topLevelDomain(host))) reasons.push('URL_SUSPICIOUS_TLD');
  if (labelCount(host) >= 4) reasons.push('URL_MANY_SUBDOMAINS');
  if (host.length > 30) reasons.push('URL_LONG_HOST');
  if (url.port && url.port !== '80' && url.port !== '443') reasons.push('URL_NONSTANDARD_PORT');
  if (raw.length > 100) reasons.push('URL_EXCESSIVE_LENGTH');

  const hyphensAndDigits = (host.match(/[-0-9]/g) ?? []).length;
  if (host.length >= 12 && hyphensAndDigits / host.length > 0.4) reasons.push('URL_HYPHEN_DIGIT_HEAVY');

  return reasons;
}

function analyzeUrls(text: string): AnalyzedUrl[] {
  return parseUrlTokens(text).map((token) => ({
    raw: token.raw,
    host: token.parsed.host,
    reasons: reasonsForUrl(token.parsed, token.raw),
  }));
}

function capsRatio(text: string): number {
  const letters = text.replace(/[^a-z]/gi, '');
  if (letters.length < 20) return 0;
  const caps = letters.replace(/[^A-Z]/g, '').length;
  return caps / letters.length;
}

/** Stable, non-cryptographic hash used only to de-duplicate alerts. */
export function hashNotificationContent(content: NotificationContent): string {
  const input = `${content.packageName}|${(content.title ?? '').trim()}|${(content.text ?? '').trim()}`;
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    // FNV-1a uses bitwise mixing by definition.
    // eslint-disable-next-line no-bitwise
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  // eslint-disable-next-line no-bitwise
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Removes the sensitive parts of a message so a short preview can be stored
 * without keeping the message itself: links become their host, emails and long
 * numbers are masked, and the result is trimmed.
 */
export function redactNotificationText(text: string, maxLength = 140): string {
  let output = text;
  for (const token of parseUrlTokens(text)) {
    output = output.split(token.raw).join(`[link: ${token.parsed.host}]`);
  }
  output = output.replace(EMAIL, '[email]');
  output = output.replace(LONG_NUMBER, '[number]');
  output = output.replace(ZERO_WIDTH, '');
  output = output.replace(/\s+/g, ' ').trim();
  if (output.length > maxLength) {
    output = `${output.slice(0, maxLength - 1).trimEnd()}…`;
  }
  return output;
}

function pickCategory(signals: NotificationSignal[]): ThreatCategory {
  const priority: ThreatCategory[] = ['phishing', 'scam', 'social-engineering', 'suspicious'];
  for (const category of priority) {
    if (signals.some((signal) => signal.category === category)) return category;
  }
  return signals[0]?.category ?? 'suspicious';
}

function recommendedActionFor(category: ThreatCategory): string {
  switch (category) {
    case 'phishing':
      return 'Do not open the link or share any codes or passwords. Check through the official app or website instead.';
    case 'scam':
      return 'Do not send money or reply. Treat the message as a scam and delete it.';
    case 'social-engineering':
      return 'Be cautious: verify the sender through a channel you trust before acting on the message.';
    default:
      return 'Treat the message with caution and do not act on any links or requests until you have verified them.';
  }
}

/**
 * Analyses one notification and returns a scored, explainable result.
 *
 * @param content the exposed notification fields (never the full app data)
 */
export function analyzeNotification(content: NotificationContent): NotificationAnalysis {
  const text = joinText(content);
  const haystack = text.toLowerCase();
  const matched: NotificationSignal[] = [];
  const push = (code: string): void => {
    const def = SIGNALS[code];
    if (def && !matched.some((signal) => signal.code === code)) {
      matched.push({ code: def.code, label: def.label, weight: def.weight, category: def.category });
    }
  };

  // Pricing/URL shape signals.
  const urls = analyzeUrls(text);
  for (const url of urls) {
    for (const reason of url.reasons) push(reason);
  }

  // Phrase signals.
  for (const entry of PHRASE_SIGNALS) {
    if (entry.phrases.some((phrase) => haystack.includes(phrase))) {
      push(entry.code);
    }
  }

  // Brand shown in the text but linked elsewhere.
  const mentionedBrands = BRANDS.filter((brand) => haystack.includes(brand));
  if (mentionedBrands.length > 0 && urls.length > 0) {
    const linksToBrand = urls.some((url) => {
      const labels = url.host.split('.').map((label) => label.replace(/[^a-z0-9]/g, ''));
      return mentionedBrands.some((brand) => labels.includes(brand.replace(/[^a-z0-9]/g, '')));
    });
    if (!linksToBrand) push('TEXT_BRAND_LINK_MISMATCH');
  }

  // Presentation tricks.
  if (ZERO_WIDTH.test(text)) push('TEXT_ZERO_WIDTH');
  if (capsRatio(text) > 0.6) push('TEXT_EXCESSIVE_CAPS');
  if (/([!?])\1{2,}/.test(text)) push('TEXT_REPEATED_PUNCT');

  const score = Math.min(100, matched.reduce((total, signal) => total + signal.weight, 0));
  const severity = severityForScore(score);
  const category = matched.length > 0 ? pickCategory(matched) : 'none';
  const suspicious = score >= ALERT_THRESHOLD;

  const reasons: DetectionReason[] = matched.map((signal) => ({
    code: signal.code,
    message: signal.label,
    severity: severityForWeight(signal.weight),
  }));

  const verdict: Verdict = {
    status: suspicious ? 'SUSPICIOUS' : 'UNKNOWN',
    severity,
    category,
    score,
    // A heuristic can never be definitive: no authoritative source was consulted.
    definitive: false,
    recommendedAction: recommendedActionFor(category),
    reasons,
    sources: [
      {
        source: 'local-text-heuristics',
        label: 'On-device message analysis',
        status: suspicious ? 'SUSPICIOUS' : 'UNKNOWN',
        detail: matched.length === 0 ? 'No scam or phishing signals matched.' : matched.map((s) => s.label).join('; '),
        categories: category === 'none' ? undefined : [category],
      },
    ],
  };

  return {
    score,
    severity,
    category,
    threatType: category === 'phishing' ? 'phishing_notification' : 'suspicious_message',
    signals: matched,
    urls,
    recommendedAction: recommendedActionFor(category),
    redactedPreview: redactNotificationText(text),
    contentHash: hashNotificationContent(content),
    verdict,
  };
}

/** True when an analysis is strong enough to raise an alert. */
export function shouldAlert(analysis: NotificationAnalysis): boolean {
  return analysis.score >= ALERT_THRESHOLD;
}

/**
 * Builds the alert row for a flagged message. The stored `target` is the
 * redacted preview, never the message itself.
 */
export function buildNotificationAlert(
  content: NotificationContent,
  analysis: NotificationAnalysis,
): Omit<ThreatAlert, 'id' | 'createdAt'> {
  const reason = analysis.signals.map((signal) => signal.label).join('; ');
  return {
    threatType: analysis.threatType,
    severity: analysis.severity,
    category: analysis.category,
    sourceApplication: content.appLabel ?? content.packageName,
    detectionReason: reason.length > 0 ? reason : 'Suspicious message content',
    target: analysis.redactedPreview,
    recommendedAction: analysis.recommendedAction,
    isRead: false,
    scannedAt: content.postedAt ?? new Date().toISOString(),
  };
}
