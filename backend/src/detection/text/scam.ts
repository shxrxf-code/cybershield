import type { DetectionReason, SourceResult } from '../../domain/verdict';
import { extractUrls } from '../url/normalize';

/**
 * Scam / phishing heuristics for short message text.
 *
 * Used by the backend's notification-analysis endpoint and mirrored (in
 * TypeScript) on the device so a flagged notification can be explained even
 * when offline. Like the URL heuristics, this returns `UNKNOWN` when it finds
 * nothing – it never declares a message safe.
 */

export interface TextAnalysisInput {
  text: string;
  title?: string;
  /** Sender/app label, e.g. "WhatsApp" or a bank name; never a private id. */
  sourceApp?: string;
}

export interface TextAnalysisResult {
  status: SourceResult['status'];
  score: number;
  reasons: DetectionReason[];
  urls: string[];
  matchedSignals: string[];
}

interface SignalGroup {
  id: string;
  label: string;
  weight: number;
  severity: DetectionReason['severity'];
  message: string;
  patterns: RegExp[];
}

const SIGNAL_GROUPS: SignalGroup[] = [
  {
    id: 'urgency',
    label: 'urgency',
    weight: 18,
    severity: 'medium',
    message: 'The message pressures you to act immediately.',
    patterns: [
      /\b(urgent(ly)?|immediately|right away|as soon as possible|act now|final (notice|warning)|last chance)\b/i,
      /\bwithin\s+\d+\s*(hours?|hrs?|minutes?|mins?|days?)\b/i,
      /\b(account|card|service|number|sim)\s+(will be|has been|is)\s+(blocked|suspended|deactivated|closed|terminated)\b/i,
      /\b(expire|expires|expiring)\s+(today|soon|in \d+)\b/i,
    ],
  },
  {
    id: 'credential-request',
    label: 'credential request',
    weight: 34,
    severity: 'high',
    message: 'The message asks for sensitive login information.',
    patterns: [
      /\b(password|passcode|login (details|credentials)|username and password)\b/i,
      /\b(share|send|provide|enter|forward|tell|confirm)\s+(me\s+)?(your\s+)?(otp|one[- ]time (password|code)|verification code|authentication code)\b/i,
      /\b(otp|verification code|authentication code)\b[^.]{0,40}\b(share|send|provide|enter|forward|reply with)\b/i,
      /\b(cvv|cvc|card number|debit card|credit card|atm pin|upi pin|pin number)\b/i,
      /\b(aadhaar|ssn|social security|national id|pan number|passport number)\b/i,
      /\b(verify|confirm|validate|update)\s+(your\s+)?(account|identity|details|information|kyc)\b/i,
    ],
  },
  {
    id: 'payment-request',
    label: 'payment request',
    weight: 30,
    severity: 'high',
    message: 'The message asks you to send money or make a payment.',
    patterns: [
      /\b(transfer|send|pay|remit)\s+(₹|rs\.?|inr|\$|usd|€|£)?\s*\d/i,
      /\b(upi|neft|imps|wire transfer|bank transfer|western union)\b/i,
      /\b(gift card|itunes card|google play card|amazon card|steam card)\b/i,
      /\b(bitcoin|btc|usdt|crypto|wallet address|ethereum|eth)\b/i,
      /\b(pay(ment)? (now|immediately|to (this|the) (account|link|number)))\b/i,
    ],
  },
  {
    id: 'threat',
    label: 'threat',
    weight: 26,
    severity: 'high',
    message: 'The message uses a threat to frighten you into acting.',
    patterns: [
      /\b(legal action|court|lawsuit|fir|police|arrest|penalty|fine)\b/i,
      /\b(account will be (blocked|permanently )?(deleted|closed|blocked))\b/i,
      /\b(you will lose|loss of) (access|service|money|funds)\b/i,
      /\b(suspend|terminate|freeze)\s+(your\s+)?(account|card|sim|service)\b/i,
    ],
  },
  {
    id: 'reward',
    label: 'too-good-to-be-true reward',
    weight: 30,
    severity: 'high',
    message: 'The message promises a prize, reward or easy money.',
    patterns: [
      /\b(you (have )?won|winner|congratulations|selected as (the )?winner)\b/i,
      /\b(lottery|lucky draw|jackpot|prize|reward|bonus)\b/i,
      /\b(claim (your|now)|redeem (your|now))\b/i,
      /\b(double your money|guaranteed returns?|risk[- ]free|huge profits?)\b/i,
      /\b(earn|make)\s+(₹|rs\.?|inr|\$)?\s*\d[\d,]*\s*(per|a|\/)\s*(day|week|hour)\b/i,
    ],
  },
  {
    id: 'job-scam',
    label: 'job / investment scam',
    weight: 24,
    severity: 'medium',
    message: 'The message offers easy work or investment returns typical of scams.',
    patterns: [
      /\b(work from home|part[- ]time job|earn daily|daily (income|payout))\b/i,
      /\b(no experience|no investment|simple tasks?|typing job|liking videos?)\b/i,
      /\b(invest(ment)? (in )?(crypto|forex|trading)|trading (tips|signals))\b/i,
    ],
  },
  {
    id: 'impersonation',
    label: 'impersonation',
    weight: 26,
    severity: 'high',
    message: 'The message pretends to be from a bank, company or official service.',
    patterns: [
      /\b(this is|from|regards?)[, ]+(your )?(bank|hdfc|sbi|icici|axis|chase|paypal|amazon|netflix|customer (care|service|support)|support team)\b/i,
      /\b(customer (care|service|support)|help ?desk|technical support|refund department)\b/i,
      /\b(bank|official|company)\s+(representative|executive|officer)\b/i,
    ],
  },
  {
    id: 'channel-move',
    label: 'move to private channel',
    weight: 16,
    severity: 'medium',
    message: 'The message asks you to continue on another app, which is common in scams.',
    patterns: [
      /\b(contact|message|reach|dm|ping) (me|us) (on|at|via)\b/i,
      /\b(whatsapp|telegram|signal)\s*(number|group|link|@)/i,
      /\bclick (here|this link|the link below)\b/i,
    ],
  },
  {
    id: 'kyc-update',
    label: 'KYC / account update lure',
    weight: 28,
    severity: 'high',
    message: 'The message asks you to update KYC or account details via a link.',
    patterns: [
      /\b(kyc|know your customer)\s*(update|pending|expired|verify)\b/i,
      /\bupdate your (kyc|pan|aadhaar|account|details|information) (immediately|now|today|within)\b/i,
      /\b(pan|aadhaar) (is )?(not )?linked\b/i,
    ],
  },
];

function testGroup(group: SignalGroup, haystack: string): string[] {
  const hits: string[] = [];
  for (const pattern of group.patterns) {
    const match = pattern.exec(haystack);
    if (match) hits.push(match[0].trim().slice(0, 80));
  }
  return hits;
}

const URL_WEIGHT_WITH_LURE = 22;
const URL_WEIGHT_ALONE = 10;

export function analyzeScamText(input: TextAnalysisInput): TextAnalysisResult {
  const raw = `${input.title ?? ''}\n${input.text ?? ''}`.trim();
  const haystack = raw.replace(/\s+/g, ' ');

  if (haystack.length === 0) {
    return { status: 'UNKNOWN', score: 0, reasons: [], urls: [], matchedSignals: [] };
  }

  const reasons: DetectionReason[] = [];
  const matchedSignals: string[] = [];
  const presentGroups = new Set<string>();
  let weight = 0;

  for (const group of SIGNAL_GROUPS) {
    const hits = testGroup(group, haystack);
    if (hits.length === 0) continue;
    presentGroups.add(group.id);
    matchedSignals.push(`${group.label}: ${hits[0]}`);
    weight += group.weight;
    reasons.push({
      code: `text-${group.id}`,
      message: group.message,
      weight: group.weight,
      severity: group.severity,
    });
  }

  // Combination bonuses: phishing is a *pattern*, not a single keyword.
  const lureGroups = ['credential-request', 'payment-request', 'kyc-update', 'reward'];
  const hasLure = lureGroups.some((id) => presentGroups.has(id));
  const hasPressure = presentGroups.has('urgency') || presentGroups.has('threat');

  if (hasLure && hasPressure) {
    weight += 20;
    reasons.push({
      code: 'text-lure-with-pressure',
      message: 'The message combines a request for information or money with urgent pressure.',
      weight: 20,
      severity: 'high',
    });
  }

  const urls = extractUrls(raw);
  if (urls.length > 0) {
    const w = hasLure || hasPressure ? URL_WEIGHT_WITH_LURE : URL_WEIGHT_ALONE;
    weight += w;
    reasons.push({
      code: 'text-contains-link',
      message: hasLure || hasPressure
        ? 'The message asks you to act and includes a link to open.'
        : 'The message contains a link.',
      weight: w,
      severity: hasLure || hasPressure ? 'high' : 'low',
    });
  }

  if (input.sourceApp && /\bbank|whatsapp|telegram|instagram|sms|message\b/i.test(input.sourceApp)) {
    // Slight uplift when a financial/phishing-prone channel is involved, only
    // if we already have signals – otherwise it would flag every message.
    if (weight > 0) weight += 4;
  }

  const score = Math.min(100, Math.round(100 * (1 - Math.exp(-weight / 45))));
  const status: SourceResult['status'] = weight >= 30 ? 'SUSPICIOUS' : 'UNKNOWN';

  return {
    status,
    score,
    reasons,
    urls,
    matchedSignals,
  };
}

/** Convenience wrapper producing a full SourceResult for the verdict merger. */
export function analyzeTextAsSource(input: TextAnalysisInput): SourceResult {
  const started = Date.now();
  const result = analyzeScamText(input);
  return {
    source: 'local-text-heuristics',
    status: result.status,
    reasons: result.reasons,
    detail:
      result.reasons.length === 0
        ? 'No scam warning signs found in the message.'
        : `${result.reasons.length} scam warning sign(s) found.`,
    categories: result.status === 'SUSPICIOUS' ? ['scam'] : undefined,
    durationMs: Date.now() - started,
  };
}
