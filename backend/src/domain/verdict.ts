/**
 * Core verdict vocabulary shared by every scanner.
 *
 * The important honesty rule lives here: a verdict is `SAFE` only when an
 * *authoritative* source actually said so. The absence of evidence is
 * `UNKNOWN`, and `UNKNOWN` must never be presented to the user as `SAFE`.
 */

export type VerdictStatus = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AnalysisSource =
  | 'local-url-heuristics'
  | 'local-text-heuristics'
  | 'local-file-analysis'
  | 'local-document-analysis'
  | 'local-apk-analysis'
  | 'local-signature'
  | 'google-safe-browsing'
  | 'urlhaus'
  | 'virustotal';

export type ThreatCategory =
  | 'phishing'
  | 'malware'
  | 'scam'
  | 'spam'
  | 'suspicious'
  | 'unwanted-software'
  | 'social-engineering'
  | 'none'
  | 'unknown';

export interface DetectionReason {
  /** Stable machine code, e.g. `punycode-host`. */
  code: string;
  /** Human-readable, non-technical sentence shown to the user. */
  message: string;
  /** Contribution to the local risk score (0 = purely informational). */
  weight: number;
  severity: Severity;
}

/** The result of one analyzer. */
export interface SourceResult {
  source: AnalysisSource;
  status: VerdictStatus;
  reasons: DetectionReason[];
  /** Free-text detail, e.g. an external engine's verdict label. */
  detail?: string;
  /** Categories reported by the source, if any. */
  categories?: ThreatCategory[];
  /** How long the analyzer took. */
  durationMs?: number;
  /** Set when the source could not answer (network failure, no key, …). */
  error?: string;
}

export interface MergedVerdict {
  status: VerdictStatus;
  /** 0–100, derived from the accumulated weight of the reasons. */
  score: number;
  severity: Severity;
  category: ThreatCategory;
  reasons: DetectionReason[];
  sources: SourceResult[];
  /** True when at least one authoritative source gave a definitive answer. */
  definitive: boolean;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

export function severityFromScore(score: number): Severity {
  if (score >= 80) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 30) return 'medium';
  if (score >= 10) return 'low';
  return 'info';
}

/**
 * Convert accumulated reason weights into a 0–100 score that saturates rather
 * than growing without bound, so one enormous weight cannot mask everything
 * else.
 */
export function scoreFromWeights(weights: number[]): number {
  const total = weights.filter((w) => w > 0).reduce((sum, w) => sum + w, 0);
  if (total <= 0) return 0;
  // Saturating curve: score → 100 as total → ∞, ~50 at total = 60.
  const score = Math.round(100 * (1 - Math.exp(-total / 45)));
  return Math.min(100, score);
}

const MALICIOUS_CATEGORIES: ThreatCategory[] = ['malware', 'phishing'];

function categoryFromStatus(status: VerdictStatus): ThreatCategory {
  switch (status) {
    case 'MALICIOUS':
      return 'malware';
    case 'SUSPICIOUS':
      return 'suspicious';
    case 'SAFE':
      return 'none';
    default:
      return 'unknown';
  }
}

function pickCategory(sources: SourceResult[], fallback: ThreatCategory): ThreatCategory {
  const counts = new Map<ThreatCategory, number>();
  for (const source of sources) {
    for (const category of source.categories ?? []) {
      if (category === 'none' || category === 'unknown') continue;
      counts.set(category, (counts.get(category) ?? 0) + 1);
    }
  }
  let best: ThreatCategory | undefined;
  let bestCount = 0;
  for (const [category, count] of counts) {
    if (count > bestCount) {
      best = category;
      bestCount = count;
    }
  }
  return best ?? fallback;
}

/**
 * Merge analyzer results into a single verdict.
 *
 * Precedence: MALICIOUS > SUSPICIOUS > SAFE(only if authoritative) > UNKNOWN.
 */
export function mergeVerdicts(sources: SourceResult[]): MergedVerdict {
  const answers = sources.filter((s) => s.status !== 'UNKNOWN');
  const reasons = sources.flatMap((s) => s.reasons);
  const score = scoreFromWeights(reasons.map((r) => r.weight));

  const hasMalicious = answers.some((s) => s.status === 'MALICIOUS');
  const hasSuspicious = answers.some((s) => s.status === 'SUSPICIOUS');
  const hasSafe = answers.some((s) => s.status === 'SAFE');

  let status: VerdictStatus;
  let definitive: boolean;

  if (hasMalicious) {
    status = 'MALICIOUS';
    definitive = true;
  } else if (hasSuspicious) {
    status = 'SUSPICIOUS';
    definitive = true;
  } else if (hasSafe) {
    status = 'SAFE';
    definitive = true;
  } else {
    status = 'UNKNOWN';
    definitive = false;
  }

  const severity =
    status === 'MALICIOUS'
      ? 'critical'
      : status === 'SUSPICIOUS'
        ? maxSeverity(severityFromScore(score), 'medium')
        : status === 'UNKNOWN'
          ? 'info'
          : severityFromScore(score);

  const fallbackCategory = categoryFromStatus(status);
  const category = pickCategory(
    sources,
    hasMalicious && answers.some((s) => MALICIOUS_CATEGORIES.includes(pickCategory([s], 'unknown')))
      ? 'malware'
      : fallbackCategory,
  );

  return { status, score, severity, category, reasons, sources, definitive };
}

export function isThreat(status: VerdictStatus): boolean {
  return status === 'MALICIOUS' || status === 'SUSPICIOUS';
}
