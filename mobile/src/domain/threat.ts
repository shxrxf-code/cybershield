import type { ThreatTone } from '../theme/theme';
import type { Severity, ThreatCategory, VerdictStatus } from './types';

/**
 * Presentation helpers that translate the threat vocabulary into words, tones
 * and labels. They live in one place so every screen describes the same result
 * in the same language.
 */

const STATUS_LABELS: Record<VerdictStatus, string> = {
  SAFE: 'Safe',
  SUSPICIOUS: 'Suspicious',
  MALICIOUS: 'Malicious',
  UNKNOWN: 'Unverified',
};

/**
 * UNKNOWN is deliberately worded as "Unverified", never "Safe": we only claim
 * safety when an authoritative source actually confirmed it.
 */
export function statusLabel(status: VerdictStatus): string {
  return STATUS_LABELS[status];
}

export function statusTone(status: VerdictStatus): ThreatTone {
  switch (status) {
    case 'SAFE':
      return 'safe';
    case 'SUSPICIOUS':
      return 'suspicious';
    case 'MALICIOUS':
      return 'malicious';
    default:
      return 'unknown';
  }
}

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export function severityLabel(severity: Severity): string {
  return SEVERITY_LABELS[severity];
}

export function severityTone(severity: Severity): ThreatTone {
  switch (severity) {
    case 'critical':
      return 'malicious';
    case 'high':
      return 'suspicious';
    case 'medium':
      return 'suspicious';
    case 'low':
      return 'info';
    default:
      return 'unknown';
  }
}

/** Higher is more severe; useful for sorting and "worst first" comparisons. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  phishing: 'Phishing',
  malware: 'Malware',
  scam: 'Scam',
  spam: 'Spam',
  suspicious: 'Suspicious',
  'unwanted-software': 'Unwanted software',
  'social-engineering': 'Social engineering',
  none: 'No threat',
  unknown: 'Unknown',
};

export function categoryLabel(category: ThreatCategory): string {
  return CATEGORY_LABELS[category];
}

const THREAT_TYPE_LABELS: Record<string, string> = {
  malicious_url: 'Malicious link',
  suspicious_url: 'Suspicious link',
  suspicious_file: 'Suspicious file',
  suspicious_pdf: 'Suspicious document',
  suspicious_image: 'Suspicious image',
  harmful_apk: 'Harmful app',
  phishing_notification: 'Phishing message',
  suspicious_message: 'Suspicious message',
};

export function threatTypeLabel(threatType: string): string {
  return THREAT_TYPE_LABELS[threatType] ?? threatType.replace(/_/g, ' ');
}

const SCAN_TYPE_LABELS: Record<string, string> = {
  quick: 'Quick scan',
  full: 'Full scan',
  url: 'Link check',
  file: 'File scan',
  apk: 'App scan',
  notification: 'Message check',
  scheduled: 'Background scan',
};

export function scanTypeLabel(scanType: string): string {
  return SCAN_TYPE_LABELS[scanType] ?? scanType;
}

/** True for statuses that require the user's attention. */
export function isThreat(status: VerdictStatus): boolean {
  return status === 'MALICIOUS' || status === 'SUSPICIOUS';
}
