import { mergeVerdicts, type MergedVerdict } from '../domain/verdict';
import { analyzeScamText } from '../detection/text/scam';
import { extractUrls } from '../detection/url/normalize';
import type { UrlReputationService, UrlScanOutcome } from './url-reputation.service';
import { scopedLogger } from '../utils/logger';

/**
 * Notification / message analysis.
 *
 * Privacy contract for this service:
 *   * it accepts only the text Android actually exposed in a notification,
 *   * it analyses that text transiently and returns *reasons*, never the body,
 *   * callers must not persist the raw text (see the controller).
 */

export interface NotificationAnalysisInput {
  text: string;
  title?: string;
  /** Human label of the source app, e.g. "WhatsApp". */
  sourceApp?: string;
  /** Android package name, used for reporting – never for content access. */
  packageName?: string;
}

export interface NotificationAnalysisOutcome {
  verdict: MergedVerdict;
  textScore: number;
  matchedSignals: string[];
  urls: UrlScanOutcome[];
  privacyNote: string;
  durationMs: number;
}

const MAX_URLS = 3;

const PRIVACY_NOTE =
  'Only the notification text Android displayed was analysed. Message contents were not stored.';

export class NotificationAnalysisService {
  private readonly log = scopedLogger('notification-analysis');

  constructor(private readonly urlService: UrlReputationService) {}

  async analyze(input: NotificationAnalysisInput): Promise<NotificationAnalysisOutcome> {
    const started = Date.now();

    const text = (input.text ?? '').slice(0, 4_000);
    const title = (input.title ?? '').slice(0, 300);

    const textResult = analyzeScamText({ text, title, sourceApp: input.sourceApp });

    const candidates = extractUrls(`${title}\n${text}`).slice(0, MAX_URLS);
    const urls: UrlScanOutcome[] = [];
    for (const candidate of candidates) {
      try {
        urls.push(await this.urlService.analyze(candidate));
      } catch (error) {
        // An unparseable URL inside a message is not a failure of the scan.
        this.log.debug({ err: error }, 'skipping unparseable url in notification text');
      }
    }

    const sources = [
      {
        source: 'local-text-heuristics' as const,
        status: textResult.status,
        reasons: textResult.reasons,
        detail:
          textResult.reasons.length === 0
            ? 'No scam warning signs in the notification text.'
            : `${textResult.reasons.length} scam warning sign(s) in the notification text.`,
      },
      ...urls.flatMap((outcome) => outcome.verdict.sources),
    ];

    const verdict = mergeVerdicts(sources);
    const durationMs = Date.now() - started;

    this.log.info(
      {
        sourceApp: input.sourceApp,
        packageName: input.packageName,
        status: verdict.status,
        signals: textResult.matchedSignals.length,
        urls: urls.length,
        durationMs,
      },
      'notification analysed',
    );

    return {
      verdict,
      textScore: textResult.score,
      matchedSignals: textResult.matchedSignals,
      urls,
      privacyNote: PRIVACY_NOTE,
      durationMs,
    };
  }
}
