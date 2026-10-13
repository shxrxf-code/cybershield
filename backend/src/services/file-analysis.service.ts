import {
  mergeVerdicts,
  type DetectionReason,
  type MergedVerdict,
  type SourceResult,
  type VerdictStatus,
} from '../domain/verdict';
import { queryHashProviders, type IntelRegistry } from '../providers';
import { ValidationError } from '../utils/errors';
import { scopedLogger } from '../utils/logger';

/**
 * Server-side view of a file scan.
 *
 * The structural work (file signature, PDF objects, EXIF, APK manifest) happens
 * natively on the device, which has the bytes. The backend contributes
 * hash-based reputation and the durable record. The device sends its own
 * findings here so they take part in the merged verdict — the backend does not
 * re-derive them from nothing.
 */

export interface FileScanInput {
  sha256: string;
  fileName?: string;
  sizeBytes?: number;
  mimeType?: string;
  extension?: string;
  /** Findings produced by the on-device analyzer. */
  localFindings?: DetectionReason[];
  /** The device's own verdict for the file, if it reached one. */
  localStatus?: VerdictStatus;
  localSource?: 'local-file-analysis' | 'local-document-analysis' | 'local-apk-analysis';
}

export interface FileScanOutcome {
  sha256: string;
  verdict: MergedVerdict;
  durationMs: number;
  scannedAt: string;
}

const SHA256_PATTERN = /^[a-f0-9]{64}$/i;

export class FileAnalysisService {
  private readonly log = scopedLogger('file-analysis');

  constructor(private readonly registry: IntelRegistry) {}

  private buildLocalSource(input: FileScanInput): SourceResult {
    const findings = input.localFindings ?? [];
    const source = input.localSource ?? 'local-file-analysis';
    const status: VerdictStatus = input.localStatus ?? (findings.length > 0 ? 'SUSPICIOUS' : 'UNKNOWN');
    return {
      source,
      status,
      reasons: findings,
      detail:
        findings.length === 0
          ? 'The device-side structural checks found no problems (this is not a guarantee of safety).'
          : `${findings.length} finding(s) from on-device file analysis.`,
    };
  }

  async analyze(input: FileScanInput): Promise<FileScanOutcome> {
    const started = Date.now();
    const sha256 = (input.sha256 ?? '').trim().toLowerCase();
    if (!SHA256_PATTERN.test(sha256)) {
      throw new ValidationError('A valid SHA-256 hash is required', { sha256: input.sha256 });
    }

    const localSource = this.buildLocalSource(input);
    const { results } = await queryHashProviders(this.registry, { sha256 });

    const verdict = mergeVerdicts([localSource, ...results]);
    const durationMs = Date.now() - started;

    this.log.info(
      {
        sha256Prefix: sha256.slice(0, 12),
        fileName: input.fileName,
        status: verdict.status,
        findings: localSource.reasons.length,
        durationMs,
      },
      'file hash analysed',
    );

    return { sha256, verdict, durationMs, scannedAt: new Date().toISOString() };
  }
}
