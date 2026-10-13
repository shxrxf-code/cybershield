import type { Request, Response } from 'express';
import type { Container } from '../container';
import { validated } from '../middleware/validate';
import type { FileScanRequest } from '../validators/file.validator';
import { presentFileScan } from './dto';

/**
 * File reputation endpoint.
 *
 * Receives a SHA-256 (computed on the device) plus the device analyzer's own
 * findings. It never receives the file bytes, so nothing is uploaded and
 * nothing is executed server-side.
 */
export function createFileController(container: Container) {
  return {
    scan: async (req: Request, res: Response): Promise<void> => {
      const body = validated<FileScanRequest>(req, 'body');

      const outcome = await container.services.fileAnalysis.analyze({
        sha256: body.sha256,
        fileName: body.fileName,
        sizeBytes: body.sizeBytes,
        mimeType: body.mimeType,
        extension: body.extension,
        localFindings: body.localFindings,
        localStatus: body.localStatus,
        localSource: body.localSource,
      });

      const recorded = await container.services.scanHistory.recordFileScan(
        outcome,
        { fileName: body.fileName, extension: body.extension },
        { source: 'api' },
      );

      res.status(200).json(presentFileScan(outcome, recorded, { fileName: body.fileName }));
    },
  };
}
