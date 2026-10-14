/**
 * React hooks for the on-device file scanner.
 *
 * Two hooks are provided:
 *
 *  - {@link useFileScanner}        — pick and scan a single file.
 *  - {@link useMultipleFileScanner} — pick several files and scan them in turn.
 *
 * Both own the full lifecycle: opening the Storage Access Framework picker,
 * running the native engine, streaming progress, optionally asking the backend
 * for a hash reputation, and merging the two into a single verdict. The heavy
 * lifting happens in the native module on a background thread; these hooks only
 * hold UI state.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  addScanProgressListener,
  cancelScan,
  clearFileCache,
  describeFileScannerError,
  isFileScannerAvailable,
  isPickCancelled,
  pickFiles,
  scanFile,
  type NativeScanStatus,
  type ScanFinding,
  type ScanProgress,
} from '../native/FileScannerNative';
import { scanFileHash } from '../api/client';
import { capabilities } from '../capabilities';
import { localStatusToVerdict, mergeVerdict, type ReputationState } from '../domain/fileScan';
import type { VerdictStatus } from '../domain/types';

/** A file the user has picked, before or after it has been scanned. */
export interface SelectedFile {
  uri: string;
  /** Best-effort display name; replaced with the real one after scanning. */
  name: string;
}

/** The merged, UI-ready result of scanning one file. */
export interface FileScanOutcome {
  uri: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  extension: string;
  magicType?: string;
  sha256?: string;
  truncated: boolean;
  durationMs: number;
  /** The native engine's local status. */
  status: NativeScanStatus;
  details: string;
  findings: ScanFinding[];
  /** The merged verdict shown to the user. */
  verdict: VerdictStatus;
  reputation: ReputationState;
  reputationReason?: string;
}

export interface UseFileScannerOptions {
  /**
   * Ask the backend for a hash reputation. Requires the user's explicit
   * consent (the app's `shareThreatData` privacy preference).
   */
  checkReputation?: boolean;
}

export interface UseFileScannerReturn {
  isAvailable: boolean;
  selected: SelectedFile | null;
  outcome: FileScanOutcome | null;
  isPicking: boolean;
  isScanning: boolean;
  progress: ScanProgress | null;
  error: string | null;
  pickFile: () => Promise<void>;
  scanSelectedFile: () => Promise<void>;
  cancel: () => Promise<void>;
  clearSelection: () => void;
  clearError: () => void;
}

export interface UseMultipleFileScannerReturn {
  isAvailable: boolean;
  files: SelectedFile[];
  outcomes: FileScanOutcome[];
  /** Index (0-based) of the file currently being scanned, or -1. */
  scanningIndex: number;
  isPicking: boolean;
  isScanning: boolean;
  progress: ScanProgress | null;
  error: string | null;
  pickFiles: (multiple: boolean) => Promise<void>;
  scanAll: () => Promise<void>;
  cancel: () => Promise<void>;
  clearSelection: () => void;
  clearError: () => void;
}

interface ReputationLookup {
  state: ReputationState;
  verdict?: VerdictStatus;
  reason?: string;
}

/** Turns a content URI into a guess at a file name for the picker preview. */
function nameFromUri(uri: string): string {
  const segment = uri.split('/').pop() ?? '';
  try {
    return decodeURIComponent(segment) || 'Selected file';
  } catch {
    return segment || 'Selected file';
  }
}

async function lookupReputation(hash: string | undefined, enabled: boolean): Promise<ReputationLookup> {
  if (!enabled || !hash || !capabilities.urlReputation) {
    return { state: 'skipped' };
  }
  try {
    const response = await scanFileHash({ hash });
    return { state: 'checked', verdict: response.threatLevel, reason: response.detectionReason };
  } catch {
    // A failed lookup must never be mistaken for a clean result.
    return { state: 'unavailable' };
  }
}

/**
 * Runs the native scan for one URI and folds in the optional reputation result.
 * Exported so it can be unit-tested without rendering a hook.
 */
export async function inspectFile(uri: string, checkReputation: boolean): Promise<FileScanOutcome> {
  const result = await scanFile(uri);
  const local = localStatusToVerdict(result.scanResult.status);
  const reputation = await lookupReputation(result.sha256, checkReputation);

  return {
    uri: result.uri,
    fileName: result.fileName,
    fileSize: result.fileSize,
    mimeType: result.mimeType,
    extension: result.extension ?? '',
    magicType: result.magicType,
    sha256: result.sha256,
    truncated: result.truncated,
    durationMs: result.durationMs,
    status: result.scanResult.status,
    details: result.scanResult.details,
    findings: result.scanResult.findings ?? [],
    verdict: mergeVerdict(local, reputation.state, reputation.verdict),
    reputation: reputation.state,
    reputationReason: reputation.reason,
  };
}

/** Subscribes to native progress events while the component is mounted. */
function useScanProgress(
  isAvailable: boolean,
  setProgress: (progress: ScanProgress | null) => void,
): void {
  useEffect(() => {
    if (!isAvailable) {
      return undefined;
    }
    return addScanProgressListener(setProgress);
  }, [isAvailable, setProgress]);
}

/** Drops cached copies of every file the engine copied while this screen is open. */
function useCacheCleanup(): void {
  useEffect(() => {
    return () => {
      void clearFileCache();
    };
  }, []);
}

/** Tracks whether the component is still mounted before touching state. */
function useMounted(): React.MutableRefObject<boolean> {
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  return mounted;
}

/**
 * Hook for scanning a single file. Handles file picking, scanning, progress and
 * error state for one selection at a time.
 */
export function useFileScanner(options: UseFileScannerOptions = {}): UseFileScannerReturn {
  const { checkReputation = false } = options;
  const [isAvailable] = useState(() => isFileScannerAvailable());
  const [selected, setSelected] = useState<SelectedFile | null>(null);
  const [outcome, setOutcome] = useState<FileScanOutcome | null>(null);
  const [isPicking, setIsPicking] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [error, setError] = useState<string | null>(null);

  const mounted = useMounted();
  useScanProgress(isAvailable, setProgress);
  useCacheCleanup();

  const pickFile = useCallback(async () => {
    if (!isAvailable) {
      setError('The native file scanner is not available on this device.');
      return;
    }
    setIsPicking(true);
    setError(null);
    setOutcome(null);
    try {
      const uris = await pickFiles(false);
      if (uris.length > 0 && mounted.current) {
        setSelected({ uri: uris[0], name: nameFromUri(uris[0]) });
      }
    } catch (err) {
      if (!isPickCancelled(err) && mounted.current) {
        setError(describeFileScannerError(err));
      }
    } finally {
      if (mounted.current) {
        setIsPicking(false);
      }
    }
  }, [isAvailable, mounted]);

  const scanSelectedFile = useCallback(async () => {
    if (!selected) {
      setError('Choose a file to scan first.');
      return;
    }
    if (!isAvailable) {
      setError('The native file scanner is not available on this device.');
      return;
    }
    setIsScanning(true);
    setError(null);
    setProgress(null);
    try {
      const scanOutcome = await inspectFile(selected.uri, checkReputation);
      if (mounted.current) {
        setSelected({ uri: scanOutcome.uri, name: scanOutcome.fileName });
        setOutcome(scanOutcome);
      }
    } catch (err) {
      if (mounted.current) {
        setError(describeFileScannerError(err));
      }
    } finally {
      if (mounted.current) {
        setIsScanning(false);
        setProgress(null);
      }
    }
  }, [selected, isAvailable, checkReputation, mounted]);

  const cancel = useCallback(async () => {
    await cancelScan();
  }, []);

  const clearSelection = useCallback(() => {
    setSelected(null);
    setOutcome(null);
    setProgress(null);
    setError(null);
  }, []);

  const clearError = useCallback(() => setError(null), []);

  return {
    isAvailable,
    selected,
    outcome,
    isPicking,
    isScanning,
    progress,
    error,
    pickFile,
    scanSelectedFile,
    cancel,
    clearSelection,
    clearError,
  };
}

/**
 * Hook for scanning several files in turn (used by the full scan). Files are
 * inspected sequentially so the single-threaded native engine is not contended
 * and progress stays meaningful.
 */
export function useMultipleFileScanner(
  options: UseFileScannerOptions = {},
): UseMultipleFileScannerReturn {
  const { checkReputation = false } = options;
  const [isAvailable] = useState(() => isFileScannerAvailable());
  const [files, setFiles] = useState<SelectedFile[]>([]);
  const [outcomes, setOutcomes] = useState<FileScanOutcome[]>([]);
  const [scanningIndex, setScanningIndex] = useState(-1);
  const [isPicking, setIsPicking] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [error, setError] = useState<string | null>(null);

  const mounted = useMounted();
  useScanProgress(isAvailable, setProgress);
  useCacheCleanup();

  const handlePickFiles = useCallback(
    async (multiple: boolean) => {
      if (!isAvailable) {
        setError('The native file scanner is not available on this device.');
        return;
      }
      setIsPicking(true);
      setError(null);
      setOutcomes([]);
      try {
        const uris = await pickFiles(multiple);
        if (mounted.current) {
          setFiles(uris.map((uri) => ({ uri, name: nameFromUri(uri) })));
        }
      } catch (err) {
        if (!isPickCancelled(err) && mounted.current) {
          setError(describeFileScannerError(err));
        }
      } finally {
        if (mounted.current) {
          setIsPicking(false);
        }
      }
    },
    [isAvailable, mounted],
  );

  const scanAll = useCallback(async () => {
    if (files.length === 0) {
      setError('Choose one or more files to scan first.');
      return;
    }
    if (!isAvailable) {
      setError('The native file scanner is not available on this device.');
      return;
    }
    setIsScanning(true);
    setError(null);
    const collected: FileScanOutcome[] = [];
    try {
      for (let index = 0; index < files.length; index += 1) {
        if (!mounted.current) {
          return;
        }
        setScanningIndex(index);
        const result = await inspectFile(files[index].uri, checkReputation);
        collected.push(result);
        if (mounted.current) {
          setOutcomes([...collected]);
        }
      }
    } catch (err) {
      if (mounted.current) {
        setError(describeFileScannerError(err));
      }
    } finally {
      if (mounted.current) {
        setIsScanning(false);
        setScanningIndex(-1);
        setProgress(null);
      }
    }
  }, [files, isAvailable, checkReputation, mounted]);

  const cancel = useCallback(async () => {
    await cancelScan();
  }, []);

  const clearSelection = useCallback(() => {
    setFiles([]);
    setOutcomes([]);
    setScanningIndex(-1);
    setProgress(null);
    setError(null);
  }, []);

  const clearError = useCallback(() => setError(null), []);

  return {
    isAvailable,
    files,
    outcomes,
    scanningIndex,
    isPicking,
    isScanning,
    progress,
    error,
    pickFiles: handlePickFiles,
    scanAll,
    cancel,
    clearSelection,
    clearError,
  };
}
