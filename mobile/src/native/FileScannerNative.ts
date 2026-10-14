/**
 * TypeScript bridge to the native Android `FileScanner` module.
 *
 * The native engine (`FileScannerModule` → `FileScanner`/`HashScanner`/
 * `SignatureScanner`) does all of the heavy lifting on a background thread: it
 * copies a user-selected document into the app cache, hashes it with SHA-256
 * and checks it for known signatures. This module only marshals values across
 * the bridge and keeps the surface area small and typed.
 *
 * If the native module is missing (iOS, an older build, or unit tests) every
 * helper degrades safely instead of throwing at import time.
 */

import { NativeEventEmitter, NativeModules, Platform } from 'react-native';

export type NativeScanStatus = 'clean' | 'suspicious' | 'threat' | 'error';
export type FindingSeverity = 'high' | 'medium' | 'low' | 'info';

export interface ScanFinding {
  code: string;
  message: string;
  severity: FindingSeverity;
}

export interface NativeScanResult {
  status: NativeScanStatus;
  details: string;
  findings: ScanFinding[];
  /** Finding codes only — a convenience mirror of `findings`. */
  threats: string[];
  truncated: boolean;
  errorCode?: string;
}

export interface NativeFileScanResult {
  uri: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  extension?: string;
  /** Container family detected from the file's leading bytes, when known. */
  magicType?: string;
  /** Absent only when the file could not be read or exceeded the size limit. */
  sha256?: string;
  truncated: boolean;
  durationMs: number;
  scanResult: NativeScanResult;
}

export interface ScanProgress {
  uri: string;
  phase: string;
  percent: number;
}

interface FileScannerNativeModule {
  pickFile(multiple: boolean): Promise<string[]>;
  computeFileHash(uri: string): Promise<{ uri: string; hash: string }>;
  scanFile(uri: string): Promise<NativeFileScanResult>;
  cancelScan(): Promise<boolean>;
  clearCache(): Promise<boolean>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
  MAX_FILE_SIZE?: number;
  MAX_CONTENT_SCAN_BYTES?: number;
  SUPPORTED_MIME_TYPES?: string[];
  ENGINE_VERSION?: number;
}

const nativeModule = (NativeModules as Record<string, unknown>).FileScanner as
  | FileScannerNativeModule
  | undefined;

const PROGRESS_EVENT = 'FileScannerProgress';

/** Human-readable messages for the errors the native module can reject with. */
const ERROR_MESSAGES: Record<string, string> = {
  E_PICK_CANCELLED: 'No file was selected.',
  E_PICK_EMPTY: 'The picker returned no files.',
  E_PICK_IN_PROGRESS: 'A file picker is already open.',
  E_NO_ACTIVITY: 'The app is not in the foreground.',
  E_FILE_TOO_LARGE: 'That file is larger than the scan limit.',
  E_SCAN_FAILED: 'The file could not be scanned.',
  E_HASH_FAILED: 'The file could not be hashed.',
  E_CANCELLED: 'The scan was cancelled.',
};

/** True when the native scanning engine is compiled into this build. */
export function isFileScannerAvailable(): boolean {
  return Platform.OS === 'android' && nativeModule != null;
}

/** The configurable maximum file size, in bytes. */
export function getMaxFileSize(): number {
  return nativeModule?.MAX_FILE_SIZE ?? 100 * 1024 * 1024;
}

/** The MIME types the picker offers. */
export function getSupportedMimeTypes(): string[] {
  return nativeModule?.SUPPORTED_MIME_TYPES ?? [];
}

/** Turn a rejected bridge error into a message we are happy to show the user. */
export function describeFileScannerError(error: unknown): string {
  if (error && typeof error === 'object') {
    const code = (error as { code?: string }).code;
    if (code && ERROR_MESSAGES[code]) {
      return ERROR_MESSAGES[code];
    }
    const message = (error as { message?: string }).message;
    if (message) {
      return message;
    }
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return 'Something went wrong while scanning the file.';
}

/**
 * True when the rejection just means "the user closed the picker". The UI
 * should treat this as a normal outcome, not an error.
 */
export function isPickCancelled(error: unknown): boolean {
  return (
    !!error &&
    typeof error === 'object' &&
    ((error as { code?: string }).code === 'E_PICK_CANCELLED' ||
      (error as { code?: string }).code === 'E_PICK_EMPTY')
  );
}

function requireModule(): FileScannerNativeModule {
  if (!nativeModule) {
    throw new Error('The native file-scanning engine is not available in this build.');
  }
  return nativeModule;
}

/**
 * Opens the system document picker and resolves with the selected content URIs.
 * Rejects with an error carrying `code === 'E_PICK_CANCELLED'` when dismissed.
 */
export async function pickFiles(multiple = false): Promise<string[]> {
  const uris = await requireModule().pickFile(multiple);
  return Array.isArray(uris) ? uris : [];
}

/** Computes the SHA-256 fingerprint of a previously-picked file. */
export async function computeFileHash(uri: string): Promise<string> {
  const result = await requireModule().computeFileHash(uri);
  return result.hash;
}

/** Inspects a previously-picked file locally and returns the structured result. */
export async function scanFile(uri: string): Promise<NativeFileScanResult> {
  return requireModule().scanFile(uri);
}

/** Asks the native engine to stop the current scan or hash. */
export async function cancelScan(): Promise<void> {
  if (!nativeModule) {
    return;
  }
  await nativeModule.cancelScan();
}

/** Deletes every cached copy the native engine has created. */
export async function clearFileCache(): Promise<void> {
  if (!nativeModule) {
    return;
  }
  await nativeModule.clearCache();
}

let emitter: NativeEventEmitter | null = null;

function getEmitter(): NativeEventEmitter | null {
  if (!nativeModule) {
    return null;
  }
  if (emitter == null) {
    emitter = new NativeEventEmitter(nativeModule as unknown as never);
  }
  return emitter;
}

/**
 * Subscribes to scan progress. Returns an unsubscribe function. Safe to call
 * when the engine is absent — the returned function is simply a no-op.
 */
export function addScanProgressListener(
  listener: (progress: ScanProgress) => void,
): () => void {
  const nativeEmitter = getEmitter();
  if (!nativeEmitter) {
    return () => undefined;
  }
  const subscription = nativeEmitter.addListener(PROGRESS_EVENT, (payload: unknown) =>
    listener(payload as ScanProgress),
  );
  return () => subscription.remove();
}
