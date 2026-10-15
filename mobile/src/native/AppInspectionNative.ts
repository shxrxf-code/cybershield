/**
 * TypeScript bridge to the native Android `AppInspection` module.
 *
 * The native engine enumerates installed applications via PackageManager and
 * analyses their permissions and risk profile. All heavy work runs on a
 * background thread. This module only marshals values across the bridge and
 * keeps the surface area small and typed.
 *
 * If the native module is missing (iOS, an older build, or unit tests) every
 * helper degrades safely instead of throwing at import time.
 */

import { NativeModules, Platform } from 'react-native';

export type AppRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export interface AppPermissionInfo {
  name: string;
  label: string;
  isSensitive: boolean;
  granted: boolean;
}

export interface AppInspectionResult {
  packageName: string;
  appName: string;
  versionName: string;
  versionCode: number;
  isSystemApp: boolean;
  riskLevel: AppRiskLevel;
  requestedPermissions: AppPermissionInfo[];
  reasons: string[];
  installationSource: string;
  targetSdkVersion: number;
  targetSdkName: string;
  iconHash: string;
}

interface AppInspectionNativeModule {
  inspectAllApps(): Promise<AppInspectionResult[]>;
  inspectPackage(packageName: string): Promise<AppInspectionResult>;
  cancelInspection(): Promise<boolean>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
  ENGINE_VERSION?: number;
}

const nativeModule = (NativeModules as Record<string, unknown>).AppInspection as
  | AppInspectionNativeModule
  | undefined;

/** True when the native app inspection engine is compiled into this build. */
export function isAppInspectionAvailable(): boolean {
  return Platform.OS === 'android' && nativeModule != null;
}

/** Human-readable messages for the errors the native module can reject with. */
const ERROR_MESSAGES: Record<string, string> = {
  E_SCAN_IN_PROGRESS: 'An app inspection is already running.',
  E_INSPECTION_FAILED: 'Failed to inspect installed apps.',
  E_NOT_FOUND: 'Package not found or could not be analyzed.',
  E_SERIALIZE: 'Failed to serialize inspection results.',
};

/** Turn a rejected bridge error into a message we are happy to show the user. */
export function describeAppInspectionError(error: unknown): string {
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
  return 'Something went wrong while inspecting apps.';
}

function requireModule(): AppInspectionNativeModule {
  if (!nativeModule) {
    throw new Error('The native app inspection engine is not available in this build.');
  }
  return nativeModule;
}

/**
 * Performs a full inspection of all visible installed applications.
 * Returns an array of results with permission details and risk assessments.
 */
export async function inspectAllApps(): Promise<AppInspectionResult[]> {
  const results = await requireModule().inspectAllApps();
  return Array.isArray(results) ? results : [];
}

/**
 * Inspects a single package by name.
 */
export async function inspectPackage(packageName: string): Promise<AppInspectionResult> {
  return requireModule().inspectPackage(packageName);
}

/**
 * Asks the native engine to stop the current inspection.
 */
export async function cancelInspection(): Promise<void> {
  if (!nativeModule) {
    return;
  }
  await nativeModule.cancelInspection();
}