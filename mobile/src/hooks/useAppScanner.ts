/**
 * React hooks for the on-device app inspection engine.
 *
 * The hook owns the full lifecycle: starting the inspection, streaming
 * progress (if available), and returning structured results with permission
 * details and risk assessments. The heavy lifting happens in the native
 * module on a background thread; this hook only holds UI state.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  cancelInspection,
  describeAppInspectionError,
  inspectAllApps,
  inspectPackage,
  isAppInspectionAvailable,
  type AppInspectionResult,
  type AppRiskLevel,
} from '../native/AppInspectionNative';
import { capabilities } from '../capabilities';

/** A simplified view of an inspected app for the UI. */
export interface InspectedApp {
  packageName: string;
  appName: string;
  versionName: string;
  versionCode: number;
  isSystemApp: boolean;
  riskLevel: AppRiskLevel;
  sensitivePermissionsCount: number;
  totalPermissionsCount: number;
  reasons: string[];
  installationSource: string;
  targetSdkVersion: number;
  targetSdkName: string;
  iconHash: string;
  requestedPermissions: Array<{
    name: string;
    label: string;
    isSensitive: boolean;
    granted: boolean;
  }>;
}

/** Summary counts for the dashboard. */
export interface AppInspectionTotals {
  totalApps: number;
  lowRisk: number;
  mediumRisk: number;
  highRisk: number;
  systemApps: number;
  userApps: number;
}

/**
 * Hook for running a full app inspection.
 */
export function useAppScanner() {
  const isAvailable = capabilities.appScan && isAppInspectionAvailable();
  const [isInspecting, setIsInspecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<InspectedApp[]>([]);
  const [totals, setTotals] = useState<AppInspectionTotals>({
    totalApps: 0,
    lowRisk: 0,
    mediumRisk: 0,
    highRisk: 0,
    systemApps: 0,
    userApps: 0,
  });
  const cancelledRef = useRef(false);

  const computeTotals = useCallback((apps: InspectedApp[]): AppInspectionTotals => {
    const t: AppInspectionTotals = {
      totalApps: apps.length,
      lowRisk: 0,
      mediumRisk: 0,
      highRisk: 0,
      systemApps: 0,
      userApps: 0,
    };
    for (const app of apps) {
      if (app.riskLevel === 'LOW') t.lowRisk++;
      else if (app.riskLevel === 'MEDIUM') t.mediumRisk++;
      else t.highRisk++;
      if (app.isSystemApp) t.systemApps++;
      else t.userApps++;
    }
    return t;
  }, []);

  const mapResult = useCallback((raw: AppInspectionResult): InspectedApp => {
    const sensitiveCount = raw.requestedPermissions.filter((p) => p.isSensitive).length;
    return {
      packageName: raw.packageName,
      appName: raw.appName,
      versionName: raw.versionName,
      versionCode: raw.versionCode,
      isSystemApp: raw.isSystemApp,
      riskLevel: raw.riskLevel,
      sensitivePermissionsCount: sensitiveCount,
      totalPermissionsCount: raw.requestedPermissions.length,
      reasons: raw.reasons,
      installationSource: raw.installationSource,
      targetSdkVersion: raw.targetSdkVersion,
      targetSdkName: raw.targetSdkName,
      iconHash: raw.iconHash,
      requestedPermissions: raw.requestedPermissions,
    };
  }, []);

  const runInspection = useCallback(async () => {
    if (!isAvailable) {
      setError('App inspection is not available in this build.');
      return;
    }
    if (isInspecting) return;

    cancelledRef.current = false;
    setIsInspecting(true);
    setError(null);

    try {
      const rawResults = await inspectAllApps();
      if (cancelledRef.current) return;

      const mapped = rawResults.map(mapResult);
      setResults(mapped);
      setTotals(computeTotals(mapped));
    } catch (err) {
      if (cancelledRef.current) return;
      setError(describeAppInspectionError(err));
      setResults([]);
      setTotals({
        totalApps: 0,
        lowRisk: 0,
        mediumRisk: 0,
        highRisk: 0,
        systemApps: 0,
        userApps: 0,
      });
    } finally {
      if (!cancelledRef.current) {
        setIsInspecting(false);
      }
    }
  }, [isAvailable, isInspecting, mapResult, computeTotals]);

  const stopInspection = useCallback(async () => {
    cancelledRef.current = true;
    await cancelInspection();
    setIsInspecting(false);
  }, []);

  const inspectSinglePackage = useCallback(
    async (packageName: string): Promise<InspectedApp | null> => {
      if (!isAvailable) return null;
      try {
        const raw = await inspectPackage(packageName);
        return mapResult(raw);
      } catch {
        return null;
      }
    },
    [isAvailable, mapResult],
  );

  useEffect(() => {
    return () => {
      cancelledRef.current = true;
    };
  }, []);

  return {
    isAvailable,
    isInspecting,
    error,
    results,
    totals,
    runInspection,
    stopInspection,
    inspectSinglePackage,
  };
}

/**
 * Hook for running a single package inspection.
 */
export function useSinglePackageInspector() {
  const isAvailable = capabilities.appScan && isAppInspectionAvailable();
  const [isInspecting, setIsInspecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InspectedApp | null>(null);

  const mapResult = useCallback((raw: AppInspectionResult): InspectedApp => {
    const sensitiveCount = raw.requestedPermissions.filter((p) => p.isSensitive).length;
    return {
      packageName: raw.packageName,
      appName: raw.appName,
      versionName: raw.versionName,
      versionCode: raw.versionCode,
      isSystemApp: raw.isSystemApp,
      riskLevel: raw.riskLevel,
      sensitivePermissionsCount: sensitiveCount,
      totalPermissionsCount: raw.requestedPermissions.length,
      reasons: raw.reasons,
      installationSource: raw.installationSource,
      targetSdkVersion: raw.targetSdkVersion,
      targetSdkName: raw.targetSdkName,
      iconHash: raw.iconHash,
      requestedPermissions: raw.requestedPermissions,
    };
  }, []);

  const inspect = useCallback(
    async (packageName: string) => {
      if (!isAvailable) {
        setError('App inspection is not available in this build.');
        return;
      }
      if (isInspecting) return;

      setIsInspecting(true);
      setError(null);

      try {
        const raw = await inspectPackage(packageName);
        setResult(mapResult(raw));
      } catch (err) {
        setError(describeAppInspectionError(err));
        setResult(null);
      } finally {
        setIsInspecting(false);
      }
    },
    [isAvailable, isInspecting, mapResult],
  );

  return {
    isAvailable,
    isInspecting,
    error,
    result,
    inspect,
  };
}