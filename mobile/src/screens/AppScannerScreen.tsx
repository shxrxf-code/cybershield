import React, { useMemo, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Badge,
  Button,
  Card,
  Chip,
  ListRow,
  Screen,
  SectionHeader,
} from '../components/ui';
import {
  AppWindow,
  Info as InfoIcon,
  Package,
  ShieldAlert,
  Search,
  X,
  ChevronRight,
} from 'lucide-react-native';
import { useAppScanner } from '../hooks/useAppScanner';
import { statusTone, toneDotRole } from '../domain/threat';
import { capabilities } from '../capabilities';

type Filter = 'all' | 'high' | 'medium' | 'low' | 'system' | 'user';

const FILTERS = [
  { id: 'all' as Filter, label: 'All apps' },
  { id: 'high' as Filter, label: 'High risk' },
  { id: 'medium' as Filter, label: 'Medium risk' },
  { id: 'low' as Filter, label: 'Low risk' },
  { id: 'system' as Filter, label: 'System apps' },
  { id: 'user' as Filter, label: 'User apps' },
] as const;

const RISK_TO_VERDICT: Record<string, 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN'> = {
  LOW: 'SAFE',
  MEDIUM: 'SUSPICIOUS',
  HIGH: 'MALICIOUS',
};

const RISK_TONES: Record<string, 'safe' | 'suspicious' | 'malicious' | 'unknown'> = {
  LOW: 'safe',
  MEDIUM: 'suspicious',
  HIGH: 'malicious',
};

/**
 * Reviews installed applications. Enumerates packages and their permissions
 * using the Android PackageManager through a native module.
 */
export function AppScannerScreen(): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: { gap: theme.spacing.xl },
        section: { gap: theme.spacing.md },
        header: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm },
        chipRow: { flexDirection: 'row', flexWrap: 'wrap', gap: theme.spacing.sm },
        emptyState: {
          padding: theme.spacing.lg,
          flexDirection: 'row',
          gap: theme.spacing.md,
          alignItems: 'center',
        },
        flex1: { flex: 1 },
        divider: {
          height: 1,
          marginLeft: theme.spacing.lg,
          backgroundColor: theme.colors.border,
        },
        dot: { width: 10, height: 10, borderRadius: 5 },
        row: { flexDirection: 'row', gap: theme.spacing.md },
        flex1Gap2: { flex: 1, gap: 2 },
        summaryRow: { flexDirection: 'row', gap: theme.spacing.md },
        summaryCard: { flex: 1, padding: theme.spacing.md, gap: theme.spacing.xs },
        summaryValue: { fontSize: 24, fontWeight: '700' },
        summaryLabel: { fontSize: 12, color: theme.colors.textTertiary },
        appRow: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.md },
        appInfo: { flex: 1, gap: 2 },
        appMeta: { flexDirection: 'row', gap: theme.spacing.sm, alignItems: 'center' },
        permissionChip: { marginTop: theme.spacing.xs },
        permissionChips: { flexDirection: 'row', flexWrap: 'wrap', gap: theme.spacing.xs },
        permissionList: { gap: theme.spacing.xs, marginTop: theme.spacing.sm },
        permissionRow: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.xs },
        permissionDot: { width: 6, height: 6, borderRadius: 3 },
        reasonList: { gap: theme.spacing.xs, marginTop: theme.spacing.sm },
        reasonItem: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.xs },
        expandArea: { paddingTop: theme.spacing.sm, borderTopWidth: 1, borderTopColor: theme.colors.border },
      }),
    [theme],
  );
  const {
    isAvailable,
    isInspecting,
    error,
    results,
    totals,
    runInspection,
    stopInspection,
  } = useAppScanner();

  const [filter, setFilter] = useState<Filter>('all');
  const [expandedPackage, setExpandedPackage] = useState<string | null>(null);

  const available = capabilities.appScan && isAvailable;

  const filteredResults = useMemo(() => {
    return results.filter((app) => {
      switch (filter) {
        case 'high':
          return app.riskLevel === 'HIGH';
        case 'medium':
          return app.riskLevel === 'MEDIUM';
        case 'low':
          return app.riskLevel === 'LOW';
        case 'system':
          return app.isSystemApp;
        case 'user':
          return !app.isSystemApp;
        default:
          return true;
      }
    });
  }, [results, filter]);

  const handleFilterPress = (f: Filter) => {
    setFilter(f);
    setExpandedPackage(null);
  };

  const handleExpand = (packageName: string) => {
    setExpandedPackage(expandedPackage === packageName ? null : packageName);
  };

  const renderPermissionChips = (perms: InspectedApp['requestedPermissions']) => {
    const sensitive = perms.filter((p) => p.isSensitive);
    if (sensitive.length === 0) return null;
    return (
      <View style={styles.permissionChips}>
        {sensitive.slice(0, 5).map((p, i) => (
          <Badge
            key={`${p.name}-${i}`}
            label={p.label}
            tone={p.granted ? 'suspicious' : 'unknown'}
            size="sm"
            style={styles.permissionChip}
          />
        ))}
        {sensitive.length > 5 && (
          <Badge
            label={`+${sensitive.length - 5} more`}
            tone="unknown"
            size="sm"
            style={styles.permissionChip}
          />
        )}
      </View>
    );
  };

  const renderReasons = (reasons: string[]) => {
    if (reasons.length === 0) return null;
    return (
      <View style={styles.reasonList}>
        {reasons.map((r, i) => (
          <View key={i} style={styles.reasonItem}>
            <ShieldAlert size={12} color={theme.colors.textTertiary} />
            <AppText variant="caption" color="secondary">
              {r}
            </AppText>
          </View>
        ))}
      </View>
    );
  };

  const renderPermissionDetails = (perms: InspectedApp['requestedPermissions']) => {
    return (
      <View style={styles.permissionList}>
        {perms.map((p, i) => (
          <View key={`${p.name}-${i}`} style={styles.permissionRow}>
            <View
              style={[
                styles.permissionDot,
                {
                  backgroundColor: p.isSensitive
                    ? p.granted
                      ? theme.colors.suspicious
                      : theme.colors.textTertiary
                    : theme.colors.textTertiary,
                },
              ]}
            />
            <AppText
              variant="caption"
              color={p.isSensitive ? (p.granted ? 'primary' : 'secondary') : 'secondary'}
            >
              {p.label}
              {p.granted ? ' (granted)' : ''}
            </AppText>
          </View>
        ))}
      </View>
    );
  };

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={styles.root}>
        <Card>
          <View style={styles.section}>
            <View style={styles.header}>
              <AppWindow size={24} color={theme.colors.accent} />
              <AppText variant="heading">Check installed apps</AppText>
            </View>
            <AppText variant="body" color="secondary">
              Review the apps on this device for risky permission combinations, missing signatures
              and known-harmful packages. The inspection runs locally and never uploads your app list.
            </AppText>
          </View>
        </Card>

        {!available ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="App inspection not available"
            message="The native app inspection module is not included in this build. Enable the capability to use this feature."
          />
        ) : null}

        {available && error ? (
          <AlertBanner
            tone="malicious"
            icon={<ShieldAlert size={20} color={theme.colors.malicious} />}
            title="Inspection failed"
            message={error}
            action={
              <Button label="Retry" variant="secondary" size="sm" onPress={runInspection} />
            }
          />
        ) : null}

        {available && !isInspecting && results.length === 0 && !error ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="No inspection run yet"
            message="Tap 'Scan installed apps' below to start reviewing applications on this device."
          />
        ) : null}

        {available && totals.totalApps > 0 && (
          <View>
            <SectionHeader title="Summary" />
            <View style={styles.summaryRow}>
              <View style={styles.summaryCard}>
                <AppText variant="heading" style={styles.summaryValue}>
                  {totals.totalApps}
                </AppText>
                <AppText variant="caption" style={styles.summaryLabel}>
                  Total apps
                </AppText>
              </View>
              <View style={styles.summaryCard}>
                <AppText
                  variant="heading"
                  style={[
                    styles.summaryValue,
                    { color: theme.colors[statusTone(RISK_TO_VERDICT.LOW)] },
                  ]}
                >
                  {totals.lowRisk}
                </AppText>
                <AppText variant="caption" style={styles.summaryLabel}>
                  Low risk
                </AppText>
              </View>
              <View style={styles.summaryCard}>
                <AppText
                  variant="heading"
                  style={[
                    styles.summaryValue,
                    { color: theme.colors[statusTone(RISK_TO_VERDICT.MEDIUM)] },
                  ]}
                >
                  {totals.mediumRisk}
                </AppText>
                <AppText variant="caption" style={styles.summaryLabel}>
                  Medium risk
                </AppText>
              </View>
              <View style={styles.summaryCard}>
                <AppText
                  variant="heading"
                  style={[
                    styles.summaryValue,
                    { color: theme.colors[statusTone(RISK_TO_VERDICT.HIGH)] },
                  ]}
                >
                  {totals.highRisk}
                </AppText>
                <AppText variant="caption" style={styles.summaryLabel}>
                  High risk
                </AppText>
              </View>
            </View>
          </View>
        )}

        <View>
          <SectionHeader title="Review filters" />
          <View style={styles.chipRow}>
            {FILTERS.map((f) => (
              <Chip key={f.id} label={f.label} selected={filter === f.id} onPress={() => handleFilterPress(f.id)} />
            ))}
          </View>
        </View>

        <View>
          <SectionHeader
            title="Installed apps"
            subtitle={
              isInspecting
                ? 'Scanning...'
                : `${filteredResults.length} of ${totals.totalApps} apps`
            }
          />
          {isInspecting ? (
            <Card flush>
              <View style={styles.emptyState}>
                <Search size={18} color={theme.colors.accent} />
                <AppText variant="body" color="secondary" style={styles.flex1}>
                  Scanning installed applications...
                </AppText>
                <Button
                  label="Cancel"
                  variant="ghost"
                  size="sm"
                  onPress={stopInspection}
                  icon={<X size={16} />}
                />
              </View>
            </Card>
          ) : filteredResults.length === 0 ? (
            <Card flush>
              <View style={styles.emptyState}>
                <Package size={18} color={theme.colors.textTertiary} />
                <AppText variant="body" color="secondary" style={styles.flex1}>
                  {totals.totalApps === 0
                    ? 'No apps found. Run an inspection to list them here.'
                    : 'No apps match the current filter.'}
                </AppText>
              </View>
            </Card>
          ) : (
            <Card flush>
              {filteredResults.map((app, index) => (
                <React.Fragment key={app.packageName}>
                  {index > 0 ? <View style={styles.divider} /> : null}
                  <ListRow
                    title={app.appName}
                    subtitle={
                      app.isSystemApp
                        ? `System app · ${app.versionName} (${app.versionCode})`
                        : `${app.versionName} (${app.versionCode})`
                    }
                    meta={app.packageName}
                    leading={
                      <View
                        style={[
                          styles.dot,
                          {
                            backgroundColor: theme.colors[toneDotRole(RISK_TONES[app.riskLevel])],
                          },
                        ]}
                      />
                    }
                    trailing={
                      <Badge
                        label={app.riskLevel}
                        tone={RISK_TONES[app.riskLevel]}
                        size="sm"
                      />
                    }
                    onPress={() => handleExpand(app.packageName)}
                    accessibilityLabel={`${app.appName}, ${app.riskLevel} risk, ${app.sensitivePermissionsCount} sensitive permissions`}
                  />
                  {expandedPackage === app.packageName && (
                    <View style={styles.expandArea}>
                      <View style={styles.appRow}>
                        <View style={styles.appInfo}>
                          <AppText variant="bodyStrong">{app.appName}</AppText>
                          <AppText variant="caption" color="secondary">
                            {app.packageName}
                          </AppText>
                          <View style={styles.appMeta}>
                            <Badge
                              label={app.isSystemApp ? 'System app' : 'User app'}
                              tone={app.isSystemApp ? 'unknown' : 'safe'}
                              size="sm"
                            />
                            <Badge
                              label={`Target: ${app.targetSdkName}`}
                              tone="unknown"
                              size="sm"
                            />
                            <Badge
                              label={`${app.sensitivePermissionsCount}/${app.totalPermissionsCount} sensitive`}
                              tone={app.sensitivePermissionsCount > 5 ? 'suspicious' : 'unknown'}
                              size="sm"
                            />
                          </View>
                        </View>
                        <ChevronRight size={20} color={theme.colors.textTertiary} />
                      </View>

                      {renderPermissionChips(app.requestedPermissions)}

                      {renderReasons(app.reasons)}

                      <AppText variant="subheading" style={{ marginTop: theme.spacing.md }}>
                        All requested permissions
                      </AppText>
                      {renderPermissionDetails(app.requestedPermissions)}

                      <View style={styles.reasonList}>
                        <View style={styles.reasonItem}>
                          <InfoIcon size={12} color={theme.colors.textTertiary} />
                          <AppText variant="caption" color="secondary">
                            Installed from: {app.installationSource || 'Unknown'}
                          </AppText>
                        </View>
                        <View style={styles.reasonItem}>
                          <InfoIcon size={12} color={theme.colors.textTertiary} />
                          <AppText variant="caption" color="secondary">
                            Icon hash: {app.iconHash?.slice(0, 16) || 'N/A'}...
                          </AppText>
                        </View>
                      </View>
                    </View>
                  )}
                </React.Fragment>
              ))}
            </Card>
          )}
        </View>

        {available && (
          <Button
            label={isInspecting ? 'Scanning...' : 'Scan installed apps'}
            disabled={isInspecting}
            fullWidth
            onPress={isInspecting ? stopInspection : runInspection}
            icon={isInspecting ? <X size={18} /> : <Search size={18} />}
            loading={isInspecting}
          />
        )}
      </View>
    </Screen>
  );
}

interface InspectedApp {
  packageName: string;
  appName: string;
  versionName: string;
  versionCode: number;
  isSystemApp: boolean;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
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