import React, { useMemo } from 'react';
import { Share, StyleSheet, View } from 'react-native';
import { useTheme } from '../theme';
import {
  AppText,
  Button,
  Card,
  Divider,
  EmptyState,
  ProgressBar,
  Screen,
  SectionHeader,
  StatTile,
} from '../components/ui';
import { CircleCheck, ClipboardList, Share2, ShieldAlert, ShieldCheck } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useAlertStore, useScanStore, useSettingsStore, selectScanTotals } from '../store';
import { severityTone, threatTypeLabel, toneDotRole } from '../domain/threat';
import { formatDateTime, formatRelativeTime } from '../utils/format';
import { APP_NAME, APP_VERSION } from '../config';
import type { Severity } from '../domain/types';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * A security summary built entirely from the live stores. Every number here is
 * derived from real records; when there is nothing to report, the screen says
 * so instead of showing zeros dressed up as findings.
 */
export function ReportScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();

  const records = useScanStore((s) => s.records);
  const alerts = useAlertStore((s) => s.alerts);
  const notificationMonitoring = useSettingsStore((s) => s.notificationMonitoring);
  const backgroundProtection = useSettingsStore((s) => s.backgroundProtection);

  const totals = useMemo(() => selectScanTotals(records), [records]);
  const unread = alerts.filter((a) => !a.isRead).length;

  const alertsBySeverity = useMemo(() => {
    const counts: Partial<Record<Severity, number>> = {};
    for (const alert of alerts) {
      counts[alert.severity] = (counts[alert.severity] ?? 0) + 1;
    }
    return counts;
  }, [alerts]);

  const maxSeverityCount = Math.max(1, ...SEVERITIES.map((s) => alertsBySeverity[s] ?? 0));
  const protectedNow = notificationMonitoring && backgroundProtection;
  const lastScan = records[0];
  const generatedAt = new Date().toISOString();

  const styles = useMemo(
    () =>
      StyleSheet.create({
        content: { gap: theme.spacing.xl },
        protectCard: { gap: theme.spacing.md },
        protectHeader: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm },
        flexFill: { flex: 1 },
        overviewRow: { flexDirection: 'row', gap: theme.spacing.md },
        severityList: { gap: theme.spacing.md },
        findingRow: {
          flexDirection: 'row',
          alignItems: 'center',
          gap: theme.spacing.md,
          paddingVertical: theme.spacing.md,
          paddingHorizontal: theme.spacing.lg,
        },
        dot: { width: 10, height: 10, borderRadius: 5 },
        dotSafe: { backgroundColor: theme.colors.safe },
        dotSuspicious: { backgroundColor: theme.colors.suspicious },
        dotMalicious: { backgroundColor: theme.colors.malicious },
        dotUnknown: { backgroundColor: theme.colors.unknown },
        findingBody: { flex: 1, gap: 2 },
        actions: { gap: theme.spacing.md },
      }),
    [theme],
  );

  const dotStyles = {
    safe: styles.dotSafe,
    suspicious: styles.dotSuspicious,
    malicious: styles.dotMalicious,
    unknown: styles.dotUnknown,
  };

  const buildSummary = (): string => {
    const lines = [
      `${APP_NAME} security report (v${APP_VERSION})`,
      `Generated: ${formatDateTime(generatedAt)}`,
      '',
      `Protection: ${protectedNow ? 'Active' : 'Limited'}`,
      `Message monitoring: ${notificationMonitoring ? 'On' : 'Off'}`,
      `Background protection: ${backgroundProtection ? 'On' : 'Off'}`,
      '',
      `Scans run: ${totals.totalScans}`,
      `Threats found: ${totals.totalThreats}`,
      `Alerts: ${alerts.length} (${unread} unread)`,
      lastScan ? `Last scan: ${formatDateTime(lastScan.scannedAt)}` : 'Last scan: none yet',
    ];
    return lines.join('\n');
  };

  const onShare = () => {
    void Share.share({ message: buildSummary(), title: 'ThreatGuard security report' });
  };

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={styles.content}>
        <Card tone={protectedNow ? 'safe' : 'suspicious'}>
          <View style={styles.protectCard}>
            <View style={styles.protectHeader}>
              {protectedNow ? (
                <ShieldCheck size={24} color={theme.colors.safe} />
              ) : (
                <ShieldAlert size={24} color={theme.colors.suspicious} />
              )}
              <AppText variant="heading" style={styles.flexFill}>
                {protectedNow ? 'Protection is active' : 'Protection is limited'}
              </AppText>
            </View>
            <AppText variant="body" color="secondary">
              {protectedNow
                ? 'Message monitoring and background protection are both switched on.'
                : 'Turn on message monitoring and background protection in Settings to close the gaps.'}
            </AppText>
          </View>
        </Card>

        <View>
          <SectionHeader title="Overview" />
          <View style={styles.overviewRow}>
            <StatTile label="Scans run" value={totals.totalScans} />
            <StatTile label="Threats found" value={totals.totalThreats} />
          </View>
        </View>

        <View>
          <SectionHeader title="Alerts by severity" subtitle={`${alerts.length} total · ${unread} unread`} />
          {alerts.length === 0 ? (
            <Card>
              <EmptyState
                icon={<CircleCheck size={32} color={theme.colors.textTertiary} />}
                title="No alerts"
                message="Nothing has been flagged yet. Alerts appear here as threats are detected."
              />
            </Card>
          ) : (
            <Card>
              <View style={styles.severityList}>
                {SEVERITIES.map((severity) => {
                  const count = alertsBySeverity[severity] ?? 0;
                  return (
                    <ProgressBar
                      key={severity}
                      label={severity.charAt(0).toUpperCase() + severity.slice(1)}
                      value={count / maxSeverityCount}
                      tone={severityTone(severity)}
                    />
                  );
                })}
              </View>
            </Card>
          )}
        </View>

        <View>
          <SectionHeader title="Recent findings" subtitle={lastScan ? formatRelativeTime(lastScan.scannedAt) : undefined} />
          {alerts.length === 0 ? (
            <Card>
              <AppText variant="body" color="secondary">
                No findings to list.
              </AppText>
            </Card>
          ) : (
            <Card flush>
              {alerts.slice(0, 5).map((alert, index) => (
                <View key={alert.id}>
                  {index > 0 ? <Divider /> : null}
                  <View
                    style={styles.findingRow}
                  >
                    <View
                      style={[styles.dot, dotStyles[toneDotRole(severityTone(alert.severity))]]}
                    />
                    <View style={styles.findingBody}>
                      <AppText variant="bodyStrong" numberOfLines={1}>
                        {threatTypeLabel(alert.threatType)}
                      </AppText>
                      <AppText variant="caption" color="secondary" numberOfLines={1}>
                        {alert.target ?? alert.detectionReason}
                      </AppText>
                    </View>
                    <AppText variant="caption" color="tertiary">
                      {formatRelativeTime(alert.createdAt)}
                    </AppText>
                  </View>
                </View>
              ))}
            </Card>
          )}
        </View>

        <View style={styles.actions}>
          <Button
            label="Share report"
            variant="secondary"
            icon={<Share2 size={18} color={theme.colors.accent} />}
            fullWidth
            onPress={onShare}
            accessibilityHint="Opens the system share sheet with a text summary"
          />
          <Button
            label="View full history"
            variant="ghost"
            icon={<ClipboardList size={18} color={theme.colors.textSecondary} />}
            fullWidth
            onPress={() => navigation.navigate('MainTabs', { screen: 'History' })}
          />
          <AppText variant="caption" color="tertiary" align="center">
            Generated {formatDateTime(generatedAt)}
          </AppText>
        </View>
      </View>
    </Screen>
  );
}
