import React, { useMemo } from 'react';
import { View } from 'react-native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Card,
  ListRow,
  SectionHeader,
  Screen,
  StatTile,
} from '../components/ui';
import { ShieldAlert, ShieldCheck, ScanLine, Bell, TriangleAlert, ChevronRight } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useAlertStore, useScanStore, useSettingsStore, selectScanTotals } from '../store';
import { statusTone, threatTypeLabel } from '../domain/threat';
import { formatRelativeTime } from '../utils/format';

/**
 * Dashboard: the app's home. Every figure comes from the live stores — there
 * are no hard-coded scores or sample rows here.
 */
export function DashboardScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();

  const records = useScanStore((s) => s.records);
  const alerts = useAlertStore((s) => s.alerts);
  const unread = useAlertStore((s) => s.alerts.filter((a) => !a.isRead).length);
  const notificationMonitoring = useSettingsStore((s) => s.notificationMonitoring);
  const backgroundProtection = useSettingsStore((s) => s.backgroundProtection);

  const totals = useMemo(() => selectScanTotals(records), [records]);
  const recentScans = records.slice(0, 3);
  const recentAlerts = alerts.slice(0, 3);
  const lastScan = records[0];

  const unprotected = !notificationMonitoring && !backgroundProtection;
  const hasUnreadThreat = unread > 0;

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        {/* Protection status */}
        <Card tone={unprotected ? 'suspicious' : 'safe'}>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              {unprotected ? (
                <ShieldAlert size={24} color={theme.colors.suspicious} />
              ) : (
                <ShieldCheck size={24} color={theme.colors.safe} />
              )}
              <AppText variant="heading">
                {unprotected ? 'Protection is limited' : 'Protection is active'}
              </AppText>
            </View>
            <AppText variant="body" color="secondary">
              {unprotected
                ? 'Enable message monitoring and background protection to catch threats automatically.'
                : 'Message monitoring and background protection are enabled.'}
            </AppText>
          </View>
        </Card>

        {/* Unread threat banner */}
        {hasUnreadThreat ? (
          <AlertBanner
            tone="malicious"
            icon={<TriangleAlert size={20} color={theme.colors.malicious} />}
            title={`${unread} unread ${unread === 1 ? 'alert' : 'alerts'}`}
            message="Review the flagged threats to decide what to do next."
            action={
              <View style={{ flexDirection: 'row', alignItems: 'center', gap: 4 }}>
                <AppText variant="label" color="malicious">
                  Open alerts
                </AppText>
                <ChevronRight size={16} color={theme.colors.malicious} />
              </View>
            }
          />
        ) : null}

        {/* Statistics */}
        <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
          <StatTile
            label="Scans run"
            value={totals.totalScans}
            icon={<ScanLine size={18} color={theme.colors.textTertiary} />}
            onPress={() => navigation.navigate('MainTabs', { screen: 'History' })}
          />
          <StatTile
            label="Threats found"
            value={totals.totalThreats}
            icon={<TriangleAlert size={18} color={theme.colors.textTertiary} />}
            onPress={() => navigation.navigate('MainTabs', { screen: 'Alerts' })}
          />
        </View>

        {/* Last scan */}
        <View>
          <SectionHeader
            title="Last scan"
            action={
              <AppText variant="label" color="accent" onPress={() => navigation.navigate('DeviceScan', { mode: 'quick' })}>
                Scan now
              </AppText>
            }
          />
          {lastScan ? (
            <Card
              tone={lastScan.threatsFound > 0 ? statusTone(lastScan.threatLevel) : 'safe'}
              onPress={() => navigation.navigate('ScanDetail', { scanId: lastScan.id })}
            >
              <View style={{ gap: theme.spacing.xs }}>
                <AppText variant="bodyStrong">
                  {lastScan.threatsFound > 0
                    ? `${lastScan.threatsFound} ${lastScan.threatsFound === 1 ? 'threat' : 'threats'} found`
                    : 'No threats found'}
                </AppText>
                <AppText variant="caption" color="secondary">
                  {formatRelativeTime(lastScan.scannedAt)} · {lastScan.filesChecked} checked
                </AppText>
              </View>
            </Card>
          ) : (
            <Card>
              <AppText variant="body" color="secondary">
                No scans yet. Run a quick scan to check this device.
              </AppText>
            </Card>
          )}
        </View>

        {/* Recent alerts */}
        <View>
          <SectionHeader
            title="Recent alerts"
            action={
              <AppText variant="label" color="accent" onPress={() => navigation.navigate('MainTabs', { screen: 'Alerts' })}>
                See all
              </AppText>
            }
          />
          <Card flush>
            {recentAlerts.length === 0 ? (
              <View style={{ padding: theme.spacing.lg, flexDirection: 'row', gap: theme.spacing.sm, alignItems: 'center' }}>
                <Bell size={18} color={theme.colors.textTertiary} />
                <AppText variant="body" color="secondary">
                  No alerts yet.
                </AppText>
              </View>
            ) : (
              recentAlerts.map((alert, index) => (
                <View key={alert.id}>
                  {index > 0 ? <View style={{ height: 1, backgroundColor: theme.colors.border }} /> : null}
                  <ListRow
                    title={threatTypeLabel(alert.threatType)}
                    subtitle={alert.target}
                    meta={formatRelativeTime(alert.createdAt)}
                    onPress={() => navigation.navigate('AlertDetail', { alertId: alert.id })}
                    trailing={
                      !alert.isRead ? (
                        <View
                          style={{
                            width: 10,
                            height: 10,
                            borderRadius: 5,
                            backgroundColor: theme.colors[severityToDot(alert.severity)],
                          }}
                        />
                      ) : undefined
                    }
                  />
                </View>
              ))
            )}
          </Card>
        </View>

        {/* Recent scans */}
        {recentScans.length > 0 ? (
          <View>
            <SectionHeader title="Recent scans" />
            <Card flush>
              {recentScans.map((scan, index) => (
                <View key={scan.id}>
                  {index > 0 ? <View style={{ height: 1, backgroundColor: theme.colors.border }} /> : null}
                  <ListRow
                    title={scan.target ?? scan.fileName ?? scan.scanType}
                    subtitle={`${scan.scanType} · ${scan.filesChecked} checked`}
                    meta={formatRelativeTime(scan.scannedAt)}
                    onPress={() => navigation.navigate('ScanDetail', { scanId: scan.id })}
                    leading={
                      <View
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: 4,
                          backgroundColor: theme.colors[severityToDot(scan.threatLevel)],
                        }}
                      />
                    }
                  />
                </View>
              ))}
            </Card>
          </View>
        ) : null}
      </View>
    </Screen>
  );
}

function severityToDot(severity: string): 'safe' | 'suspicious' | 'malicious' | 'unknown' {
  const tone = statusTone(severity as any);
  return tone === 'info' ? 'unknown' : (tone as 'safe' | 'suspicious' | 'malicious' | 'unknown');
}
