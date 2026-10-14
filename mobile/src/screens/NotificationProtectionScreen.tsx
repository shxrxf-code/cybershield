import React, { useCallback, useMemo, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Badge,
  Button,
  Card,
  Divider,
  EmptyState,
  Screen,
  SectionHeader,
  SettingRow,
} from '../components/ui';
import {
  Bell,
  BellRing,
  ExternalLink,
  Info as InfoIcon,
  Lock,
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useSettingsStore } from '../store';
import { useNotificationMonitor } from '../hooks/useNotificationMonitor';
import { openNotificationSettings } from '../native/NotificationMonitorNative';
import { categoryLabel, severityLabel, severityTone } from '../domain/threat';
import { formatRelativeTime } from '../utils/format';
import type { RecentFinding } from '../notifications/monitor';

/**
 * Social-protection controls for message monitoring.
 *
 * The listener and the scam analyser are real in this build: this screen drives
 * the genuine Android notification-access permission, runs the on-device
 * analysis and lists what it has seen. Nothing is simulated — when a control
 * cannot work yet (a non-Android runtime, or notification posting not being
 * permitted) it says so plainly instead of pretending.
 */
export function NotificationProtectionScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const monitoring = useSettingsStore((s) => s.notificationMonitoring);
  const setMonitoring = useSettingsStore((s) => s.setNotificationMonitoring);
  const alertNotifications = useSettingsStore((s) => s.alertNotifications);
  const setAlertNotifications = useSettingsStore((s) => s.setAlertNotifications);

  const {
    state,
    ignoredPackages,
    recent,
    sources,
    refresh,
    clearSources,
    setPackageMonitored,
    requestNotificationPermission,
    canPostNotifications,
  } = useNotificationMonitor();

  const [permissionNotice, setPermissionNotice] = useState(false);

  const openNotificationAccess = useCallback(() => {
    // The native module opens the real settings screen; refresh on return.
    openNotificationSettings();
  }, []);

  const handleToggleAlertNotifications = useCallback(
    async (value: boolean) => {
      if (value && !canPostNotifications) {
        const granted = await requestNotificationPermission();
        if (!granted) {
          setPermissionNotice(true);
          return;
        }
      }
      setPermissionNotice(false);
      await setAlertNotifications(value);
    },
    [canPostNotifications, requestNotificationPermission, setAlertNotifications],
  );

  const handleToggleMonitoring = useCallback(
    async (value: boolean) => {
      await setMonitoring(value);
      await refresh();
    },
    [setMonitoring, refresh],
  );

  const styles = useMemo(
    () =>
      StyleSheet.create({
        content: { gap: theme.spacing.xl },
        intro: { flexDirection: 'row', gap: theme.spacing.md },
        introBody: { flex: 1, gap: theme.spacing.xs },
        permissionNotice: { marginTop: theme.spacing.sm, paddingHorizontal: theme.spacing.xs },
        forgetRow: { marginTop: theme.spacing.sm },
        gapMd: { gap: theme.spacing.md },
        privacyCard: { gap: theme.spacing.md },
        privacyHeader: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm },
      }),
    [theme],
  );

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={styles.content}>
        <Card>
          <View style={styles.intro}>
            <MessageSquare size={24} color={theme.colors.accent} />
            <View style={styles.introBody}>
              <AppText variant="heading">Message monitoring</AppText>
              <AppText variant="body" color="secondary">
                Watch message notifications for scam and phishing signals, then warn you before you
                tap anything.
              </AppText>
            </View>
          </View>
        </Card>

        <StatusBanner
          available={state.available}
          accessGranted={state.accessGranted}
          connected={state.connected}
          monitoring={monitoring}
          onOpenSettings={openNotificationAccess}
        />

        <View>
          <SectionHeader title="Monitoring" />
          <Card flush>
            <SettingRow
              title="Monitor message notifications"
              description="Read the text Android exposes and check it for scam wording and suspicious links."
              value={monitoring}
              onValueChange={handleToggleMonitoring}
              icon={<Bell size={20} color={monitoring ? theme.colors.safe : theme.colors.textSecondary} />}
            />
            <Divider />
            <SettingRow
              title="Notify me about threats"
              description="Show a system notification when a monitored message is flagged."
              value={alertNotifications}
              onValueChange={handleToggleAlertNotifications}
              icon={<BellRing size={20} color={theme.colors.textSecondary} />}
            />
          </Card>
          {permissionNotice ? (
            <AppText
              variant="caption"
              color="secondary"
              style={styles.permissionNotice}
            >
              Android didn&apos;t grant notification permission, so system alerts stay off. You can
              enable them in system settings.
            </AppText>
          ) : null}
        </View>

        <View>
          <SectionHeader
            title="Apps to monitor"
            subtitle="Mute any app you would rather not have checked"
          />
          {sources.length === 0 ? (
            <Card>
              <EmptyState
                title="No apps seen yet"
                message="Once monitoring is on and an app posts a notification, it appears here so you can mute it if you want."
                icon={<Bell size={28} color={theme.colors.textTertiary} />}
              />
            </Card>
          ) : (
            <Card flush>
              {sources.slice(0, 20).map((source, index) => (
                <React.Fragment key={source.packageName}>
                  {index > 0 ? <Divider /> : null}
                  <SettingRow
                    title={source.appLabel}
                    description={source.packageName}
                    value={!ignoredPackages.includes(source.packageName)}
                    onValueChange={(value) => {
                      void setPackageMonitored(source.packageName, value);
                    }}
                  />
                </React.Fragment>
              ))}
            </Card>
          )}
          {sources.length > 0 ? (
            <View style={styles.forgetRow}>
              <Button
                label="Forget this list"
                variant="ghost"
                onPress={() => {
                  void clearSources();
                }}
              />
            </View>
          ) : null}
        </View>

        <View>
          <SectionHeader
            title="Recent findings"
            subtitle="Signals seen since the app started — the message text is not kept"
          />
          {recent.length === 0 ? (
            <Card>
              <EmptyState
                title="Nothing flagged yet"
                message="Messages with scam or phishing signals will be summarised here. Benign messages are not listed."
                icon={<ShieldCheck size={28} color={theme.colors.textTertiary} />}
              />
            </Card>
          ) : (
            <View style={styles.gapMd}>
              {recent.map((finding) => (
                <FindingCard key={finding.id} finding={finding} />
              ))}
            </View>
          )}
        </View>

        <View>
          <SectionHeader title="System access" subtitle="Granted in Android settings, not in this app" />
          <Card>
            <View style={styles.gapMd}>
              <AppText variant="body" color="secondary">
                Android only lets an app read notifications if you allow notification access for it.
                ThreatGuard can only see the content Android exposes — it cannot open other apps or
                read their private data.
              </AppText>
              <Button
                label="Open notification access"
                variant="secondary"
                icon={<ExternalLink size={18} color={theme.colors.accent} />}
                onPress={openNotificationAccess}
              />
            </View>
          </Card>
        </View>

        <Card>
          <View style={styles.privacyCard}>
            <View style={styles.privacyHeader}>
              <Lock size={18} color={theme.colors.textSecondary} />
              <AppText variant="subheading">Privacy limits</AppText>
            </View>
            <AppText variant="body" color="secondary">
              Message text is analysed on this device and is never uploaded. The full message is
              discarded; an alert keeps only the reason it was flagged and a short redacted preview
              (links reduced to their host, emails and long numbers masked). ThreatGuard does not
              access private app data, bypass the Android sandbox, or intercept encrypted traffic.
            </AppText>
            <Button
              label="Review privacy and permissions"
              variant="ghost"
              icon={<ShieldAlert size={18} color={theme.colors.textSecondary} />}
              onPress={() => navigation.navigate('Permissions')}
            />
          </View>
        </Card>

        <View>
          <SectionHeader title="What an alert tells you" />
          <Card flush>
            <AlertField icon={<MessageSquare size={18} color={theme.colors.textSecondary} />} label="Source app" />
            <Divider />
            <AlertField icon={<TriangleAlert size={18} color={theme.colors.textSecondary} />} label="Threat type and severity" />
            <Divider />
            <AlertField icon={<ShieldAlert size={18} color={theme.colors.textSecondary} />} label="Why it was flagged" />
            <Divider />
            <AlertField icon={<Lock size={18} color={theme.colors.textSecondary} />} label="A recommended action, without opening anything" />
          </Card>
        </View>
      </View>
    </Screen>
  );
}

interface StatusBannerProps {
  available: boolean;
  accessGranted: boolean;
  connected: boolean;
  monitoring: boolean;
  onOpenSettings: () => void;
}

/** A truthful banner describing exactly where monitoring stands right now. */
function StatusBanner({
  available,
  accessGranted,
  connected,
  monitoring,
  onOpenSettings,
}: StatusBannerProps): React.JSX.Element | null {
  const theme = useTheme();

  if (!available) {
    return (
      <AlertBanner
        tone="info"
        icon={<InfoIcon size={20} color={theme.colors.info} />}
        title="Not available on this platform"
        message="The notification listener is Android-only. On other platforms no monitoring runs."
      />
    );
  }

  if (!accessGranted) {
    return (
      <AlertBanner
        tone={monitoring ? 'suspicious' : 'info'}
        icon={<InfoIcon size={20} color={monitoring ? theme.colors.suspicious : theme.colors.info} />}
        title="Notification access is off"
        message={
          monitoring
            ? 'Monitoring is switched on, but Android has not granted notification access yet. Turn it on for ThreatGuard to start checking messages.'
            : 'ThreatGuard cannot read notifications until you allow notification access in Android settings.'
        }
        action={
          <Button
            label="Grant access"
            variant={monitoring ? 'primary' : 'secondary'}
            onPress={onOpenSettings}
          />
        }
      />
    );
  }

  if (!monitoring) {
    return (
      <AlertBanner
        tone="info"
        icon={<InfoIcon size={20} color={theme.colors.info} />}
        title="Access granted — monitoring is paused"
        message="Notification access is allowed, but monitoring is switched off. Nothing is being checked."
      />
    );
  }

  if (!connected) {
    return (
      <AlertBanner
        tone="info"
        icon={<InfoIcon size={20} color={theme.colors.info} />}
        title="Waiting for Android to connect"
        message="Access is granted and monitoring is on. Android sometimes takes a moment to bind the listener; new messages will be checked once it connects."
      />
    );
  }

  return (
    <AlertBanner
      tone="safe"
      icon={<ShieldCheck size={20} color={theme.colors.safe} />}
      title="Monitoring is active"
      message="ThreatGuard is checking the notifications Android exposes and will flag scam or phishing wording."
    />
  );
}

function FindingCard({ finding }: { finding: RecentFinding }): React.JSX.Element {
  const theme = useTheme();
  const tone = severityTone(finding.severity);
  const findingStyles = useMemo(
    () =>
      StyleSheet.create({
        root: { gap: theme.spacing.sm },
        header: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm },
        flexFill: { flex: 1 },
        badges: { flexDirection: 'row', gap: theme.spacing.sm, flexWrap: 'wrap' },
      }),
    [theme],
  );

  return (
    <Card>
      <View style={findingStyles.root}>
        <View style={findingStyles.header}>
          <ShieldAlert size={18} color={theme.colors[tone]} />
          <AppText variant="bodyStrong" style={findingStyles.flexFill} numberOfLines={1}>
            {finding.appLabel}
          </AppText>
          <AppText variant="caption" color="secondary">
            {formatRelativeTime(finding.at)}
          </AppText>
        </View>

        <View style={findingStyles.badges}>
          <Badge label={severityLabel(finding.severity)} tone={tone} size="sm" />
          <Badge label={categoryLabel(finding.category)} tone="unknown" size="sm" />
          {finding.alerted ? <Badge label="Alert raised" tone="suspicious" size="sm" /> : null}
        </View>

        <AppText variant="caption" color="secondary">
          {finding.signalLabels.join(' • ')}
        </AppText>
      </View>
    </Card>
  );
}

interface AlertFieldProps {
  icon: React.ReactNode;
  label: string;
}

function AlertField({ icon, label }: AlertFieldProps): React.JSX.Element {
  const theme = useTheme();
  const fieldStyles = useMemo(
    () =>
      StyleSheet.create({
        root: {
          flexDirection: 'row',
          alignItems: 'center',
          gap: theme.spacing.md,
          paddingVertical: theme.spacing.md,
          paddingHorizontal: theme.spacing.lg,
        },
        flexFill: { flex: 1 },
      }),
    [theme],
  );

  return (
    <View style={fieldStyles.root}>
      {icon}
      <AppText variant="body" color="secondary" style={fieldStyles.flexFill}>
        {label}
      </AppText>
    </View>
  );
}
