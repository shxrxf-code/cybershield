import React, { useMemo } from 'react';
import { StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../theme';
import {
  AppText,
  Button,
  Card,
  ListRow,
  Screen,
  SectionHeader,
  SettingRow,
} from '../components/ui';
import {
  AppWindow,
  Bell,
  ChevronRight,
  FileText,
  Link2,
  ScanLine,
  ShieldCheck,
  Zap,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useSettingsStore } from '../store';

/** The scanning hub and protection controls. */
export function ProtectionScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const notificationMonitoring = useSettingsStore((s) => s.notificationMonitoring);
  const backgroundProtection = useSettingsStore((s) => s.backgroundProtection);
  const setBackgroundProtection = useSettingsStore((s) => s.setBackgroundProtection);

  const styles = useMemo(
    () =>
      StyleSheet.create({
        content: { gap: theme.spacing.xl },
        deviceSection: { gap: theme.spacing.md },
        scanRow: { flexDirection: 'row', gap: theme.spacing.md },
        stackMd: { gap: theme.spacing.md },
      }),
    [theme],
  );

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={styles.content}>
        {/* Device scans */}
        <View style={styles.deviceSection}>
          <SectionHeader title="Device scan" subtitle="Check apps and files on this device" />
          <View style={styles.scanRow}>
            <ActionTile
              title="Quick scan"
              caption="Apps & key files"
              icon={<Zap size={22} color={theme.colors.accent} />}
              onPress={() => navigation.navigate('DeviceScan', { mode: 'quick' })}
            />
            <ActionTile
              title="Full scan"
              caption="All storage"
              icon={<ScanLine size={22} color={theme.colors.accent} />}
              onPress={() => navigation.navigate('DeviceScan', { mode: 'full' })}
            />
          </View>
        </View>

        {/* Specific scanners */}
        <View>
          <SectionHeader title="Check something specific" />
          <Card flush>
            <ListRow
              title="Check a link"
              subtitle="Paste a URL to verify before opening it"
              leading={<Link2 size={20} color={theme.colors.textSecondary} />}
              trailing={<ChevronRight size={18} color={theme.colors.textTertiary} />}
              onPress={() => navigation.navigate('UrlScanner')}
            />
            <Separator />
            <ListRow
              title="Scan a file"
              subtitle="Documents, images and downloads"
              leading={<FileText size={20} color={theme.colors.textSecondary} />}
              trailing={<ChevronRight size={18} color={theme.colors.textTertiary} />}
              onPress={() => navigation.navigate('FileScanner')}
            />
            <Separator />
            <ListRow
              title="Check installed apps"
              subtitle="Review app permissions and signatures"
              leading={<AppWindow size={20} color={theme.colors.textSecondary} />}
              trailing={<ChevronRight size={18} color={theme.colors.textTertiary} />}
              onPress={() => navigation.navigate('AppScanner')}
            />
          </Card>
        </View>

        {/* Protection toggles */}
        <View>
          <SectionHeader title="Protection" />
          <Card flush>
            <ListRow
              title="Message monitoring"
              subtitle={
                notificationMonitoring
                  ? 'Scanning notification text for scam patterns'
                  : 'Off — turn on to scan message notifications'
              }
              leading={<Bell size={20} color={notificationMonitoring ? theme.colors.safe : theme.colors.textSecondary} />}
              trailing={<ChevronRight size={18} color={theme.colors.textTertiary} />}
              onPress={() => navigation.navigate('NotificationProtection')}
            />
            <Separator />
            <SettingRow
              title="Background protection"
              description="Periodic scans while the app is closed"
              value={backgroundProtection}
              onValueChange={setBackgroundProtection}
              icon={<ShieldCheck size={20} color={backgroundProtection ? theme.colors.safe : theme.colors.textSecondary} />}
            />
          </Card>
        </View>

        <Card>
          <View style={styles.stackMd}>
            <AppText variant="subheading">How protection works</AppText>
            <AppText variant="body" color="secondary">
              Link checks query vetted reputation services. File and app checks run on the device;
              only a file's fingerprint is ever sent, never its contents. Message text is analysed
              on-device and is never stored.
            </AppText>
            <Button label="Manage permissions" variant="secondary" onPress={() => navigation.navigate('Permissions')} />
          </View>
        </Card>
      </View>
    </Screen>
  );
}

function Separator(): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        separator: { height: 1, marginLeft: theme.spacing.lg, backgroundColor: theme.colors.border },
      }),
    [theme],
  );
  return <View style={styles.separator} />;
}

interface ActionTileProps {
  title: string;
  caption: string;
  icon: React.ReactNode;
  onPress: () => void;
  style?: StyleProp<ViewStyle>;
}

function ActionTile({ title, caption, icon, onPress, style }: ActionTileProps): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        card: { flex: 1, minHeight: 120 },
        inner: { gap: theme.spacing.sm, flex: 1, justifyContent: 'space-between' },
        captionGroup: { gap: 2 },
      }),
    [theme],
  );
  return (
    <Card onPress={onPress} style={[styles.card, style]}>
      <View style={styles.inner}>
        {icon}
        <View style={styles.captionGroup}>
          <AppText variant="subheading">{title}</AppText>
          <AppText variant="caption" color="secondary">
            {caption}
          </AppText>
        </View>
      </View>
    </Card>
  );
}
