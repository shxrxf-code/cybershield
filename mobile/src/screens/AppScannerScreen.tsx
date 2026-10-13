import React, { useState } from 'react';
import { View } from 'react-native';
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
import { AppWindow, Info as InfoIcon, Lock, Package, ShieldAlert, ShieldCheck } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { severityLabel, severityTone, toneDotRole } from '../domain/threat';
import { formatRelativeTime } from '../utils/format';
import { capabilities } from '../capabilities';

type Filter = 'all' | 'permissions' | 'signature';

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: 'all', label: 'All apps' },
  { id: 'permissions', label: 'Risky permissions' },
  { id: 'signature', label: 'Unsigned' },
];

/**
 * Reviews installed applications. Enumerating packages and their permissions
 * uses the Android PackageManager through a native module, which is a later
 * phase; the interface is real but the action stays disabled until then.
 */
export function AppScannerScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const records = useScanStore((s) => s.records);
  const apkScans = records.filter((r) => r.scanType === 'apk');
  const [filter, setFilter] = useState<Filter>('all');

  const available = capabilities.appScan;

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <Card>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              <AppWindow size={24} color={theme.colors.accent} />
              <AppText variant="heading">Check installed apps</AppText>
            </View>
            <AppText variant="body" color="secondary">
              Review the apps on this device for risky permission combinations, missing signatures
              and known-harmful packages.
            </AppText>
          </View>
        </Card>

        {!available ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="App inspection not in this build"
            message="Listing installed packages and their permissions uses the Android PackageManager, which arrives in a later phase. The list below stays empty and honest until then — no app data is invented."
          />
        ) : null}

        <View>
          <SectionHeader title="Review filters" />
          <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: theme.spacing.sm }}>
            {FILTERS.map((f) => (
              <Chip key={f.id} label={f.label} selected={filter === f.id} onPress={() => setFilter(f.id)} />
            ))}
          </View>
        </View>

        <View>
          <SectionHeader title="Installed apps" subtitle={available ? undefined : 'Unavailable in this build'} />
          <Card flush>
            <View
              style={{
                padding: theme.spacing.lg,
                flexDirection: 'row',
                gap: theme.spacing.md,
                alignItems: 'center',
              }}
            >
              <Package size={18} color={theme.colors.textTertiary} />
              <AppText variant="body" color="secondary" style={{ flex: 1 }}>
                {available
                  ? 'No apps reviewed yet. Run a check to list them here.'
                  : 'App list is not available until the native inspection module is present.'}
              </AppText>
            </View>
          </Card>
        </View>

        <Card>
          <View style={{ gap: theme.spacing.md }}>
            <AppText variant="subheading">What we look for</AppText>
            <CheckItem
              icon={<Lock size={18} color={theme.colors.textSecondary} />}
              title="Risky permission combinations"
              detail="Apps that combine access to messages, accessibility and overlays."
            />
            <CheckItem
              icon={<ShieldAlert size={18} color={theme.colors.textSecondary} />}
              title="Missing or unusual signatures"
              detail="Apps that are debug-signed or not signed by a known publisher."
            />
            <CheckItem
              icon={<ShieldCheck size={18} color={theme.colors.textSecondary} />}
              title="Reputation of the package"
              detail="A hash-based lookup of the installed package, with your consent."
            />
          </View>
        </Card>

        {apkScans.length > 0 ? (
          <View>
            <SectionHeader title="Recent app checks" />
            <Card flush>
              {apkScans.map((scan, index) => (
                <View key={scan.id}>
                  {index > 0 ? (
                    <View style={{ height: 1, marginLeft: theme.spacing.lg, backgroundColor: theme.colors.border }} />
                  ) : null}
                  <ListRow
                    title={scan.target ?? scan.fileName ?? 'Package'}
                    subtitle={`${severityLabel(scan.threatLevel)} · ${formatRelativeTime(scan.scannedAt)}`}
                    leading={
                      <View
                        style={{
                          width: 10,
                          height: 10,
                          borderRadius: 5,
                          backgroundColor: theme.colors[toneDotRole(severityTone(scan.threatLevel))],
                        }}
                      />
                    }
                    trailing={<Badge label={severityLabel(scan.threatLevel)} tone={severityTone(scan.threatLevel)} size="sm" />}
                    onPress={() => navigation.navigate('ScanDetail', { scanId: scan.id })}
                  />
                </View>
              ))}
            </Card>
          </View>
        ) : null}

        <Button label="Scan installed apps" disabled={!available} fullWidth onPress={() => undefined} />
      </View>
    </Screen>
  );
}

interface CheckItemProps {
  icon: React.ReactNode;
  title: string;
  detail: string;
}

function CheckItem({ icon, title, detail }: CheckItemProps): React.JSX.Element {
  const theme = useTheme();
  return (
    <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
      {icon}
      <View style={{ flex: 1, gap: 2 }}>
        <AppText variant="bodyStrong">{title}</AppText>
        <AppText variant="caption" color="secondary">
          {detail}
        </AppText>
      </View>
    </View>
  );
}
