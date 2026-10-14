import React from 'react';
import { View } from 'react-native';
import { useRoute, type RouteProp } from '@react-navigation/native';
import { useTheme } from '../theme';
import { AlertBanner, AppText, Button, Card, Chip, Screen, SectionHeader } from '../components/ui';
import {
  Download,
  FileCode,
  FileText,
  Image as ImageIcon,
  Info as InfoIcon,
  Package,
  Play,
  ScanLine,
  ShieldAlert,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { statusLabel, statusTone } from '../domain/threat';
import { formatRelativeTime, formatDuration } from '../utils/format';
import { capabilities } from '../capabilities';
import type { RootStackParamList } from '../navigation/types';

interface ScopeItem {
  title: string;
  detail: string;
  icon: React.ReactNode;
}

const QUICK_SCOPE: ScopeItem[] = [
  { title: 'Installed apps', detail: 'Permissions and signatures of installed packages', icon: <Package size={20} /> },
  { title: 'Downloads', detail: 'Recently downloaded documents and archives', icon: <Download size={20} /> },
  { title: 'Key documents', detail: 'Documents in shared storage', icon: <FileText size={20} /> },
];

const FULL_SCOPE: ScopeItem[] = [
  ...QUICK_SCOPE,
  { title: 'Images and media', detail: 'Photos and media files across storage', icon: <ImageIcon size={20} /> },
  { title: 'Installable packages', detail: 'APK files that could be installed', icon: <FileCode size={20} /> },
];

/**
 * Runs a device scan. The screen is complete and stateful, but the on-device
 * scanning engine is a later phase; until it is present the scan action is
 * disabled and the reason is stated plainly rather than faking progress.
 */
export function DeviceScanScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const route = useRoute<RouteProp<RootStackParamList, 'DeviceScan'>>();
  const mode = route.params.mode;

  const records = useScanStore((s) => s.records);
  const previous = records.find((r) => r.scanType === mode);

  const scope = mode === 'quick' ? QUICK_SCOPE : FULL_SCOPE;
  const available = capabilities.deviceScan;

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <Card>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              <ScanLine size={24} color={theme.colors.accent} />
              <AppText variant="heading">{mode === 'quick' ? 'Quick scan' : 'Full scan'}</AppText>
            </View>
            <AppText variant="body" color="secondary">
              {mode === 'quick'
                ? 'Fast check of installed apps and the files most likely to carry a threat.'
                : 'Checks all storage, including images, media and installable packages.'}
            </AppText>
            <View style={{ flexDirection: 'row', gap: theme.spacing.sm }}>
              <Chip
                label="Quick"
                selected={mode === 'quick'}
                onPress={() => navigation.setParams({ mode: 'quick' })}
              />
              <Chip
                label="Full"
                selected={mode === 'full'}
                onPress={() => navigation.setParams({ mode: 'full' })}
              />
            </View>
          </View>
        </Card>

        {!available ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="Scanning engine not in this build"
            message="On-device scanning is wired up in a later phase. Until then this screen cannot produce a real result, so the scan action stays disabled."
          />
        ) : null}

        {previous ? (
          <View>
            <SectionHeader title="Last result" subtitle={formatRelativeTime(previous.scannedAt)} />
            <Card
              tone={previous.threatsFound > 0 ? statusTone(previous.threatLevel) : 'safe'}
              onPress={() => navigation.navigate('ScanDetail', { scanId: previous.id })}
            >
              <View style={{ gap: theme.spacing.xs }}>
                <AppText variant="bodyStrong">
                  {previous.threatsFound > 0
                    ? `${previous.threatsFound} ${previous.threatsFound === 1 ? 'threat' : 'threats'} found`
                    : 'No threats found'}
                </AppText>
                <AppText variant="caption" color="secondary">
                  {previous.filesChecked} checked · {formatDuration(previous.durationMs)} ·{' '}
                  {statusLabel(previous.threatLevel)}
                </AppText>
              </View>
            </Card>
          </View>
        ) : null}

        <View>
          <SectionHeader title="What this scan covers" />
          <Card flush>
            {scope.map((item, index) => (
              <View
                key={item.title}
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  gap: theme.spacing.md,
                  padding: theme.spacing.lg,
                  borderTopWidth: index === 0 ? 0 : 1,
                  borderTopColor: theme.colors.border,
                }}
              >
                <View style={{ opacity: 0.9 }}>{item.icon}</View>
                <View style={{ flex: 1, gap: 2 }}>
                  <AppText variant="bodyStrong">{item.title}</AppText>
                  <AppText variant="caption" color="secondary">
                    {item.detail}
                  </AppText>
                </View>
              </View>
            ))}
          </Card>
        </View>

        {available ? (
          <Button
            label={`Start ${mode} scan`}
            icon={<Play size={18} color={theme.colors.onAccent} />}
            fullWidth
            onPress={() => undefined}
          />
        ) : (
          <Button label="Start scan" disabled fullWidth onPress={() => undefined} />
        )}

        <Card>
          <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
            <ShieldAlert size={20} color={theme.colors.textSecondary} />
            <AppText variant="caption" color="secondary" style={{ flex: 1 }}>
              ThreatGuard never opens or runs a file it inspects. Results only tell you what was
              found and what to do next.
            </AppText>
          </View>
        </Card>
      </View>
    </Screen>
  );
}
