import React from 'react';
import { View } from 'react-native';
import { useTheme } from '../theme';
import { AlertBanner, AppText, Button, Card, ListRow, Screen, SectionHeader } from '../components/ui';
import {
  FileText,
  Fingerprint,
  Info as InfoIcon,
  Search,
  ShieldCheck,
  Upload,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { severityLabel, severityTone, toneDotRole } from '../domain/threat';
import { truncateMiddle } from '../utils/format';
import { capabilities } from '../capabilities';

interface StepItem {
  title: string;
  detail: string;
  icon: React.ReactNode;
}

const STEPS: StepItem[] = [
  {
    title: 'Choose a file',
    detail: 'Select a document, image or download from your device.',
    icon: <Upload size={20} />,
  },
  {
    title: 'Read it on-device',
    detail: 'ThreatGuard inspects the file locally and computes its SHA-256 fingerprint.',
    icon: <Fingerprint size={20} />,
  },
  {
    title: 'Look up the fingerprint',
    detail: 'With your consent, only the hash is sent for a reputation check — never the file.',
    icon: <Search size={20} />,
  },
];

/**
 * Scans a single file. Picking a file and hashing it needs the native file
 * access layer, which is a later phase; the screen presents the real flow and
 * keeps the action disabled rather than pretending to scan.
 */
export function FileScannerScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const records = useScanStore((s) => s.records);
  const fileScans = records.filter((r) => r.scanType === 'file').slice(0, 3);

  const available = capabilities.fileScan;

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <Card>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              <FileText size={24} color={theme.colors.accent} />
              <AppText variant="heading">Scan a file</AppText>
            </View>
            <AppText variant="body" color="secondary">
              Check a document, image or download before you open it. File contents never leave
              this device unless you explicitly allow a fingerprint lookup.
            </AppText>
          </View>
        </Card>

        {!available ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="File access not in this build"
            message="Choosing and reading a file uses the Android storage layer, which arrives in a later phase. The file picker stays disabled until then."
          />
        ) : null}

        <View>
          <SectionHeader title="How it works" />
          <Card flush>
            {STEPS.map((step, index) => (
              <View
                key={step.title}
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  gap: theme.spacing.md,
                  padding: theme.spacing.lg,
                  borderTopWidth: index === 0 ? 0 : 1,
                  borderTopColor: theme.colors.border,
                }}
              >
                <View
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 18,
                    alignItems: 'center',
                    justifyContent: 'center',
                    backgroundColor: theme.colors.accentMuted,
                  }}
                >
                  <AppText variant="label" color="accent">
                    {index + 1}
                  </AppText>
                </View>
                <View style={{ flex: 1, gap: 2 }}>
                  <AppText variant="bodyStrong">{step.title}</AppText>
                  <AppText variant="caption" color="secondary">
                    {step.detail}
                  </AppText>
                </View>
                {step.icon}
              </View>
            ))}
          </Card>
        </View>

        {fileScans.length > 0 ? (
          <View>
            <SectionHeader title="Recent file checks" />
            <Card flush>
              {fileScans.map((scan, index) => (
                <View key={scan.id}>
                  {index > 0 ? (
                    <View style={{ height: 1, marginLeft: theme.spacing.lg, backgroundColor: theme.colors.border }} />
                  ) : null}
                  <ListRow
                    title={scan.fileName ?? 'File'}
                    subtitle={`${severityLabel(scan.threatLevel)} · ${scan.filesChecked} checked`}
                    meta={scan.fileHash ? truncateMiddle(scan.fileHash) : undefined}
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
                    onPress={() => navigation.navigate('ScanDetail', { scanId: scan.id })}
                  />
                </View>
              ))}
            </Card>
          </View>
        ) : null}

        <Button
          label="Choose a file"
          icon={available ? <Upload size={18} color={theme.colors.onAccent} /> : undefined}
          disabled={!available}
          fullWidth
          onPress={() => undefined}
        />

        <Card>
          <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
            <ShieldCheck size={20} color={theme.colors.safe} />
            <AppText variant="caption" color="secondary" style={{ flex: 1 }}>
              Files are opened read-only. ThreatGuard never modifies, uploads or runs a file you
              select.
            </AppText>
          </View>
        </Card>
      </View>
    </Screen>
  );
}
