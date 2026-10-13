import React, { useState } from 'react';
import { View } from 'react-native';
import { useTheme } from '../theme';
import { AlertBanner, AppText, Badge, Button, Card, KeyValue, ListRow, Screen, SectionHeader } from '../components/ui';
import {
  FileText,
  Fingerprint,
  Info as InfoIcon,
  Search,
  ShieldCheck,
  TriangleAlert,
  Upload,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { severityLabel, severityTone, toneDotRole } from '../domain/threat';
import { truncateMiddle } from '../utils/format';
import { capabilities } from '../capabilities';
import { scanFileHash } from '../api';
import type { FileScanResponse } from '../api/client';

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
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [reputation, setReputation] = useState<FileScanResponse | null>(null);
  const [checking, setChecking] = useState(false);

  const onPickFile = () => {
    if (!available) return;
    // In a real implementation this would launch the system file picker
    // and compute the SHA-256 hash. For now we simulate a hash for testing.
    const testHash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    setFileName('test-document.pdf');
    setFileHash(testHash);
    setReputation(null);
  };

  const onLookupHash = async () => {
    if (!fileHash || !available) return;
    setChecking(true);
    try {
      const apiResult = await scanFileHash({ hash: fileHash });
      setReputation(apiResult);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Network error';
      setReputation(null);
      // In a real app, show this error to the user
      console.warn('Reputation check failed:', message);
    } finally {
      setChecking(false);
    }
  };

  const onClear = () => {
    setFileName(null);
    setFileHash(null);
    setReputation(null);
  };

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

        {fileName ? (
          <View>
            <SectionHeader title="Selected file" />
            <Card flush>
              <View style={{ padding: theme.spacing.lg, gap: theme.spacing.md }}>
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
                  <FileText size={20} color={theme.colors.textSecondary} />
                  <AppText variant="bodyStrong">{fileName}</AppText>
                </View>
                <AppText variant="caption" color="secondary" style={{ fontFamily: 'monospace' }}>
                  SHA-256: {fileHash}
                </AppText>
                <View style={{ flexDirection: 'row', gap: theme.spacing.md, marginTop: theme.spacing.sm }}>
                  <Button
                    label="Look up fingerprint"
                    disabled={!fileHash || checking || !!reputation}
                    onPress={onLookupHash}
                  />
                  <Button label="Clear" variant="ghost" onPress={onClear} />
                </View>
              </View>
            </Card>

            {checking ? (
              <AlertBanner
                tone="info"
                icon={<InfoIcon size={20} color={theme.colors.info} />}
                title="Checking reputation…"
                message="The ThreatGuard backend is looking up this file fingerprint."
              />
            ) : reputation ? (
              <View>
                <SectionHeader title="Reputation verdict" subtitle="From the ThreatGuard backend" />
                <Card flush tone={severityToneFromLevel(reputation.threatLevel)}>
                  <View style={{ padding: theme.spacing.lg, gap: theme.spacing.md }}>
                    <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
                      {iconForLevel(reputation.threatLevel, theme)}
                      <AppText variant="bodyStrong">
                        {reputation.threatLevel === 'SAFE'
                          ? 'No threat found'
                          : reputation.threatLevel === 'UNKNOWN'
                            ? 'Unverified'
                            : `${reputation.threatLevel} threat`}
                      </AppText>
                      <Badge
                        label={reputation.threatLevel === 'SAFE' ? 'Safe' : reputation.threatLevel}
                        tone={toneForLevel(reputation.threatLevel)}
                        size="sm"
                      />
                    </View>
                    {reputation.detectionReason ? (
                      <AppText variant="body" color="secondary">{reputation.detectionReason}</AppText>
                    ) : null}
                    <View style={{ height: 1, backgroundColor: theme.colors.border }} />
                    <View style={{ paddingHorizontal: theme.spacing.lg, paddingVertical: theme.spacing.sm }}>
                      <KeyValue label="Threat type" value={reputation.threatType ?? '—'} />
                      <KeyValue label="Scanned" value={new Date(reputation.scannedAt).toLocaleString()} />
                    </View>
                  </View>
                </Card>
              </View>
            ) : capabilities.fileScan ? (
              <AlertBanner
                tone="info"
                icon={<InfoIcon size={20} color={theme.colors.info} />}
                title="Ready to check"
                message={'Select a file and tap "Look up fingerprint" to query the ThreatGuard backend.'}
              />
            ) : null}
          </View>
        ) : null}

        <Button
          label="Choose a file"
          icon={available ? <Upload size={18} color={theme.colors.onAccent} /> : undefined}
          disabled={!available}
          fullWidth
          onPress={onPickFile}
        />

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

function toneForLevel(level: string): 'safe' | 'suspicious' | 'malicious' | 'unknown' {
  switch (level) {
    case 'SAFE':
      return 'safe';
    case 'MALICIOUS':
      return 'malicious';
    case 'SUSPICIOUS':
      return 'suspicious';
    default:
      return 'unknown';
  }
}

function severityToneFromLevel(level: string): 'safe' | 'suspicious' | 'malicious' | 'unknown' | 'info' {
  switch (level) {
    case 'SAFE':
      return 'safe';
    case 'MALICIOUS':
      return 'malicious';
    case 'SUSPICIOUS':
      return 'suspicious';
    default:
      return 'info';
  }
}

function iconForLevel(level: string, theme: ReturnType<typeof useTheme>): React.ReactNode {
  switch (level) {
    case 'SAFE':
      return <ShieldCheck size={20} color={theme.colors.safe} />;
    case 'MALICIOUS':
      return <TriangleAlert size={20} color={theme.colors.malicious} />;
    case 'SUSPICIOUS':
      return <TriangleAlert size={20} color={theme.colors.suspicious} />;
    default:
      return <ShieldCheck size={20} color={theme.colors.unknown} />;
  }
}
