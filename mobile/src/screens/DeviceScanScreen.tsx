import React, { useMemo, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { useRoute, type RouteProp } from '@react-navigation/native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Badge,
  Button,
  Card,
  Chip,
  ListRow,
  ProgressBar,
  Screen,
  SectionHeader,
} from '../components/ui';
import { FileScanResultCard } from '../components/FileScanResultCard';
import {
  FileText,
  Info as InfoIcon,
  Play,
  ScanLine,
  ShieldAlert,
  Upload,
  X,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { useSettingsStore } from '../store/useSettingsStore';
import { statusLabel, statusTone, toneDotRole } from '../domain/threat';
import { formatBytes, formatDuration, formatRelativeTime } from '../utils/format';
import { capabilities } from '../capabilities';
import type { RootStackParamList } from '../navigation/types';
import { useFileScanner, useMultipleFileScanner } from '../hooks/useFileScanner';

interface CoverageItem {
  title: string;
  detail: string;
  icon: React.ReactNode;
}

const COVERAGE: CoverageItem[] = [
  {
    title: 'Files you choose',
    detail: 'Documents, images, archives and APKs selected through the system picker',
    icon: <FileText size={20} />,
  },
  {
    title: 'On-device checks',
    detail: 'SHA-256 hashing plus structure and known-signature checks',
    icon: <ScanLine size={20} />,
  },
  {
    title: 'Optional reputation',
    detail: 'A SHA-256-only lookup, and only when you have turned it on',
    icon: <ShieldAlert size={20} />,
  },
];

/**
 * The quick and full scan screens.
 *
 * Both run the real on-device engine over files the user explicitly selects:
 * quick scans one file, full scans several at once. ThreatGuard cannot enumerate
 * another app's private storage or the whole device, so the screen says so
 * plainly instead of offering a scan it cannot perform.
 */
export function DeviceScanScreen(): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: { gap: theme.spacing.xl },
        section: { gap: theme.spacing.md },
        header: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm },
        chipRow: { flexDirection: 'row', gap: theme.spacing.sm },
        divider: {
          height: 1,
          marginLeft: theme.spacing.lg,
          backgroundColor: theme.colors.border,
        },
        dot: { width: 10, height: 10, borderRadius: 5 },
        cardPad: { padding: theme.spacing.lg, gap: theme.spacing.sm },
        stackSm: { gap: theme.spacing.sm },
        row: { flexDirection: 'row', gap: theme.spacing.md },
        flex1: { flex: 1 },
        coverageRow: {
          flexDirection: 'row',
          alignItems: 'center',
          gap: theme.spacing.md,
          padding: theme.spacing.lg,
          borderTopColor: theme.colors.border,
        },
        coverageRowFirst: { borderTopWidth: 0 },
        coverageRowRest: { borderTopWidth: 1 },
        iconWrap: { opacity: 0.9 },
        flex1Gap2: { flex: 1, gap: 2 },
        stackXs: { gap: theme.spacing.xs },
      }),
    [theme],
  );
  const navigation = useRootNavigation();
  const route = useRoute<RouteProp<RootStackParamList, 'DeviceScan'>>();
  const mode = route.params.mode;
  const isFull = mode === 'full';

  const records = useScanStore((s) => s.records);
  const createFromAPI = useScanStore((s) => s.createFromAPI);
  const shareThreatData = useSettingsStore((s) => s.privacyPreferences.shareThreatData);

  const single = useFileScanner({ checkReputation: shareThreatData });
  const multi = useMultipleFileScanner({ checkReputation: shareThreatData });
  const [savedUris, setSavedUris] = useState<string[]>([]);

  const previous = useMemo(() => records.find((r) => r.scanType === mode), [records, mode]);

  const isAvailable = isFull ? multi.isAvailable : single.isAvailable;
  const isScanning = isFull ? multi.isScanning : single.isScanning;
  const isPicking = isFull ? multi.isPicking : single.isPicking;
  const error = isFull ? multi.error : single.error;
  const progress = isFull ? multi.progress : single.progress;

  const progressValue = (progress?.percent ?? 0) / 100;
  const progressLabel =
    isFull && multi.files.length > 0 && multi.scanningIndex >= 0
      ? `Scanning file ${multi.scanningIndex + 1} of ${multi.files.length}…`
      : 'Scanning…';

  const switchMode = (next: 'quick' | 'full') => {
    if (next === mode) {
      return;
    }
    single.clearSelection();
    multi.clearSelection();
    setSavedUris([]);
    navigation.setParams({ mode: next });
  };

  const saveOutcome = async (uri: string) => {
    const outcome = isFull
      ? multi.outcomes.find((o) => o.uri === uri)
      : single.outcome?.uri === uri
        ? single.outcome
        : null;
    if (!outcome) {
      return;
    }
    await createFromAPI({
      scanType: mode,
      target: outcome.uri,
      fileHash: outcome.sha256,
      fileName: outcome.fileName,
      threatLevel: outcome.verdict,
      threatType: outcome.findings[0]?.code,
      detectionReason: outcome.details,
      durationMs: outcome.durationMs,
      source: outcome.reputation === 'checked' ? 'backend' : 'local',
    });
    setSavedUris((uris) => (uris.includes(uri) ? uris : [...uris, uri]));
  };

  const saveAll = async () => {
    for (const outcome of multi.outcomes) {
      await saveOutcome(outcome.uri);
    }
  };

  const threatCount = multi.outcomes.filter(
    (o) => o.verdict === 'MALICIOUS' || o.verdict === 'SUSPICIOUS',
  ).length;

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={styles.root}>
        <Card>
          <View style={styles.section}>
            <View style={styles.header}>
              <ScanLine size={24} color={theme.colors.accent} />
              <AppText variant="heading">{isFull ? 'Full scan' : 'Quick scan'}</AppText>
            </View>
            <AppText variant="body" color="secondary">
              {isFull
                ? 'Check several files at once. ThreatGuard inspects each one on-device and reports what it found.'
                : 'Check a single file before you open it. The file is inspected on-device and never modified.'}
            </AppText>
            <View style={styles.chipRow}>
              <Chip label="Quick" selected={!isFull} onPress={() => switchMode('quick')} />
              <Chip label="Full" selected={isFull} onPress={() => switchMode('full')} />
            </View>
          </View>
        </Card>

        <AlertBanner
          tone="info"
          icon={<InfoIcon size={20} color={theme.colors.info} />}
          title="What this build can scan"
          message="Full-device scanning of installed apps and shared storage is not enabled in this build. ThreatGuard inspects the files you pick, one at a time."
        />

        {!isAvailable ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="Scanning is unavailable here"
            message="The native scanning engine is built for Android only. On this platform no file result is produced."
          />
        ) : isFull ? (
          <View style={styles.section}>
            <Button
              label="Choose files"
              variant="secondary"
              icon={<Upload size={18} />}
              fullWidth
              onPress={() => {
                void multi.pickFiles(true);
              }}
              disabled={isScanning || isPicking}
              loading={isPicking}
            />

            {multi.files.length > 0 ? (
              <Card flush>
                {multi.files.map((file, index) => (
                  <View key={file.uri}>
                    {index > 0 ? (
                      <View style={styles.divider} />
                    ) : null}
                    <ListRow title={file.name} showChevron={false} />
                  </View>
                ))}
              </Card>
            ) : null}

            <Button
              label={multi.files.length > 1 ? `Scan ${multi.files.length} files` : 'Scan files'}
              icon={<Play size={18} />}
              fullWidth
              onPress={multi.scanAll}
              disabled={multi.files.length === 0 || isScanning || isPicking}
              loading={isScanning}
            />

            {isScanning ? (
              <View style={styles.stackSm}>
                <ProgressBar value={progressValue} label={progressLabel} showPercent tone="info" />
                <Button
                  label="Cancel scan"
                  variant="ghost"
                  icon={<X size={18} />}
                  onPress={() => {
                    void multi.cancel();
                  }}
                />
              </View>
            ) : null}

            {multi.outcomes.length > 0 ? (
              <View style={styles.section}>
                <SectionHeader
                  title="Results"
                  subtitle={`${multi.outcomes.length} scanned · ${threatCount} need attention`}
                />
                <Card flush>
                  {multi.outcomes.map((outcome, index) => (
                    <View key={outcome.uri}>
                      {index > 0 ? (
                        <View style={styles.divider} />
                      ) : null}
                      <ListRow
                        title={outcome.fileName}
                        subtitle={outcome.details}
                        meta={`${statusLabel(outcome.verdict)} · ${formatBytes(outcome.fileSize)}`}
                        showChevron={false}
                        leading={
                          <View
                            style={[
                              styles.dot,
                              {
                                backgroundColor:
                                  theme.colors[toneDotRole(statusTone(outcome.verdict))],
                              },
                            ]}
                          />
                        }
                        trailing={<Badge label={statusLabel(outcome.verdict)} tone={statusTone(outcome.verdict)} size="sm" />}
                      />
                    </View>
                  ))}
                </Card>
                <Button
                  label="Save all to history"
                  onPress={saveAll}
                  disabled={savedUris.length === multi.outcomes.length}
                  fullWidth
                />
              </View>
            ) : null}
          </View>
        ) : (
          <View style={styles.section}>
            <Button
              label={single.selected ? 'Choose a different file' : 'Choose a file'}
              variant="secondary"
              icon={<Upload size={18} />}
              fullWidth
              onPress={single.pickFile}
              disabled={isScanning || isPicking}
              loading={isPicking}
            />

            {single.selected ? (
              <Card>
                <View style={styles.cardPad}>
                  <AppText variant="caption" color="secondary">
                    Selected file
                  </AppText>
                  <AppText variant="bodyStrong">{single.selected.name}</AppText>
                </View>
              </Card>
            ) : null}

            <Button
              label="Scan selected file"
              icon={<Play size={18} />}
              fullWidth
              onPress={single.scanSelectedFile}
              disabled={!single.selected || isScanning || isPicking}
              loading={isScanning}
            />

            {isScanning ? (
              <View style={styles.stackSm}>
                <ProgressBar value={progressValue} label={progressLabel} showPercent tone="info" />
                <Button
                  label="Cancel scan"
                  variant="ghost"
                  icon={<X size={18} />}
                  onPress={() => {
                    void single.cancel();
                  }}
                />
              </View>
            ) : null}

            {single.outcome ? (
              <View style={styles.section}>
                <SectionHeader title="Result" />
                <FileScanResultCard
                  outcome={single.outcome}
                  onScanAnother={() => {
                    setSavedUris([]);
                    single.clearSelection();
                  }}
                  onSave={() => {
                    void saveOutcome(single.outcome!.uri);
                  }}
                  saved={savedUris.includes(single.outcome.uri)}
                />
              </View>
            ) : null}
          </View>
        )}

        {error ? (
          <AlertBanner
            tone="suspicious"
            title="Scan problem"
            message={error}
            action={
              <Button
                label="Dismiss"
                variant="ghost"
                size="sm"
                onPress={isFull ? multi.clearError : single.clearError}
              />
            }
          />
        ) : null}

        {!capabilities.appScan ? (
          <Card>
            <View style={styles.row}>
              <ShieldAlert size={20} color={theme.colors.textSecondary} />
              <AppText variant="caption" color="secondary" style={styles.flex1}>
                Installed-app inspection and background storage scanning are planned for a later
                phase. This screen only reports results from the files you select.
              </AppText>
            </View>
          </Card>
        ) : null}

        <View>
          <SectionHeader title="What ThreatGuard inspects" />
          <Card flush>
            {COVERAGE.map((item, index) => (
              <View
                key={item.title}
                style={[
                  styles.coverageRow,
                  index === 0 ? styles.coverageRowFirst : styles.coverageRowRest,
                ]}
              >
                <View style={styles.iconWrap}>{item.icon}</View>
                <View style={styles.flex1Gap2}>
                  <AppText variant="bodyStrong">{item.title}</AppText>
                  <AppText variant="caption" color="secondary">
                    {item.detail}
                  </AppText>
                </View>
              </View>
            ))}
          </Card>
        </View>

        {previous ? (
          <View>
            <SectionHeader title="Last result" subtitle={formatRelativeTime(previous.scannedAt)} />
            <Card
              tone={previous.threatsFound > 0 ? statusTone(previous.threatLevel) : 'unknown'}
              onPress={() => navigation.navigate('ScanDetail', { scanId: previous.id })}
            >
              <View style={styles.stackXs}>
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
      </View>
    </Screen>
  );
}
