import React, { useMemo, useState } from 'react';
import { View } from 'react-native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Button,
  Card,
  ListRow,
  ProgressBar,
  Screen,
  SectionHeader,
  SettingRow,
} from '../components/ui';
import { FileScanResultCard } from '../components/FileScanResultCard';
import {
  FileText,
  Info as InfoIcon,
  Search,
  ShieldCheck,
  Upload,
  X,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { useSettingsStore } from '../store/useSettingsStore';
import { statusLabel, statusTone, toneDotRole } from '../domain/threat';
import { formatRelativeTime, truncateMiddle } from '../utils/format';
import { useFileScanner } from '../hooks/useFileScanner';

const PHASE_LABELS: Record<string, string> = {
  inspect: 'Reading file…',
  hashing: 'Computing SHA-256…',
  signatures: 'Checking signatures…',
  done: 'Finishing…',
};

/**
 * Scans a single user-selected file.
 *
 * The file is opened read-only through the Storage Access Framework, copied
 * into the app's own cache, hashed and inspected entirely on-device. If the user
 * has explicitly opted in to sharing threat data, only the SHA-256 fingerprint
 * is sent to the reputation service — never the file itself.
 */
export function FileScannerScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const records = useScanStore((s) => s.records);
  const createFromAPI = useScanStore((s) => s.createFromAPI);
  const shareThreatData = useSettingsStore((s) => s.privacyPreferences.shareThreatData);
  const setPrivacyPreference = useSettingsStore((s) => s.setPrivacyPreference);

  const [savedUri, setSavedUri] = useState<string | null>(null);

  const fileScanner = useFileScanner({ checkReputation: shareThreatData });
  const { outcome } = fileScanner;

  const fileScans = useMemo(
    () => records.filter((r) => r.scanType === 'file').slice(0, 3),
    [records],
  );

  const progressValue = (fileScanner.progress?.percent ?? 0) / 100;
  const progressLabel = fileScanner.progress
    ? PHASE_LABELS[fileScanner.progress.phase] ?? 'Scanning…'
    : 'Scanning…';

  const handleSave = async () => {
    if (!outcome) {
      return;
    }
    await createFromAPI({
      scanType: 'file',
      target: outcome.uri,
      fileHash: outcome.sha256,
      fileName: outcome.fileName,
      threatLevel: outcome.verdict,
      threatType: outcome.findings[0]?.code,
      detectionReason: outcome.details,
      durationMs: outcome.durationMs,
      source: outcome.reputation === 'checked' ? 'backend' : 'local',
    });
    setSavedUri(outcome.uri);
  };

  const handleScanAnother = () => {
    setSavedUri(null);
    fileScanner.clearSelection();
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
              Check a document, image or download before you open it. The file is opened read-only
              and inspected on-device; it is never modified, uploaded or run.
            </AppText>
          </View>
        </Card>

        {!fileScanner.isAvailable ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="File scanning is unavailable here"
            message="The native scanning engine is built for Android only. On this platform the scanner cannot read files, so no result is shown."
          />
        ) : (
          <View style={{ gap: theme.spacing.md }}>
            <Button
              label={fileScanner.selected ? 'Choose a different file' : 'Choose a file'}
              variant="secondary"
              icon={<Upload size={18} />}
              fullWidth
              onPress={fileScanner.pickFile}
              disabled={fileScanner.isScanning || fileScanner.isPicking}
              loading={fileScanner.isPicking}
            />

            {fileScanner.selected ? (
              <Card>
                <View style={{ padding: theme.spacing.lg, gap: theme.spacing.sm }}>
                  <AppText variant="caption" color="secondary">
                    Selected file
                  </AppText>
                  <AppText variant="bodyStrong">{fileScanner.selected.name}</AppText>
                </View>
              </Card>
            ) : null}

            <Button
              label="Scan selected file"
              icon={<Search size={18} />}
              fullWidth
              onPress={fileScanner.scanSelectedFile}
              disabled={!fileScanner.selected || fileScanner.isScanning || fileScanner.isPicking}
              loading={fileScanner.isScanning}
            />

            {fileScanner.isScanning ? (
              <View style={{ gap: theme.spacing.sm }}>
                <ProgressBar value={progressValue} label={progressLabel} showPercent tone="info" />
                <Button
                  label="Cancel scan"
                  variant="ghost"
                  icon={<X size={18} />}
                  onPress={() => {
                    void fileScanner.cancel();
                  }}
                />
              </View>
            ) : null}

            {fileScanner.error ? (
              <AlertBanner
                tone="suspicious"
                title="Scan problem"
                message={fileScanner.error}
                action={
                  <Button
                    label="Dismiss"
                    variant="ghost"
                    size="sm"
                    onPress={fileScanner.clearError}
                  />
                }
              />
            ) : null}

            <Card flush>
              <SettingRow
                title="Check hash with the reputation service"
                description="Sends only the SHA-256 fingerprint, never the file. Off by default."
                value={shareThreatData}
                onValueChange={(value) => {
                  void setPrivacyPreference('shareThreatData', value);
                }}
              />
            </Card>

            {outcome ? (
              <View style={{ gap: theme.spacing.md }}>
                <SectionHeader title="Result" />
                <FileScanResultCard
                  outcome={outcome}
                  onScanAnother={handleScanAnother}
                  onSave={handleSave}
                  saved={savedUri === outcome.uri}
                />
              </View>
            ) : null}
          </View>
        )}

        {fileScans.length > 0 ? (
          <View>
            <SectionHeader title="Recent file checks" />
            <Card flush>
              {fileScans.map((scan, index) => (
                <View key={scan.id}>
                  {index > 0 ? (
                    <View
                      style={{
                        height: 1,
                        marginLeft: theme.spacing.lg,
                        backgroundColor: theme.colors.border,
                      }}
                    />
                  ) : null}
                  <ListRow
                    title={scan.fileName ?? 'File'}
                    subtitle={`${statusLabel(scan.threatLevel)} · ${formatRelativeTime(scan.scannedAt)}`}
                    meta={scan.fileHash ? truncateMiddle(scan.fileHash) : undefined}
                    leading={
                      <View
                        style={{
                          width: 10,
                          height: 10,
                          borderRadius: 5,
                          backgroundColor: theme.colors[toneDotRole(statusTone(scan.threatLevel))],
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
              A local scan that finds nothing is reported as “Unverified”, never “Safe”. Only the
              reputation service can confirm a file is known-good.
            </AppText>
          </View>
        </Card>
      </View>
    </Screen>
  );
}
