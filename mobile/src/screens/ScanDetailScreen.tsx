import React from 'react';
import { View } from 'react-native';
import { useRoute, type RouteProp } from '@react-navigation/native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Badge,
  Button,
  Card,
  Divider,
  ErrorState,
  KeyValue,
  Screen,
  SectionHeader,
} from '../components/ui';
import { CircleCheck, ScanLine, ShieldAlert, Trash2, TriangleAlert } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { scanTypeLabel, statusLabel, statusTone } from '../domain/threat';
import { formatDateTime, formatDuration } from '../utils/format';
import type { RootStackParamList } from '../navigation/types';

/** Full detail for one scan record, read from the scan store. */
export function ScanDetailScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const route = useRoute<RouteProp<RootStackParamList, 'ScanDetail'>>();
  const { scanId } = route.params;

  const scan = useScanStore((s) => s.records.find((r) => r.id === scanId));
  const removeRecord = useScanStore((s) => s.removeRecord);

  if (!scan) {
    return (
      <Screen scroll edges={['left', 'right']}>
        <ErrorState
          title="Scan not found"
          message="This scan is no longer in your history. It may have been cleared."
          retryLabel="Go back"
          onRetry={() => navigation.goBack()}
        />
      </Screen>
    );
  }

  const tone = statusTone(scan.threatLevel);
  const clean = scan.threatsFound === 0;

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <Card tone={clean ? 'safe' : tone}>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              {clean ? (
                <CircleCheck size={24} color={theme.colors.safe} />
              ) : (
                <TriangleAlert size={24} color={theme.colors[tone]} />
              )}
              <AppText variant="heading" style={{ flex: 1 }}>
                {clean ? 'No threats found' : `${scan.threatsFound} ${scan.threatsFound === 1 ? 'threat' : 'threats'} found`}
              </AppText>
            </View>
            <View style={{ flexDirection: 'row', gap: theme.spacing.sm, flexWrap: 'wrap' }}>
              <Badge label={scanTypeLabel(scan.scanType)} tone="info" />
              <Badge label={statusLabel(scan.threatLevel)} tone={tone} />
              <Badge label={scan.scanStatus} tone={scan.scanStatus === 'completed' ? 'safe' : 'unknown'} />
            </View>
          </View>
        </Card>

        <View>
          <SectionHeader title="Details" />
          <Card flush>
            <View style={{ paddingHorizontal: theme.spacing.lg, paddingVertical: theme.spacing.sm }}>
              {scan.target ? <KeyValue label="Target" value={scan.target} mono selectable /> : null}
              {scan.fileName ? <KeyValue label="File name" value={scan.fileName} selectable /> : null}
              {scan.fileHash ? <KeyValue label="SHA-256" value={scan.fileHash} mono selectable /> : null}
              <KeyValue label="Scan type" value={scanTypeLabel(scan.scanType)} />
              <KeyValue label="Files checked" value={String(scan.filesChecked)} />
              <KeyValue label="Threats found" value={String(scan.threatsFound)} />
              <KeyValue label="Duration" value={formatDuration(scan.durationMs)} />
              {scan.source ? <KeyValue label="Source" value={scan.source} /> : null}
              <KeyValue label="Scanned" value={formatDateTime(scan.scannedAt)} />
            </View>
          </Card>
        </View>

        {!clean ? (
          <AlertBanner
            tone="malicious"
            icon={<ShieldAlert size={20} color={theme.colors.malicious} />}
            title="What to do next"
            message="Do not open or run anything this scan flagged. Review the related alert for the exact reason and a recommended action."
          />
        ) : (
          <AlertBanner
            tone="safe"
            icon={<CircleCheck size={20} color={theme.colors.safe} />}
            title="Nothing flagged"
            message="No threat was detected in the checked items. A clean result only covers what was actually scanned."
          />
        )}

        <Card>
          <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
            <ScanLine size={20} color={theme.colors.textSecondary} />
            <AppText variant="caption" color="secondary" style={{ flex: 1 }}>
              This record is stored on your device as part of your scan history.
            </AppText>
          </View>
        </Card>

        <View style={{ gap: theme.spacing.md }}>
          <Divider />
          <Button
            label="Remove from history"
            variant="danger"
            icon={<Trash2 size={18} color={theme.colors.malicious} />}
            fullWidth
            onPress={() => {
              removeRecord(scanId);
              navigation.goBack();
            }}
          />
        </View>
      </View>
    </Screen>
  );
}
