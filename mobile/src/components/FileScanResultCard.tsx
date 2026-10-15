import React, { useMemo } from 'react';
import { StyleSheet, View } from 'react-native';
import { useTheme } from '../theme';
import { AppText, Badge, Button, Card, Divider, KeyValue } from './ui';
import { ShieldAlert, ShieldCheck, TriangleAlert } from 'lucide-react-native';
import { statusLabel, statusTone } from '../domain/threat';
import {
  findingLabel,
  findingTone,
  reputationLabel,
  reputationTone,
  scanStatusLabel,
} from '../domain/fileScan';
import type { FileScanOutcome } from '../hooks/useFileScanner';
import { formatBytes, formatDuration, truncateMiddle } from '../utils/format';

export interface FileScanResultCardProps {
  outcome: FileScanOutcome;
  /** Shown as the primary action ("Scan another file"). */
  onScanAnother?: () => void;
  /** Persist the result to scan history. */
  onSave?: () => void;
  /** When true, the save action is hidden and a saved note is shown instead. */
  saved?: boolean;
}

/**
 * Renders the merged result of a single file scan: the verdict, the raw engine
 * status, file details, the reputation lookup state and every finding the local
 * engine raised. It is shared by the file scanner and the quick/full scan
 * screens so the vocabulary stays identical everywhere.
 */
export function FileScanResultCard({
  outcome,
  onScanAnother,
  onSave,
  saved = false,
}: FileScanResultCardProps): React.JSX.Element {
  const theme = useTheme();
  const tone = statusTone(outcome.verdict);
  const threatFindings = outcome.findings.filter((f) => f.severity !== 'info');
  const notes = outcome.findings.filter((f) => f.severity === 'info');

  const styles = useMemo(
    () =>
      StyleSheet.create({
        content: { padding: theme.spacing.lg, gap: theme.spacing.md },
        header: { gap: theme.spacing.sm },
        row: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm, flexWrap: 'wrap' },
        fileName: { flexShrink: 1 },
        section: { gap: theme.spacing.sm },
        findingRow: { flexDirection: 'row', alignItems: 'flex-start', gap: theme.spacing.sm },
        findingText: { flex: 1 },
        notes: { gap: theme.spacing.xs },
        actions: { flexDirection: 'row', gap: theme.spacing.md, flexWrap: 'wrap' },
        savedNote: { alignSelf: 'center' },
      }),
    [theme],
  );

  return (
    <Card tone={tone}>
      <View style={styles.content}>
        <View style={styles.header}>
          <View style={styles.row}>
            {outcome.verdict === 'MALICIOUS' ? (
              <ShieldAlert size={18} color={theme.colors.malicious} />
            ) : outcome.verdict === 'SUSPICIOUS' ? (
              <TriangleAlert size={18} color={theme.colors.suspicious} />
            ) : (
              <ShieldCheck size={18} color={theme.colors.textSecondary} />
            )}
            <AppText variant="bodyStrong" style={styles.fileName}>
              {outcome.fileName}
            </AppText>
            <Badge label={statusLabel(outcome.verdict)} tone={tone} />
          </View>
          <AppText variant="caption" color="secondary">
            {outcome.details}
          </AppText>
        </View>

        <Divider />

        <View>
          <KeyValue label="Local result" value={scanStatusLabel(outcome.status)} />
          <KeyValue label="Type" value={outcome.mimeType} />
          <KeyValue label="Size" value={formatBytes(outcome.fileSize)} />
          <KeyValue label="Scanned in" value={formatDuration(outcome.durationMs)} />
          {outcome.sha256 ? (
            <KeyValue label="SHA-256" value={truncateMiddle(outcome.sha256, 12, 10)} mono selectable />
          ) : null}
        </View>

        <View style={styles.row}>
          <Badge label={reputationLabel(outcome.reputation)} tone={reputationTone(outcome.reputation)} size="sm" />
          {outcome.truncated ? (
            <Badge label="Partial scan" tone="suspicious" size="sm" />
          ) : null}
        </View>

        {outcome.reputationReason ? (
          <AppText variant="caption" color="secondary">
            Reputation: {outcome.reputationReason}
          </AppText>
        ) : null}

        {threatFindings.length > 0 ? (
          <View style={styles.section}>
            <AppText variant="caption" color="secondary">
              {threatFindings.length === 1 ? 'Finding' : 'Findings'}
            </AppText>
            {threatFindings.map((finding) => (
              <View key={finding.code} style={styles.findingRow}>
                <Badge label={finding.severity} tone={findingTone(finding.severity)} size="sm" />
                <AppText variant="caption" color="secondary" style={styles.findingText}>
                  {findingLabel(finding)}
                </AppText>
              </View>
            ))}
          </View>
        ) : null}

        {notes.length > 0 ? (
          <View style={styles.notes}>
            {notes.map((note) => (
              <AppText key={note.code} variant="caption" color="tertiary">
                • {findingLabel(note)}
              </AppText>
            ))}
          </View>
        ) : null}

        {(onScanAnother || onSave) && (
          <View style={styles.actions}>
            {onScanAnother ? (
              <Button label="Scan another" variant="ghost" onPress={onScanAnother} />
            ) : null}
            {onSave && !saved ? <Button label="Save to history" onPress={onSave} /> : null}
            {saved ? (
              <AppText variant="caption" color="secondary" style={styles.savedNote}>
                Saved to history
              </AppText>
            ) : null}
          </View>
        )}
      </View>
    </Card>
  );
}
