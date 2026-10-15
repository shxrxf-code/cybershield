import React, { useEffect, useMemo } from 'react';
import { StyleSheet, View } from 'react-native';
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
import { CircleCheck, ShieldAlert, Trash2, TriangleAlert } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useAlertStore } from '../store';
import { categoryLabel, severityLabel, severityTone, threatTypeLabel } from '../domain/threat';
import { formatDateTime } from '../utils/format';
import type { RootStackParamList } from '../navigation/types';

/**
 * Full detail for a single alert, read from the alert store. Landing here marks
 * the alert as read. ThreatGuard never opens a flagged target for the user.
 */
export function AlertDetailScreen(): React.JSX.Element {
  const theme = useTheme();

  const styles = useMemo(
    () =>
      StyleSheet.create({
        content: { gap: theme.spacing.xl },
        card: { gap: theme.spacing.md },
        titleRow: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm },
        flexFill: { flex: 1 },
        badgeRow: { flexDirection: 'row', gap: theme.spacing.sm, flexWrap: 'wrap' },
        detail: { paddingHorizontal: theme.spacing.lg, paddingVertical: theme.spacing.sm },
        noteRow: { flexDirection: 'row', gap: theme.spacing.md },
        actions: { gap: theme.spacing.md },
      }),
    [theme],
  );

  const navigation = useRootNavigation();
  const route = useRoute<RouteProp<RootStackParamList, 'AlertDetail'>>();
  const { alertId } = route.params;

  const alert = useAlertStore((s) => s.alerts.find((a) => a.id === alertId));
  const markRead = useAlertStore((s) => s.markRead);
  const markUnread = useAlertStore((s) => s.markUnread);
  const removeAlert = useAlertStore((s) => s.removeAlert);

  useEffect(() => {
    if (alert && !alert.isRead) {
      markRead(alertId);
    }
  }, [alert, alertId, markRead]);

  if (!alert) {
    return (
      <Screen scroll edges={['left', 'right']}>
        <ErrorState
          title="Alert not found"
          message="This alert is no longer available. It may have been cleared from history."
          retryLabel="Go back"
          onRetry={() => navigation.goBack()}
        />
      </Screen>
    );
  }

  const tone = severityTone(alert.severity);

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={styles.content}>
        <Card tone={tone}>
          <View style={styles.card}>
            <View style={styles.titleRow}>
              {tone === 'malicious' ? (
                <TriangleAlert size={24} color={theme.colors.malicious} />
              ) : (
                <ShieldAlert size={24} color={theme.colors[tone]} />
              )}
              <AppText variant="heading" style={styles.flexFill}>
                {threatTypeLabel(alert.threatType)}
              </AppText>
            </View>
            <View style={styles.badgeRow}>
              <Badge label={severityLabel(alert.severity)} tone={tone} />
              {alert.category ? <Badge label={categoryLabel(alert.category)} tone="unknown" /> : null}
            </View>
          </View>
        </Card>

        {alert.recommendedAction ? (
          <AlertBanner
            tone={tone}
            icon={<ShieldAlert size={20} color={theme.colors[tone]} />}
            title="Recommended action"
            message={alert.recommendedAction}
          />
        ) : null}

        <View>
          <SectionHeader title="Detection" />
          <Card flush>
            <View style={styles.detail}>
              <KeyValue label="Reason" value={alert.detectionReason} />
              {alert.target ? <KeyValue label="Target" value={alert.target} mono selectable /> : null}
              {alert.sourceApplication ? (
                <KeyValue label="Source app" value={alert.sourceApplication} />
              ) : null}
              <KeyValue label="Detected" value={formatDateTime(alert.createdAt)} />
              <KeyValue label="Status" value={alert.isRead ? 'Read' : 'Unread'} />
            </View>
          </Card>
        </View>

        <Card>
          <View style={styles.noteRow}>
            <ShieldAlert size={20} color={theme.colors.textSecondary} />
            <AppText variant="caption" color="secondary" style={styles.flexFill}>
              ThreatGuard does not open flagged links or files for you. If you recognise the target as
              a threat, delete the message or file rather than interacting with it.
            </AppText>
          </View>
        </Card>

        <View style={styles.actions}>
          <Button
            label={alert.isRead ? 'Mark as unread' : 'Mark as read'}
            variant="secondary"
            icon={<CircleCheck size={18} color={theme.colors.accent} />}
            fullWidth
            onPress={() => (alert.isRead ? markUnread(alertId) : markRead(alertId))}
          />
          <Divider />
          <Button
            label="Delete alert"
            variant="danger"
            icon={<Trash2 size={18} color={theme.colors.malicious} />}
            fullWidth
            onPress={() => {
              removeAlert(alertId);
              navigation.goBack();
            }}
          />
        </View>
      </View>
    </Screen>
  );
}
