import React, { useMemo, useState } from 'react';
import { FlatList, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useTheme } from '../theme';
import { AppText, Button, Chip, EmptyState, ListRow } from '../components/ui';
import { ShieldCheck } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useAlertStore } from '../store';
import { severityTone, threatTypeLabel } from '../domain/threat';
import { formatRelativeTime } from '../utils/format';
import type { Severity } from '../domain/types';

type Filter = 'all' | 'unread' | Severity;

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'unread', label: 'Unread' },
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'medium', label: 'Medium' },
  { id: 'low', label: 'Low' },
];

export function AlertsScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const alerts = useAlertStore((s) => s.alerts);
  const markAllRead = useAlertStore((s) => s.markAllRead);
  const clear = useAlertStore((s) => s.clear);
  const unreadCount = alerts.filter((a) => !a.isRead).length;
  const [filter, setFilter] = useState<Filter>('all');

  const filtered = useMemo(() => {
    switch (filter) {
      case 'all':
        return alerts;
      case 'unread':
        return alerts.filter((a) => !a.isRead);
      default:
        return alerts.filter((a) => a.severity === filter);
    }
  }, [alerts, filter]);

  const header = (
    <View style={{ gap: theme.spacing.md, paddingHorizontal: theme.layout.screenPadding, paddingTop: theme.spacing.md }}>
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: theme.spacing.sm }}>
        {FILTERS.map((f) => (
          <Chip key={f.id} label={f.label} selected={filter === f.id} onPress={() => setFilter(f.id)} />
        ))}
      </View>
      {alerts.length > 0 ? (
        <View style={{ flexDirection: 'row', gap: theme.spacing.sm }}>
          <Button
            label="Mark all read"
            variant="ghost"
            size="sm"
            disabled={unreadCount === 0}
            onPress={markAllRead}
          />
          <Button label="Clear" variant="ghost" size="sm" onPress={clear} />
        </View>
      ) : null}
    </View>
  );

  return (
    <SafeAreaView edges={['left', 'right']} style={{ flex: 1, backgroundColor: theme.colors.background }}>
      <FlatList
        data={filtered}
        keyExtractor={(item) => item.id}
        ListHeaderComponent={header}
        contentContainerStyle={{ paddingBottom: theme.spacing.huge }}
        ItemSeparatorComponent={() => (
          <View style={{ height: 1, marginHorizontal: theme.layout.screenPadding, backgroundColor: theme.colors.border }} />
        )}
        ListEmptyComponent={
          <EmptyState
            icon={<ShieldCheck size={40} color={theme.colors.textTertiary} />}
            title={alerts.length === 0 ? 'No alerts yet' : 'Nothing matches this filter'}
            message={
              alerts.length === 0
                ? 'When a scan or a monitored message turns up a threat, it will appear here.'
                : 'Try a different filter to see other alerts.'
            }
          />
        }
        renderItem={({ item }) => (
          <View
            style={{
              paddingHorizontal: theme.layout.screenPadding,
              backgroundColor: item.isRead ? 'transparent' : theme.colors.surface,
            }}
          >
            <ListRow
              title={threatTypeLabel(item.threatType)}
              subtitle={item.detectionReason}
              meta={`${item.target ?? ''}${item.target ? ' · ' : ''}${formatRelativeTime(item.createdAt)}`}
              leading={
                <View
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: 5,
                    marginTop: 6,
                    backgroundColor: theme.colors[dotColor(severityTone(item.severity))],
                  }}
                />
              }
              trailing={!item.isRead ? <AppText variant="caption" color="accent">New</AppText> : undefined}
              onPress={() => navigation.navigate('AlertDetail', { alertId: item.id })}
            />
          </View>
        )}
      />
    </SafeAreaView>
  );
}

function dotColor(tone: ReturnType<typeof severityTone>): 'safe' | 'suspicious' | 'malicious' | 'unknown' {
  if (tone === 'info') return 'unknown';
  if (tone === 'safe') return 'safe';
  if (tone === 'suspicious') return 'suspicious';
  if (tone === 'malicious') return 'malicious';
  return 'unknown';
}
