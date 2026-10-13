import React, { useMemo, useState } from 'react';
import { FlatList, TextInput, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useTheme } from '../theme';
import { AppText, Button, Chip, EmptyState, ListRow } from '../components/ui';
import { History as HistoryIcon, Search } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useScanStore } from '../store';
import { scanTypeLabel, severityLabel, severityTone } from '../domain/threat';
import { formatRelativeTime, formatDuration } from '../utils/format';
import { toneColors } from '../theme';
import type { ScanType } from '../domain/types';

type Filter = 'all' | ScanType;

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'url', label: 'Links' },
  { id: 'file', label: 'Files' },
  { id: 'apk', label: 'Apps' },
  { id: 'notification', label: 'Messages' },
  { id: 'quick', label: 'Quick' },
  { id: 'full', label: 'Full' },
];

export function HistoryScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const records = useScanStore((s) => s.records);
  const clear = useScanStore((s) => s.clear);
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return records.filter((record) => {
      if (filter !== 'all' && record.scanType !== filter) return false;
      if (needle.length === 0) return true;
      const haystack = `${record.target ?? ''} ${record.fileName ?? ''} ${record.fileHash ?? ''}`.toLowerCase();
      return haystack.includes(needle);
    });
  }, [records, filter, query]);

  const header = (
    <View style={{ gap: theme.spacing.md, paddingHorizontal: theme.layout.screenPadding, paddingTop: theme.spacing.md }}>
      <View
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          gap: theme.spacing.sm,
          backgroundColor: theme.colors.sunken,
          borderRadius: theme.radius.md,
          borderWidth: 1,
          borderColor: theme.colors.border,
          paddingHorizontal: theme.spacing.md,
          height: 44,
        }}
      >
        <Search size={18} color={theme.colors.textTertiary} />
        <TextInput
          value={query}
          onChangeText={setQuery}
          placeholder="Search by domain, file or hash"
          placeholderTextColor={theme.colors.textTertiary}
          style={{ flex: 1, color: theme.colors.textPrimary, paddingVertical: 0 }}
          autoCapitalize="none"
          autoCorrect={false}
          accessibilityLabel="Search scan history"
        />
      </View>
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: theme.spacing.sm }}>
        {FILTERS.map((f) => (
          <Chip key={f.id} label={f.label} selected={filter === f.id} onPress={() => setFilter(f.id)} />
        ))}
      </View>
      {records.length > 0 ? (
        <Button label="Clear history" variant="ghost" size="sm" onPress={clear} />
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
            icon={<HistoryIcon size={40} color={theme.colors.textTertiary} />}
            title={records.length === 0 ? 'No scans yet' : 'No matches'}
            message={
              records.length === 0
                ? 'Scans you run will be listed here with their result.'
                : 'Try a different search term or filter.'
            }
          />
        }
        renderItem={({ item }) => (
          <View style={{ paddingHorizontal: theme.layout.screenPadding }}>
            <ListRow
              title={item.target ?? item.fileName ?? scanTypeLabel(item.scanType)}
              subtitle={`${scanTypeLabel(item.scanType)} · ${item.filesChecked} checked · ${formatDuration(item.durationMs)}`}
              meta={formatRelativeTime(item.scannedAt)}
              leading={
                <View
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: 5,
                    marginTop: 6,
                    backgroundColor: toneColors(theme, severityTone(item.threatLevel)).fg,
                  }}
                />
              }
              trailing={
                <AppText variant="caption" color="tertiary">
                  {severityLabel(item.threatLevel)}
                </AppText>
              }
              onPress={() => navigation.navigate('ScanDetail', { scanId: item.id })}
            />
          </View>
        )}
      />
    </SafeAreaView>
  );
}
