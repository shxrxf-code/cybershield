import React, { useMemo } from 'react';
import { StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface KeyValueProps {
  label: string;
  value: string;
  /** Render the value in a monospace face (hashes, domains, package names). */
  mono?: boolean;
  selectable?: boolean;
  style?: StyleProp<ViewStyle>;
}

/** A two-column label/value row for detail and report screens. */
export function KeyValue({ label, value, mono = false, selectable = false, style }: KeyValueProps): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: {
          flexDirection: 'row',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: theme.spacing.lg,
          paddingVertical: theme.spacing.sm,
        },
        label: { flexShrink: 0 },
        value: { flex: 1 },
      }),
    [theme],
  );
  return (
    <View style={[styles.root, style]}>
      <AppText variant="caption" color="secondary" style={styles.label}>
        {label}
      </AppText>
      <AppText
        variant={mono ? 'mono' : 'body'}
        align="right"
        selectable={selectable}
        style={styles.value}
      >
        {value}
      </AppText>
    </View>
  );
}
