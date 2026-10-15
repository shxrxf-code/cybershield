import React, { useMemo } from 'react';
import { StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface DividerProps {
  /** Optional centred label (e.g. "or"). */
  label?: string;
  style?: StyleProp<ViewStyle>;
}

export function Divider({ label, style }: DividerProps): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        line: { height: 1, flex: 1, backgroundColor: theme.colors.border },
        plain: { height: 1, backgroundColor: theme.colors.border },
        row: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.md },
      }),
    [theme],
  );

  if (!label) {
    return <View style={[styles.plain, style]} />;
  }

  return (
    <View style={styles.row}>
      <View style={styles.line} />
      <AppText variant="caption" color="tertiary">
        {label}
      </AppText>
      <View style={styles.line} />
    </View>
  );
}
