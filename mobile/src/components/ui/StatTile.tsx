import React, { useMemo } from 'react';
import { Pressable, StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import type { ThreatTone } from '../../theme/theme';
import { AppText } from './Text';

export interface StatTileProps {
  label: string;
  value: string | number;
  hint?: string;
  tone?: ThreatTone;
  icon?: React.ReactNode;
  onPress?: () => void;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
}

/**
 * A single number with context. Used on the dashboard; every value is passed in
 * from real data, never invented here.
 */
export function StatTile({
  label,
  value,
  hint,
  icon,
  onPress,
  style,
  accessibilityLabel,
}: StatTileProps): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: {
          backgroundColor: theme.colors.surface,
          borderRadius: theme.radius.lg,
          borderWidth: 1,
          borderColor: theme.colors.border,
          padding: theme.spacing.lg,
          gap: theme.spacing.sm,
          minWidth: 140,
          flex: 1,
        },
        header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
        pressable: { flex: 1 },
      }),
    [theme],
  );

  const body = (
    <View style={[styles.root, style]}>
      <View style={styles.header}>
        <AppText variant="caption" color="secondary">
          {label}
        </AppText>
        {icon}
      </View>
      <AppText variant="display">{value}</AppText>
      {hint ? (
        <AppText variant="caption" color="tertiary">
          {hint}
        </AppText>
      ) : null}
    </View>
  );

  if (!onPress) return body;

  return (
    <Pressable
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? label}
      android_ripple={{ color: theme.colors.overlay }}
      style={styles.pressable}
    >
      {body}
    </Pressable>
  );
}
