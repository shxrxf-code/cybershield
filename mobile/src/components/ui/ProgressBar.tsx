import React, { useMemo } from 'react';
import { StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { toneColors, useTheme } from '../../theme';
import type { ThreatTone } from '../../theme/theme';
import { AppText } from './Text';

export interface ProgressBarProps {
  /** 0–1. Values outside the range are clamped. */
  value: number;
  tone?: ThreatTone;
  label?: string;
  /** Show the percentage on the right of the label row. */
  showPercent?: boolean;
  height?: number;
  style?: StyleProp<ViewStyle>;
}

export function ProgressBar({
  value,
  tone = 'info',
  label,
  showPercent = false,
  height = 8,
  style,
}: ProgressBarProps): React.JSX.Element {
  const theme = useTheme();
  const clamped = Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
  const { fg } = toneColors(theme, tone);
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: { gap: theme.spacing.xs },
        header: { flexDirection: 'row', justifyContent: 'space-between' },
        track: {
          height,
          borderRadius: theme.radius.pill,
          backgroundColor: theme.colors.sunken,
          overflow: 'hidden',
        },
        fill: {
          width: `${clamped * 100}%`,
          height: '100%',
          borderRadius: theme.radius.pill,
          backgroundColor: fg,
        },
      }),
    [theme, height, clamped, fg],
  );

  return (
    <View style={[styles.root, style]}>
      {label || showPercent ? (
        <View style={styles.header}>
          {label ? (
            <AppText variant="caption" color="secondary">
              {label}
            </AppText>
          ) : (
            <View />
          )}
          {showPercent ? (
            <AppText variant="caption" color="secondary">
              {Math.round(clamped * 100)}%
            </AppText>
          ) : null}
        </View>
      ) : null}
      <View
        accessibilityRole="progressbar"
        accessibilityValue={{ min: 0, max: 100, now: Math.round(clamped * 100) }}
        style={styles.track}
      >
        <View style={styles.fill} />
      </View>
    </View>
  );
}
