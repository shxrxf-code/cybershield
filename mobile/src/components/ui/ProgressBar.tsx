import React from 'react';
import { View, type StyleProp, type ViewStyle } from 'react-native';
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

  return (
    <View style={[{ gap: theme.spacing.xs }, style]}>
      {label || showPercent ? (
        <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
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
        style={{
          height,
          borderRadius: theme.radius.pill,
          backgroundColor: theme.colors.sunken,
          overflow: 'hidden',
        }}
      >
        <View
          style={{
            width: `${clamped * 100}%`,
            height: '100%',
            borderRadius: theme.radius.pill,
            backgroundColor: fg,
          }}
        />
      </View>
    </View>
  );
}
