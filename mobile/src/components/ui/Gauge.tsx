import React, { useMemo } from 'react';
import { StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import Svg, { Circle } from 'react-native-svg';
import { toneColors, useTheme } from '../../theme';
import type { ThreatTone } from '../../theme/theme';
import { AppText } from './Text';

export interface GaugeProps {
  /** 0–100. Used for the risk score. */
  value: number;
  size?: number;
  strokeWidth?: number;
  tone?: ThreatTone;
  /** Large centre text (e.g. the score). */
  label?: string;
  /** Small centre text under the label. */
  caption?: string;
  style?: StyleProp<ViewStyle>;
}

/**
 * A circular progress gauge. The track is a full ring; the foreground arc is
 * coloured by the threat tone. Non-threat-bearing by itself: callers pass the
 * tone so red always means malicious.
 */
export function Gauge({
  value,
  size = 132,
  strokeWidth = 12,
  tone = 'info',
  label,
  caption,
  style,
}: GaugeProps): React.JSX.Element {
  const theme = useTheme();
  const clamped = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0));
  const { fg } = toneColors(theme, tone);

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - clamped / 100);
  const styles = useMemo(
    () =>
      StyleSheet.create({
        container: { width: size, height: size, alignItems: 'center', justifyContent: 'center' },
        center: { position: 'absolute', alignItems: 'center' },
      }),
    [size],
  );

  return (
    <View style={[styles.container, style]}>
      <Svg width={size} height={size}>
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={theme.colors.sunken}
          strokeWidth={strokeWidth}
          fill="none"
        />
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={fg}
          strokeWidth={strokeWidth}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${circumference} ${circumference}`}
          strokeDashoffset={dashOffset}
          // Start the arc at 12 o'clock.
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </Svg>
      <View style={styles.center}>
        {label ? <AppText variant="title">{label}</AppText> : null}
        {caption ? (
          <AppText variant="caption" color="secondary">
            {caption}
          </AppText>
        ) : null}
      </View>
    </View>
  );
}
