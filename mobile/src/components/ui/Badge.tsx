import React from 'react';
import { View, type StyleProp, type ViewStyle } from 'react-native';
import { toneColors, useTheme } from '../../theme';
import type { ThreatTone } from '../../theme/theme';
import { AppText } from './Text';

export interface BadgeProps {
  label: string;
  tone?: ThreatTone;
  /** Leading icon element at badge scale (~14px). */
  icon?: React.ReactNode;
  size?: 'sm' | 'md';
  style?: StyleProp<ViewStyle>;
}

/** A small, tone-coloured pill for verdicts, severities and categories. */
export function Badge({ label, tone = 'unknown', icon, size = 'md', style }: BadgeProps): React.JSX.Element {
  const theme = useTheme();
  const { fg, bg } = toneColors(theme, tone);

  return (
    <View
      style={[
        {
          flexDirection: 'row',
          alignItems: 'center',
          gap: theme.spacing.xs,
          alignSelf: 'flex-start',
          paddingVertical: size === 'sm' ? 2 : theme.spacing.xs,
          paddingHorizontal: size === 'sm' ? theme.spacing.sm : theme.spacing.md,
          borderRadius: theme.radius.pill,
          backgroundColor: bg,
          borderWidth: 1,
          borderColor: fg,
        },
        style,
      ]}
    >
      {icon}
      <AppText variant={size === 'sm' ? 'caption' : 'label'} style={{ color: fg }}>
        {label}
      </AppText>
    </View>
  );
}
