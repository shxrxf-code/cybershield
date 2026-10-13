import React from 'react';
import { View, type StyleProp, type ViewStyle } from 'react-native';
import { toneColors, useTheme } from '../../theme';
import type { ThreatTone } from '../../theme/theme';
import { AppText } from './Text';

export interface AlertBannerProps {
  title: string;
  message?: string;
  tone?: ThreatTone;
  icon?: React.ReactNode;
  /** Trailing action element (e.g. a small button). */
  action?: React.ReactNode;
  style?: StyleProp<ViewStyle>;
}

/** An inline, tone-coloured notice used for warnings and important context. */
export function AlertBanner({
  title,
  message,
  tone = 'info',
  icon,
  action,
  style,
}: AlertBannerProps): React.JSX.Element {
  const theme = useTheme();
  const { fg, bg } = toneColors(theme, tone);

  return (
    <View
      accessibilityRole="alert"
      style={[
        {
          flexDirection: 'row',
          gap: theme.spacing.md,
          padding: theme.spacing.md,
          borderRadius: theme.radius.md,
          borderWidth: 1,
          borderColor: fg,
          backgroundColor: bg,
        },
        style,
      ]}
    >
      {icon ? <View style={{ paddingTop: 1 }}>{icon}</View> : null}
      <View style={{ flex: 1, gap: theme.spacing.xs }}>
        <AppText variant="bodyStrong">{title}</AppText>
        {message ? (
          <AppText variant="caption" color="secondary">
            {message}
          </AppText>
        ) : null}
        {action ? <View style={{ marginTop: theme.spacing.xs }}>{action}</View> : null}
      </View>
    </View>
  );
}
