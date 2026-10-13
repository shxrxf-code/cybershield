import React from 'react';
import { View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface SectionHeaderProps {
  title: string;
  subtitle?: string;
  /** Trailing element (e.g. a "See all" button). */
  action?: React.ReactNode;
  style?: StyleProp<ViewStyle>;
}

export function SectionHeader({ title, subtitle, action, style }: SectionHeaderProps): React.JSX.Element {
  const theme = useTheme();
  return (
    <View
      style={[
        {
          flexDirection: 'row',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          gap: theme.spacing.md,
          marginBottom: theme.spacing.md,
        },
        style,
      ]}
    >
      <View style={{ flex: 1, gap: theme.spacing.xxs }}>
        <AppText variant="subheading">{title}</AppText>
        {subtitle ? (
          <AppText variant="caption" color="secondary">
            {subtitle}
          </AppText>
        ) : null}
      </View>
      {action}
    </View>
  );
}
