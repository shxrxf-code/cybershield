import React from 'react';
import { ActivityIndicator, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface LoadingStateProps {
  label?: string;
  style?: StyleProp<ViewStyle>;
}

export function LoadingState({ label = 'Loading…', style }: LoadingStateProps): React.JSX.Element {
  const theme = useTheme();
  return (
    <View
      style={[
        {
          alignItems: 'center',
          justifyContent: 'center',
          gap: theme.spacing.md,
          paddingVertical: theme.spacing.xxxl,
        },
        style,
      ]}
    >
      <ActivityIndicator size="large" color={theme.colors.accent} />
      <AppText variant="caption" color="secondary">
        {label}
      </AppText>
    </View>
  );
}
