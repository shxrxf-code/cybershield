import React, { useMemo } from 'react';
import { ActivityIndicator, StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface LoadingStateProps {
  label?: string;
  style?: StyleProp<ViewStyle>;
}

export function LoadingState({ label = 'Loading…', style }: LoadingStateProps): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: {
          alignItems: 'center',
          justifyContent: 'center',
          gap: theme.spacing.md,
          paddingVertical: theme.spacing.xxxl,
        },
      }),
    [theme],
  );
  return (
    <View style={[styles.root, style]}>
      <ActivityIndicator size="large" color={theme.colors.accent} />
      <AppText variant="caption" color="secondary">
        {label}
      </AppText>
    </View>
  );
}
