import React from 'react';
import { View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';
import { Button } from './Button';

export interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
  icon?: React.ReactNode;
  style?: StyleProp<ViewStyle>;
}

/**
 * A recoverable error surface. The message is always the real, user-safe
 * message from the failure — never a generic "something went wrong" that hides
 * what actually happened.
 */
export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
  retryLabel = 'Try again',
  icon,
  style,
}: ErrorStateProps): React.JSX.Element {
  const theme = useTheme();
  return (
    <View
      style={[
        {
          alignItems: 'center',
          justifyContent: 'center',
          gap: theme.spacing.sm,
          paddingVertical: theme.spacing.xxxl,
          paddingHorizontal: theme.spacing.xl,
        },
        style,
      ]}
    >
      {icon ? <View style={{ marginBottom: theme.spacing.xs }}>{icon}</View> : null}
      <AppText variant="subheading" color="malicious" align="center">
        {title}
      </AppText>
      <AppText variant="body" color="secondary" align="center">
        {message}
      </AppText>
      {onRetry ? (
        <View style={{ marginTop: theme.spacing.md }}>
          <Button label={retryLabel} variant="secondary" onPress={onRetry} />
        </View>
      ) : null}
    </View>
  );
}
