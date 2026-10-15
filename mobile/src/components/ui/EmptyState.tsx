import React, { useMemo } from 'react';
import { StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface EmptyStateProps {
  title: string;
  message?: string;
  /** A large muted icon (e.g. a Lucide icon at 40px, tertiary colour). */
  icon?: React.ReactNode;
  action?: React.ReactNode;
  style?: StyleProp<ViewStyle>;
}

/**
 * Honest "nothing here yet" state. Never dressed up with fake data — an empty
 * list says it is empty.
 */
export function EmptyState({ title, message, icon, action, style }: EmptyStateProps): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: {
          alignItems: 'center',
          justifyContent: 'center',
          gap: theme.spacing.sm,
          paddingVertical: theme.spacing.xxxl,
          paddingHorizontal: theme.spacing.xl,
        },
        icon: { marginBottom: theme.spacing.xs },
        action: { marginTop: theme.spacing.md },
      }),
    [theme],
  );
  return (
    <View style={[styles.root, style]}>
      {icon ? <View style={styles.icon}>{icon}</View> : null}
      <AppText variant="subheading" align="center">
        {title}
      </AppText>
      {message ? (
        <AppText variant="body" color="secondary" align="center">
          {message}
        </AppText>
      ) : null}
      {action ? <View style={styles.action}>{action}</View> : null}
    </View>
  );
}
