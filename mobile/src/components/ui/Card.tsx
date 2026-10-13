import React from 'react';
import { Pressable, View, type StyleProp, type ViewStyle } from 'react-native';
import { toneColors, useTheme } from '../../theme';
import type { ThreatTone } from '../../theme/theme';

export interface CardProps {
  children: React.ReactNode;
  style?: StyleProp<ViewStyle>;
  /** Remove internal padding (for lists that manage their own rows). */
  flush?: boolean;
  /** Use the raised surface + shadow. */
  elevated?: boolean;
  /** Coloured left border + tinted surface for status emphasis. */
  tone?: ThreatTone;
  onPress?: () => void;
  accessibilityLabel?: string;
}

/**
 * A surface container. Cards are the primary grouping element across the app;
 * `tone` gives a threat result its semantic colour without shouting.
 */
export function Card({
  children,
  style,
  flush = false,
  elevated = false,
  tone,
  onPress,
  accessibilityLabel,
}: CardProps): React.JSX.Element {
  const theme = useTheme();

  const base: ViewStyle = {
    backgroundColor: elevated ? theme.colors.elevated : theme.colors.surface,
    borderRadius: theme.radius.lg,
    borderWidth: 1,
    borderColor: theme.colors.border,
    padding: flush ? 0 : theme.spacing.lg,
    ...(elevated ? theme.elevation.md : theme.elevation.none),
  };

  const toned: ViewStyle =
    tone === undefined
      ? {}
      : {
          borderColor: toneColors(theme, tone).fg,
          borderLeftWidth: 4,
          backgroundColor: toneColors(theme, tone).bg,
        };

  if (!onPress) {
    return (
      <View style={[base, toned, style]} accessibilityLabel={accessibilityLabel}>
        {children}
      </View>
    );
  }

  return (
    <Pressable
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel}
      android_ripple={{ color: theme.colors.overlay }}
      style={({ pressed }) => [
        base,
        toned,
        pressed ? { backgroundColor: theme.colors.overlay } : null,
        style,
      ]}
    >
      {children}
    </Pressable>
  );
}
