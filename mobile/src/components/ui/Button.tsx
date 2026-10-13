import React from 'react';
import {
  ActivityIndicator,
  Pressable,
  View,
  type StyleProp,
  type ViewStyle,
} from 'react-native';
import { useTheme } from '../../theme';
import { AppText, textColorFor, type TextColorRole } from './Text';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps {
  label: string;
  onPress?: () => void;
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Leading icon element (e.g. a Lucide icon) rendered before the label. */
  icon?: React.ReactNode;
  disabled?: boolean;
  loading?: boolean;
  fullWidth?: boolean;
  style?: StyleProp<ViewStyle>;
  accessibilityHint?: string;
  testID?: string;
}

interface VariantStyle {
  container: ViewStyle;
  labelColor: TextColorRole;
}

export function Button({
  label,
  onPress,
  variant = 'primary',
  size = 'md',
  icon,
  disabled = false,
  loading = false,
  fullWidth = false,
  style,
  accessibilityHint,
  testID,
}: ButtonProps): React.JSX.Element {
  const theme = useTheme();
  const isDisabled = disabled || loading;

  const height = size === 'sm' ? 38 : size === 'lg' ? 56 : 48;
  const horizontalPadding = size === 'sm' ? theme.spacing.md : theme.spacing.xl;
  const textVariant = size === 'sm' ? 'label' : 'bodyStrong';

  const variants: Record<ButtonVariant, VariantStyle> = {
    primary: {
      container: { backgroundColor: theme.colors.accent, borderWidth: 0 },
      labelColor: 'onAccent',
    },
    secondary: {
      container: {
        backgroundColor: theme.colors.accentMuted,
        borderWidth: 1,
        borderColor: theme.colors.border,
      },
      labelColor: 'accent',
    },
    ghost: {
      container: { backgroundColor: 'transparent', borderWidth: 0 },
      labelColor: 'primary',
    },
    danger: {
      container: { backgroundColor: theme.colors.maliciousSurface, borderWidth: 1, borderColor: theme.colors.malicious },
      labelColor: 'malicious',
    },
  };

  const selected = variants[variant];

  return (
    <Pressable
      onPress={isDisabled ? undefined : onPress}
      disabled={isDisabled}
      testID={testID}
      accessibilityRole="button"
      accessibilityState={{ disabled: isDisabled, busy: loading }}
      accessibilityHint={accessibilityHint}
      android_ripple={isDisabled ? undefined : { color: theme.colors.overlay }}
      style={({ pressed }) => [
        {
          height,
          paddingHorizontal: horizontalPadding,
          borderRadius: theme.radius.md,
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'center',
          gap: theme.spacing.sm,
          opacity: isDisabled ? 0.5 : 1,
        },
        selected.container,
        fullWidth ? { alignSelf: 'stretch' } : { alignSelf: 'flex-start' },
        pressed && !isDisabled ? { opacity: 0.85 } : null,
        style,
      ]}
    >
      {loading ? (
        <ActivityIndicator size="small" color={textColorFor(theme, selected.labelColor)} />
      ) : (
        <>
          {icon ? <View>{icon}</View> : null}
          <AppText variant={textVariant} color={selected.labelColor} numberOfLines={1}>
            {label}
          </AppText>
        </>
      )}
    </Pressable>
  );
}
