import React from 'react';
import { Pressable } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface ChipProps {
  label: string;
  selected?: boolean;
  onPress?: () => void;
  /** Leading icon element. */
  icon?: React.ReactNode;
  disabled?: boolean;
}

/** A compact, selectable filter/segment token. */
export function Chip({ label, selected = false, onPress, icon, disabled }: ChipProps): React.JSX.Element {
  const theme = useTheme();

  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      accessibilityRole="button"
      accessibilityState={{ selected, disabled }}
      android_ripple={{ color: theme.colors.overlay, borderless: false }}
      style={({ pressed }) => [
        {
          flexDirection: 'row',
          alignItems: 'center',
          gap: theme.spacing.xs,
          paddingVertical: theme.spacing.sm,
          paddingHorizontal: theme.spacing.md,
          borderRadius: theme.radius.pill,
          borderWidth: 1,
          borderColor: selected ? theme.colors.accent : theme.colors.border,
          backgroundColor: selected ? theme.colors.accentMuted : theme.colors.surface,
          opacity: disabled ? 0.5 : 1,
        },
        pressed && !disabled ? { opacity: 0.8 } : null,
      ]}
    >
      {icon}
      <AppText variant="label" color={selected ? 'accent' : 'secondary'}>
        {label}
      </AppText>
    </Pressable>
  );
}
