import React from 'react';
import { Pressable, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';

export interface IconButtonProps {
  icon: React.ReactNode;
  onPress?: () => void;
  accessibilityLabel: string;
  disabled?: boolean;
  size?: number;
  /** Tint the hit target surface; `transparent` by default. */
  solid?: boolean;
  style?: StyleProp<ViewStyle>;
  testID?: string;
}

/** A square, icon-only pressable with a guaranteed 44pt touch target. */
export function IconButton({
  icon,
  onPress,
  accessibilityLabel,
  disabled = false,
  size = 44,
  solid = false,
  style,
  testID,
}: IconButtonProps): React.JSX.Element {
  const theme = useTheme();

  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel}
      accessibilityState={{ disabled }}
      android_ripple={disabled ? undefined : { color: theme.colors.overlay, borderless: true }}
      style={({ pressed }) => [
        {
          width: size,
          height: size,
          borderRadius: size / 2,
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: solid ? theme.colors.sunken : 'transparent',
          opacity: disabled ? 0.4 : 1,
        },
        pressed && !disabled ? { backgroundColor: theme.colors.overlay } : null,
        style,
      ]}
    >
      {icon}
    </Pressable>
  );
}
