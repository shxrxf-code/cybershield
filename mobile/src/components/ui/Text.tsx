import React from 'react';
import { Text as RNText, type TextProps as RNTextProps, type TextStyle } from 'react-native';
import { useTheme } from '../../theme';
import type { ColorTokens, TypographyToken } from '../../theme/tokens';

/** Semantic colour roles a piece of text can use. */
export type TextColorRole =
  | 'primary'
  | 'secondary'
  | 'tertiary'
  | 'inverse'
  | 'onAccent'
  | 'accent'
  | 'safe'
  | 'suspicious'
  | 'malicious'
  | 'unknown'
  | 'info';

const COLOR_ROLES: Record<TextColorRole, keyof ColorTokens> = {
  primary: 'textPrimary',
  secondary: 'textSecondary',
  tertiary: 'textTertiary',
  inverse: 'textInverse',
  onAccent: 'onAccent',
  accent: 'accent',
  safe: 'safe',
  suspicious: 'suspicious',
  malicious: 'malicious',
  unknown: 'unknown',
  info: 'info',
};

/** Resolve a text colour role to its concrete value for the active theme. */
export function textColorFor(theme: ReturnType<typeof useTheme>, role: TextColorRole): string {
  return theme.colors[COLOR_ROLES[role]];
}

export interface AppTextProps extends RNTextProps {
  variant?: TypographyToken;
  color?: TextColorRole;
  align?: TextStyle['textAlign'];
  /** Override the token weight when a one-off emphasis is needed. */
  weight?: TextStyle['fontWeight'];
}

/**
 * Themed text. Uses the typographic scale and colour roles so no screen has to
 * know a hex value or a raw font size.
 */
export function AppText({
  variant = 'body',
  color = 'primary',
  align,
  weight,
  style,
  ...rest
}: AppTextProps): React.JSX.Element {
  const theme = useTheme();
  const token = theme.typography[variant];
  return (
    <RNText
      {...rest}
      style={[
        token,
        { color: textColorFor(theme, color) },
        weight ? { fontWeight: weight } : null,
        align ? { textAlign: align } : null,
        style,
      ]}
    />
  );
}

export { AppText as Text };
