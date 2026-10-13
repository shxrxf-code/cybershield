import React from 'react';
import { View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface DividerProps {
  /** Optional centred label (e.g. "or"). */
  label?: string;
  style?: StyleProp<ViewStyle>;
}

export function Divider({ label, style }: DividerProps): React.JSX.Element {
  const theme = useTheme();
  const line: ViewStyle = { height: 1, flex: 1, backgroundColor: theme.colors.border };

  if (!label) {
    return <View style={[{ height: 1, backgroundColor: theme.colors.border }, style]} />;
  }

  return (
    <View
      style={[
        { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.md },
        style,
      ]}
    >
      <View style={line} />
      <AppText variant="caption" color="tertiary">
        {label}
      </AppText>
      <View style={line} />
    </View>
  );
}
