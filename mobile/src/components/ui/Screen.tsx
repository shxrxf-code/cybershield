import React from 'react';
import { ScrollView, View, type StyleProp, type ViewStyle } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useTheme } from '../../theme';

export type ScreenEdge = 'top' | 'bottom' | 'left' | 'right';

export interface ScreenProps {
  children: React.ReactNode;
  /** Wrap content in a ScrollView. */
  scroll?: boolean;
  /** Apply the standard horizontal/vertical content padding. */
  padded?: boolean;
  /** Safe-area edges to respect. Defaults to top + bottom (headers excluded). */
  edges?: ScreenEdge[];
  style?: StyleProp<ViewStyle>;
  contentContainerStyle?: StyleProp<ViewStyle>;
  /** Refresh control for scrollable screens. */
  refreshControl?: React.ReactElement;
}

/**
 * The root container for every screen: safe-area aware, themed background, and
 * an optional scroll surface. Keeps spacing identical across screens.
 */
export function Screen({
  children,
  scroll = false,
  padded = true,
  edges = ['left', 'right'],
  style,
  contentContainerStyle,
  refreshControl,
}: ScreenProps): React.JSX.Element {
  const theme = useTheme();
  const padding = padded
    ? { paddingHorizontal: theme.layout.screenPadding, paddingVertical: theme.spacing.lg }
    : undefined;

  return (
    <SafeAreaView
      edges={edges}
      style={[{ flex: 1, backgroundColor: theme.colors.background }, style]}
    >
      {scroll ? (
        <ScrollView
          contentContainerStyle={[padding, { paddingBottom: theme.spacing.huge }, contentContainerStyle]}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
          refreshControl={refreshControl}
        >
          {children}
        </ScrollView>
      ) : (
        <View style={[{ flex: 1 }, padding, contentContainerStyle]}>{children}</View>
      )}
    </SafeAreaView>
  );
}
