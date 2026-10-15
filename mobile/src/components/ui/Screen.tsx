import React, { useMemo } from 'react';
import { ScrollView, StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
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
  const styles = useMemo(
    () =>
      StyleSheet.create({
        safe: { flex: 1, backgroundColor: theme.colors.background },
        scrollContent: { paddingBottom: theme.spacing.huge },
        content: { flex: 1 },
      }),
    [theme],
  );
  const padding = padded
    ? { paddingHorizontal: theme.layout.screenPadding, paddingVertical: theme.spacing.lg }
    : undefined;

  return (
    <SafeAreaView edges={edges} style={[styles.safe, style]}>
      {scroll ? (
        <ScrollView
          contentContainerStyle={[padding, styles.scrollContent, contentContainerStyle]}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
          refreshControl={refreshControl}
        >
          {children}
        </ScrollView>
      ) : (
        <View style={[styles.content, padding, contentContainerStyle]}>{children}</View>
      )}
    </SafeAreaView>
  );
}
