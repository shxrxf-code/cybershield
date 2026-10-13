import React from 'react';
import { Pressable, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../../theme';
import { AppText } from './Text';

export interface ListRowProps {
  title: string;
  subtitle?: string;
  /** Small caption shown under the subtitle (e.g. a timestamp). */
  meta?: string;
  /** A leading element: icon container, avatar, or status dot. */
  leading?: React.ReactNode;
  /** A trailing element; defaults to a chevron when `onPress` is set. */
  trailing?: React.ReactNode;
  onPress?: () => void;
  showChevron?: boolean;
  destructive?: boolean;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
  testID?: string;
}

/** The standard tappable row used by lists across the app. */
export function ListRow({
  title,
  subtitle,
  meta,
  leading,
  trailing,
  onPress,
  showChevron = true,
  destructive = false,
  style,
  accessibilityLabel,
  testID,
}: ListRowProps): React.JSX.Element {
  const theme = useTheme();

  const content = (
    <View
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        gap: theme.spacing.md,
        paddingVertical: theme.spacing.md,
        paddingHorizontal: theme.spacing.lg,
        minHeight: 60,
      }}
    >
      {leading ? <View>{leading}</View> : null}
      <View style={{ flex: 1, gap: 2 }}>
        <AppText variant="bodyStrong" color={destructive ? 'malicious' : 'primary'} numberOfLines={1}>
          {title}
        </AppText>
        {subtitle ? (
          <AppText variant="caption" color="secondary" numberOfLines={2}>
            {subtitle}
          </AppText>
        ) : null}
        {meta ? (
          <AppText variant="caption" color="tertiary" numberOfLines={1}>
            {meta}
          </AppText>
        ) : null}
      </View>
      {trailing ? <View>{trailing}</View> : null}
    </View>
  );

  if (!onPress) return <View style={style}>{content}</View>;

  return (
    <Pressable
      onPress={onPress}
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? title}
      android_ripple={{ color: theme.colors.overlay }}
      style={({ pressed }) => [pressed ? { backgroundColor: theme.colors.overlay } : null, style]}
    >
      {content}
    </Pressable>
  );
}
