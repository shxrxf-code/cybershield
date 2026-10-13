import React from 'react';
import { View } from 'react-native';
import { useTheme } from '../theme';
import { AppText, Card, Divider, KeyValue, Screen, SectionHeader } from '../components/ui';
import { Info, Lock, Package, ShieldCheck } from 'lucide-react-native';
import { APP_BUILD, APP_NAME, APP_PACKAGE, APP_VERSION, OPEN_SOURCE, PRIVACY_COMMITMENTS } from '../config';

/**
 * Project and privacy information. Everything here is static metadata about the
 * build — no runtime data and no external links that could be substituted.
 */
export function AboutScreen(): React.JSX.Element {
  const theme = useTheme();

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <View style={{ alignItems: 'center', gap: theme.spacing.sm }}>
          <ShieldCheck size={56} color={theme.colors.accent} />
          <AppText variant="title" align="center">
            {APP_NAME}
          </AppText>
          <AppText variant="caption" color="secondary" align="center">
            An Android threat-detection project
          </AppText>
        </View>

        <Card flush>
          <View style={{ paddingHorizontal: theme.spacing.lg, paddingVertical: theme.spacing.sm }}>
            <KeyValue label="Version" value={APP_VERSION} />
            <KeyValue label="Build" value={APP_BUILD} />
            <KeyValue label="Package" value={APP_PACKAGE} mono />
          </View>
        </Card>

        <View>
          <SectionHeader title="What it does" />
          <Card>
            <AppText variant="body" color="secondary">
              ThreatGuard helps you check links, files and the messages you receive, then explains
              what it found and what to do next. Detection combines on-device analysis with vetted
              online reputation services, and it never claims a link or file is safe unless a real
              source confirmed it.
            </AppText>
          </Card>
        </View>

        <View>
          <SectionHeader title="Privacy commitments" />
          <Card flush>
            {PRIVACY_COMMITMENTS.map((commitment, index) => (
              <View
                key={commitment}
                style={{
                  flexDirection: 'row',
                  gap: theme.spacing.md,
                  padding: theme.spacing.lg,
                  borderTopWidth: index === 0 ? 0 : 1,
                  borderTopColor: theme.colors.border,
                }}
              >
                <Lock size={18} color={theme.colors.textSecondary} />
                <AppText variant="body" color="secondary" style={{ flex: 1 }}>
                  {commitment}
                </AppText>
              </View>
            ))}
          </Card>
        </View>

        <View>
          <SectionHeader title="Open-source components" />
          <Card flush>
            {OPEN_SOURCE.map((item, index) => (
              <View key={item.name}>
                {index > 0 ? <Divider /> : null}
                <View
                  style={{
                    flexDirection: 'row',
                    alignItems: 'center',
                    gap: theme.spacing.md,
                    paddingVertical: theme.spacing.md,
                    paddingHorizontal: theme.spacing.lg,
                  }}
                >
                  <Package size={18} color={theme.colors.textTertiary} />
                  <AppText variant="body" style={{ flex: 1 }}>
                    {item.name}
                  </AppText>
                  <AppText variant="caption" color="tertiary">
                    {item.licence}
                  </AppText>
                </View>
              </View>
            ))}
          </Card>
        </View>

        <Card>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              <Info size={18} color={theme.colors.textSecondary} />
              <AppText variant="subheading">Known limitations</AppText>
            </View>
            <AppText variant="body" color="secondary">
              This is an early build. On-device scanning, file inspection and message monitoring are
              added in later phases; until they are present, the matching screens say so rather than
              producing a result. Because Android protects app storage and encrypted traffic,
              ThreatGuard only ever inspects what the system legitimately exposes.
            </AppText>
          </View>
        </Card>

        <View
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'center',
            gap: theme.spacing.xs,
          }}
        >
          <ShieldCheck size={16} color={theme.colors.textTertiary} />
          <AppText variant="caption" color="tertiary">
            A final-year cybersecurity project
          </AppText>
        </View>
      </View>
    </Screen>
  );
}
