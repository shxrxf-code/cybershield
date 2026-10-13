import React, { useMemo, useState } from 'react';
import { View } from 'react-native';
import { useTheme } from '../theme';
import { AppText, Button, Card, Screen } from '../components/ui';
import { BellRing, Lock, ShieldCheck, TriangleAlert } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useSettingsStore } from '../store';
import { APP_NAME, PRIVACY_COMMITMENTS } from '../config';

const STEP_COUNT = 3;

/**
 * First-run introduction. Three short steps that explain what the app does, how
 * it treats the user's data, and how protection gets switched on. Finishing —
 * or skipping — records the choice and enters the main app.
 */
export function OnboardingScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const completeOnboarding = useSettingsStore((s) => s.completeOnboarding);
  const [step, setStep] = useState(0);

  const finish = () => {
    completeOnboarding();
    navigation.replace('MainTabs');
  };

  const dots = useMemo(
    () =>
      Array.from({ length: STEP_COUNT }, (_, index) => (
        <View
          key={index}
          style={{
            width: index === step ? 22 : 8,
            height: 8,
            borderRadius: 4,
            backgroundColor: index === step ? theme.colors.accent : theme.colors.borderStrong,
          }}
        />
      )),
    [step, theme],
  );

  return (
    <Screen edges={['top', 'bottom', 'left', 'right']}>
      <View style={{ flex: 1, justifyContent: 'space-between' }}>
        <View style={{ flex: 1, justifyContent: 'center', gap: theme.spacing.xl }}>
          {step === 0 ? (
            <View style={{ alignItems: 'center', gap: theme.spacing.md }}>
              <ShieldCheck size={72} color={theme.colors.accent} />
              <AppText variant="display" align="center">
                {APP_NAME}
              </AppText>
              <AppText variant="body" color="secondary" align="center">
                Check links, files and apps before they can harm your phone — with analysis that
                keeps your data on your device.
              </AppText>
            </View>
          ) : null}

          {step === 1 ? (
            <View style={{ gap: theme.spacing.lg }}>
              <View style={{ alignItems: 'center', gap: theme.spacing.sm }}>
                <Lock size={48} color={theme.colors.accent} />
                <AppText variant="title" align="center">
                  Your data stays yours
                </AppText>
              </View>
              <Card flush>
                {PRIVACY_COMMITMENTS.map((commitment, index) => (
                  <View
                    key={commitment}
                    style={{
                      padding: theme.spacing.lg,
                      borderTopWidth: index === 0 ? 0 : 1,
                      borderTopColor: theme.colors.border,
                    }}
                  >
                    <AppText variant="body" color="secondary">
                      {commitment}
                    </AppText>
                  </View>
                ))}
              </Card>
            </View>
          ) : null}

          {step === 2 ? (
            <View style={{ gap: theme.spacing.lg }}>
              <View style={{ alignItems: 'center', gap: theme.spacing.sm }}>
                <BellRing size={48} color={theme.colors.accent} />
                <AppText variant="title" align="center">
                  You are in control
                </AppText>
              </View>
              <AppText variant="body" color="secondary" align="center">
                Protection features switch on as you grant access. You can review or change every
                permission later in Settings.
              </AppText>
              <Card tone="suspicious">
                <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
                  <TriangleAlert size={20} color={theme.colors.suspicious} />
                  <View style={{ flex: 1 }}>
                    <AppText variant="bodyStrong">This is an early build</AppText>
                    <AppText variant="caption" color="secondary">
                      On-device scanning and message monitoring arrive in later phases. Nothing is
                      scanned until those engines are present.
                    </AppText>
                  </View>
                </View>
              </Card>
            </View>
          ) : null}
        </View>

        <View style={{ gap: theme.spacing.lg }}>
          <View style={{ flexDirection: 'row', justifyContent: 'center', gap: theme.spacing.xs }}>
            {dots}
          </View>
          <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
            {step > 0 ? (
              <Button label="Back" variant="secondary" onPress={() => setStep((s) => s - 1)} />
            ) : (
              <Button label="Skip" variant="ghost" onPress={finish} />
            )}
            <View style={{ flex: 1 }}>
              {step < STEP_COUNT - 1 ? (
                <Button label="Continue" fullWidth onPress={() => setStep((s) => s + 1)} />
              ) : (
                <Button label="Get started" fullWidth onPress={finish} />
              )}
            </View>
          </View>
        </View>
      </View>
    </Screen>
  );
}
