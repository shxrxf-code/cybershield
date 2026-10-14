import React from 'react';
import { Linking, View } from 'react-native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Badge,
  Button,
  Card,
  Divider,
  Screen,
  SectionHeader,
} from '../components/ui';
import {
  BatteryCharging,
  Bell,
  BellRing,
  ExternalLink,
  FileText,
  Globe,
  Info as InfoIcon,
  Package,
  ShieldCheck,
} from 'lucide-react-native';
import { capabilities } from '../capabilities';
import type { ThreatTone } from '../theme/theme';

interface PermissionEntry {
  id: string;
  title: string;
  why: string;
  ifDenied: string;
  icon: React.ReactNode;
  /** What the OS state is, described truthfully for this build. */
  status: string;
  statusTone: ThreatTone;
}

/**
 * A truthful catalogue of the access ThreatGuard will ask for. None of the
 * special permissions are requested in this build, so each row says exactly
 * that rather than inventing a granted/denied state we cannot check yet.
 */
export function PermissionsScreen(): React.JSX.Element {
  const theme = useTheme();

  const entries: PermissionEntry[] = [
    {
      id: 'internet',
      title: 'Internet',
      why: 'Send a link or file fingerprint to the reputation service and receive a verdict.',
      ifDenied: 'Checks can still run on-device, but reputation results are unavailable.',
      icon: <Globe size={20} color={theme.colors.textSecondary} />,
      status: 'Granted automatically',
      statusTone: 'safe',
    },
    {
      id: 'notifications',
      title: 'Post notifications',
      why: 'Raise a system alert the moment a threat is detected.',
      ifDenied: 'Threats still appear inside the app, but you will not be alerted in the background.',
      icon: <Bell size={20} color={theme.colors.textSecondary} />,
      status: capabilities.notificationListener ? 'Requested at first use' : 'Not requested yet',
      statusTone: 'unknown',
    },
    {
      id: 'notification-access',
      title: 'Notification access (special)',
      why: 'Read the notification content Android exposes so suspicious messages can be flagged.',
      ifDenied: 'Message monitoring cannot work at all. Everything else still works.',
      icon: <BellRing size={20} color={theme.colors.textSecondary} />,
      status: capabilities.notificationListener ? 'Managed in Android settings' : 'Not requested yet',
      statusTone: 'unknown',
    },
    {
      id: 'media',
      title: 'Files and media',
      why: 'Read the documents, images and downloads you choose to have scanned.',
      ifDenied: 'You can still scan files; access is granted one document at a time by the system picker.',
      icon: <FileText size={20} color={theme.colors.textSecondary} />,
      status: capabilities.fileScan ? 'Not required — you pick each file' : 'Not requested yet',
      statusTone: capabilities.fileScan ? 'safe' : 'unknown',
    },
    {
      id: 'packages',
      title: 'Installed apps',
      why: 'List installed packages to review permissions and signatures.',
      ifDenied: 'App inspection cannot run and shows no apps.',
      icon: <Package size={20} color={theme.colors.textSecondary} />,
      status: capabilities.appScan ? 'Requested when you scan' : 'Not requested yet',
      statusTone: 'unknown',
    },
    {
      id: 'battery',
      title: 'Ignore battery optimisation',
      why: 'Let scheduled background checks run reliably instead of being deferred by Android.',
      ifDenied: 'Background protection may run late or be skipped when the device is idle.',
      icon: <BatteryCharging size={20} color={theme.colors.textSecondary} />,
      status: capabilities.deviceScan ? 'Offered in Settings' : 'Not requested yet',
      statusTone: 'unknown',
    },
  ];

  const openSettings = () => {
    void Linking.openSettings();
  };

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <AlertBanner
          tone="info"
          icon={<InfoIcon size={20} color={theme.colors.info} />}
          title="Nothing is requested without a reason"
          message="File scanning uses the system picker, so it needs no storage permission at all. Installed-app inspection and message monitoring are not available in this build, so Internet access — used only for the optional hash reputation lookup — is the only permission that currently applies."
        />

        <View>
          <SectionHeader title="Access ThreatGuard will ask for" />
          <Card flush>
            {entries.map((entry, index) => (
              <View key={entry.id}>
                {index > 0 ? <Divider /> : null}
                <View style={{ padding: theme.spacing.lg, gap: theme.spacing.sm }}>
                  <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.md }}>
                    {entry.icon}
                    <AppText variant="bodyStrong" style={{ flex: 1 }}>
                      {entry.title}
                    </AppText>
                    <Badge label={entry.status} tone={entry.statusTone} size="sm" />
                  </View>
                  <AppText variant="caption" color="secondary">
                    {entry.why}
                  </AppText>
                  <AppText variant="caption" color="tertiary">
                    If denied: {entry.ifDenied}
                  </AppText>
                </View>
              </View>
            ))}
          </Card>
        </View>

        <Card>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              <ShieldCheck size={20} color={theme.colors.safe} />
              <AppText variant="subheading">What we never do</AppText>
            </View>
            <AppText variant="body" color="secondary">
              ThreatGuard does not read other apps’ private data, bypass the Android sandbox,
              intercept encrypted traffic, capture keystrokes, or run a hidden surveillance service.
            </AppText>
          </View>
        </Card>

        <Button
          label="Open Android app settings"
          variant="secondary"
          icon={<ExternalLink size={18} color={theme.colors.accent} />}
          fullWidth
          onPress={openSettings}
          accessibilityHint="Opens this app's page in Android settings"
        />
      </View>
    </Screen>
  );
}
