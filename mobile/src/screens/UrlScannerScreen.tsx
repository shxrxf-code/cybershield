import React, { useMemo, useState } from 'react';
import { StyleSheet, TextInput, View } from 'react-native';
import { useTheme } from '../theme';
import { AlertBanner, AppText, Badge, Button, Card, KeyValue, Screen, SectionHeader } from '../components/ui';
import { CircleAlert, Info as InfoIcon, Link2, Search, ShieldCheck, TriangleAlert } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { parseWebUrl, type ParsedUrl } from '../utils/url';
import { capabilities } from '../capabilities';
import { scanUrl } from '../api';
import type { UrlScanResponse } from '../api/client';

interface LocalResult {
  parsed: ParsedUrl;
  checkedAt: string;
}

interface ReputationResult extends UrlScanResponse {
  source: 'backend';
}

/**
 * Checks a link. The local syntax analysis runs for real and offline; the
 * reputation lookup (Google Safe Browsing, URLhaus, VirusTotal) is a backend
 * feature that is connected when `capabilities.urlReputation` is true.
 */
export function UrlScannerScreen(): React.JSX.Element {
  const theme = useTheme();
  const styles = useMemo(
    () =>
      StyleSheet.create({
        root: { gap: theme.spacing.xl },
        searchContainer: {
          flexDirection: 'row',
          alignItems: 'center',
          gap: theme.spacing.sm,
          backgroundColor: theme.colors.sunken,
          borderRadius: theme.radius.md,
          borderWidth: 1,
          paddingHorizontal: theme.spacing.md,
          height: 48,
        },
        searchInput: { flex: 1, color: theme.colors.textPrimary, paddingVertical: 0 },
        errorRow: { flexDirection: 'row', gap: theme.spacing.sm, marginTop: theme.spacing.sm },
        flex1: { flex: 1 },
        actionRow: { flexDirection: 'row', gap: theme.spacing.md, marginTop: theme.spacing.lg },
        section: { padding: theme.spacing.lg, gap: theme.spacing.md },
        row: { flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm },
        divider: { height: 1, backgroundColor: theme.colors.border },
        details: { paddingHorizontal: theme.spacing.lg, paddingVertical: theme.spacing.sm },
        safetySection: { gap: theme.spacing.sm },
      }),
    [theme],
  );
  const navigation = useRootNavigation();

  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LocalResult | null>(null);
  const [reputation, setReputation] = useState<ReputationResult | null>(null);
  const [checking, setChecking] = useState(false);

  const onCheck = async () => {
    const parsed = parseWebUrl(value);
    if (!parsed.ok || !parsed.url) {
      setError(parsed.reason ?? 'That address could not be read.');
      setResult(null);
      setReputation(null);
      return;
    }
    setError(null);
    const localResult = { parsed: parsed.url, checkedAt: new Date().toISOString() };
    setResult(localResult);

    if (!capabilities.urlReputation) {
      return;
    }

    setChecking(true);
    setReputation(null);
    try {
      const apiResult = await scanUrl({ url: value });
      setReputation({ ...apiResult, source: 'backend' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Network error';
      setError(`Reputation check failed: ${message}`);
    } finally {
      setChecking(false);
    }
  };

  const onClear = () => {
    setValue('');
    setError(null);
    setResult(null);
  };

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={styles.root}>
        <View>
          <SectionHeader
            title="Check a link"
            subtitle="Paste an address to review it before you open it"
          />
          <View
            style={[
              styles.searchContainer,
              { borderColor: error ? theme.colors.malicious : theme.colors.border },
            ]}
          >
            <Link2 size={18} color={theme.colors.textTertiary} />
            <TextInput
              value={value}
              onChangeText={(text) => {
                setValue(text);
                if (error) setError(null);
              }}
              placeholder="example.com/login"
              placeholderTextColor={theme.colors.textTertiary}
              style={styles.searchInput}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
              inputMode="url"
              returnKeyType="go"
              onSubmitEditing={onCheck}
              accessibilityLabel="Web address to check"
            />
          </View>
          {error ? (
            <View style={styles.errorRow}>
              <CircleAlert size={16} color={theme.colors.malicious} />
              <AppText variant="caption" color="malicious" style={styles.flex1}>
                {error}
              </AppText>
            </View>
          ) : null}
          <View style={styles.actionRow}>
            <Button
              label="Check link"
              icon={<Search size={18} color={theme.colors.onAccent} />}
              disabled={value.trim().length === 0}
              onPress={onCheck}
            />
            {result || value.length > 0 ? (
              <Button label="Clear" variant="ghost" onPress={onClear} />
            ) : null}
          </View>
        </View>

        {result ? (
          <View>
            <SectionHeader title="Local analysis" subtitle="Runs on this device, no network" />
            <Card flush>
              <View style={styles.section}>
                <View style={styles.row}>
                  <ShieldCheck size={20} color={theme.colors.unknown} />
                  <AppText variant="bodyStrong">Address is well-formed</AppText>
                  <Badge label="Unverified" tone="unknown" size="sm" />
                </View>
                <AppText variant="caption" color="secondary">
                  The address parses correctly. That says nothing about whether it is safe — only a
                  reputation check can do that.
                </AppText>
              </View>
              <View style={styles.divider} />
              <View style={styles.details}>
                <KeyValue label="Host" value={result.parsed.host} mono selectable />
                <KeyValue label="Scheme" value={result.parsed.scheme} />
                {result.parsed.port ? (
                  <KeyValue label="Port" value={result.parsed.port} mono />
                ) : null}
                <KeyValue label="Path" value={result.parsed.path} mono selectable />
                {result.parsed.query ? (
                  <KeyValue label="Query" value={result.parsed.query} mono selectable />
                ) : null}
                <KeyValue label="Checked" value={new Date(result.checkedAt).toLocaleString()} />
              </View>
            </Card>

            {reputation ? (
              <View>
                <SectionHeader title="Reputation verdict" subtitle="From the ThreatGuard backend" />
                <Card flush tone={severityToneFromLevel(reputation.threatLevel)}>
                  <View style={styles.section}>
                    <View style={styles.row}>
                      {iconForLevel(reputation.threatLevel, theme)}
                      <AppText variant="bodyStrong">
                        {reputation.threatLevel === 'SAFE'
                          ? 'No threat found'
                          : reputation.threatLevel === 'UNKNOWN'
                            ? 'Unverified'
                            : `${reputation.threatLevel} threat`}
                      </AppText>
                      <Badge
                        label={reputation.threatLevel === 'SAFE' ? 'Safe' : reputation.threatLevel}
                        tone={toneForLevel(reputation.threatLevel)}
                        size="sm"
                      />
                    </View>
                    {reputation.detectionReason ? (
                      <AppText variant="body" color="secondary">{reputation.detectionReason}</AppText>
                    ) : null}
                    <View style={styles.divider} />
                    <View style={styles.details}>
                      <KeyValue label="Threat type" value={reputation.threatType ?? '—'} />
                      <KeyValue label="Scanned" value={new Date(reputation.scannedAt).toLocaleString()} />
                    </View>
                  </View>
                </Card>
              </View>
            ) : checking ? (
              <AlertBanner
                tone="info"
                icon={<InfoIcon size={20} color={theme.colors.info} />}
                title="Checking reputation…"
                message="The ThreatGuard backend is looking up this link with Safe Browsing, URLhaus and VirusTotal."
              />
            ) : capabilities.urlReputation ? (
              <AlertBanner
                tone="info"
                icon={<InfoIcon size={20} color={theme.colors.info} />}
                title="Run a check to get a reputation verdict"
                message={'Tap "Check link" to send the address to the ThreatGuard backend.'}
              />
            ) : null}
          </View>
        ) : null}

        {!capabilities.urlReputation ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="Reputation lookup not connected"
            message="Safe Browsing, URLhaus and VirusTotal lookups run through the backend, which this build does not talk to yet. Until then, no verdict is shown for a link — never assume an unchecked link is safe."
          />
        ) : null}

        <Card>
          <View style={styles.safetySection}>
            <AppText variant="subheading">Staying safe with links</AppText>
            <AppText variant="body" color="secondary">
              Check the host carefully before you tap. A well-known name can be hidden inside a
              longer address, and unexpected urgency — a payment, a locked account — is a common
              sign of a scam.
            </AppText>
            <Button
              label="Learn about link safety"
              variant="ghost"
              onPress={() => navigation.navigate('About')}
            />
          </View>
        </Card>
      </View>
    </Screen>
  );
}

function toneForLevel(level: string): 'safe' | 'suspicious' | 'malicious' | 'unknown' {
  switch (level) {
    case 'SAFE':
      return 'safe';
    case 'MALICIOUS':
      return 'malicious';
    case 'SUSPICIOUS':
      return 'suspicious';
    default:
      return 'unknown';
  }
}

function severityToneFromLevel(level: string): 'safe' | 'suspicious' | 'malicious' | 'unknown' | 'info' {
  switch (level) {
    case 'SAFE':
      return 'safe';
    case 'MALICIOUS':
      return 'malicious';
    case 'SUSPICIOUS':
      return 'suspicious';
    default:
      return 'info';
  }
}

function iconForLevel(level: string, theme: ReturnType<typeof useTheme>): React.ReactNode {
  switch (level) {
    case 'SAFE':
      return <ShieldCheck size={20} color={theme.colors.safe} />;
    case 'MALICIOUS':
      return <TriangleAlert size={20} color={theme.colors.malicious} />;
    case 'SUSPICIOUS':
      return <TriangleAlert size={20} color={theme.colors.suspicious} />;
    default:
      return <ShieldCheck size={20} color={theme.colors.unknown} />;
  }
}
