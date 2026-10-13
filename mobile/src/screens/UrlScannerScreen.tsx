import React, { useState } from 'react';
import { TextInput, View } from 'react-native';
import { useTheme } from '../theme';
import { AlertBanner, AppText, Badge, Button, Card, KeyValue, Screen, SectionHeader } from '../components/ui';
import { CircleAlert, Info as InfoIcon, Link2, Search, ShieldCheck } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { parseWebUrl, type ParsedUrl } from '../utils/url';
import { capabilities } from '../capabilities';

interface LocalResult {
  parsed: ParsedUrl;
  checkedAt: string;
}

/**
 * Checks a link. The local syntax analysis runs for real and offline; the
 * reputation lookup (Google Safe Browsing, URLhaus, VirusTotal) is a backend
 * feature that is not connected in this build, so no verdict is invented.
 */
export function UrlScannerScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();

  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LocalResult | null>(null);

  const onCheck = () => {
    const parsed = parseWebUrl(value);
    if (!parsed.ok || !parsed.url) {
      setError(parsed.reason ?? 'That address could not be read.');
      setResult(null);
      return;
    }
    setError(null);
    setResult({ parsed: parsed.url, checkedAt: new Date().toISOString() });
  };

  const onClear = () => {
    setValue('');
    setError(null);
    setResult(null);
  };

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <View>
          <SectionHeader
            title="Check a link"
            subtitle="Paste an address to review it before you open it"
          />
          <View
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              gap: theme.spacing.sm,
              backgroundColor: theme.colors.sunken,
              borderRadius: theme.radius.md,
              borderWidth: 1,
              borderColor: error ? theme.colors.malicious : theme.colors.border,
              paddingHorizontal: theme.spacing.md,
              height: 48,
            }}
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
              style={{ flex: 1, color: theme.colors.textPrimary, paddingVertical: 0 }}
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
            <View style={{ flexDirection: 'row', gap: theme.spacing.sm, marginTop: theme.spacing.sm }}>
              <CircleAlert size={16} color={theme.colors.malicious} />
              <AppText variant="caption" color="malicious" style={{ flex: 1 }}>
                {error}
              </AppText>
            </View>
          ) : null}
          <View style={{ flexDirection: 'row', gap: theme.spacing.md, marginTop: theme.spacing.lg }}>
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
              <View style={{ padding: theme.spacing.lg, gap: theme.spacing.md }}>
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
                  <ShieldCheck size={20} color={theme.colors.unknown} />
                  <AppText variant="bodyStrong">Address is well-formed</AppText>
                  <Badge label="Unverified" tone="unknown" size="sm" />
                </View>
                <AppText variant="caption" color="secondary">
                  The address parses correctly. That says nothing about whether it is safe — only a
                  reputation check can do that.
                </AppText>
              </View>
              <View style={{ height: 1, backgroundColor: theme.colors.border }} />
              <View style={{ paddingHorizontal: theme.spacing.lg, paddingVertical: theme.spacing.sm }}>
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
          <View style={{ gap: theme.spacing.sm }}>
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
