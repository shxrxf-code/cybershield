import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/app_platform.dart';
import '../apps/apps_screen.dart';
import '../auth/sign_in_sheet.dart';
import '../intel/intel_screen.dart';
import '../quarantine/quarantine_screen.dart';

/// Protection & Permissions centre ("Security" destination).
///
/// Everything shown here corresponds to a real capability or a real OS rule:
/// each row reports whether the platform allows it, whether this build has
/// wired it, and why. Nothing is claimed that is not true.
class SecurityScreen extends StatelessWidget {
  const SecurityScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final session = AppScope.of(context);
    final caps = capabilitiesFor();
    final modulesOk = session.isAuthenticated;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Security'),
        actions: [
          IconButton(
            tooltip: 'Sign in / out',
            icon: const Icon(Icons.account_circle_outlined),
            onPressed: modulesOk
                ? null
                : () => showSignInSheet(context),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _sectionHeader(context, 'Protection status'),
          _protectionCard(context, caps, session),
          const SizedBox(height: 20),
          _sectionHeader(context, 'Protection modules'),
          _moduleList(context, modulesOk),
          const SizedBox(height: 20),
          _sectionHeader(context, 'Permissions & capabilities'),
          _capabilityList(context, caps, scheme),
          const SizedBox(height: 20),
          _sectionHeader(context, 'Battery & background'),
          _batteryCard(context),
          const SizedBox(height: 20),
          _sectionHeader(context, 'Other sections'),
          _secondarySections(context),
          const SizedBox(height: 8),
          _honestyNote(context),
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  Widget _sectionHeader(BuildContext context, String title) => Padding(
        padding: const EdgeInsets.only(left: 2, bottom: 10),
        child: Text(
          title,
          style: Theme.of(context)
              .textTheme
              .titleMedium
              ?.copyWith(fontWeight: FontWeight.w800, letterSpacing: 0.2),
        ),
      );

  Widget _protectionCard(
      BuildContext context, AppCapabilities caps, dynamic session) {
    final scheme = Theme.of(context).colorScheme;
    final signedIn = session.isAuthenticated;
    final title = signedIn ? 'Static analysis ready' : 'Sign in to activate';
    final subtitle = signedIn
        ? 'Demand-driven scanning is available on ${caps.platform.label}. '
            'Nothing runs, monitors or uploads in the background.'
        : 'Scans are stored per account. Sign in once to enable scanning.';
    final color = signedIn ? const Color(0xFF38D6F5) : scheme.outline;
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(18),
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF081226), Color(0xFF0E2A5C)],
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 54,
            height: 54,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: color.withValues(alpha: 0.2),
              border: Border.all(color: color.withValues(alpha: 0.6)),
            ),
            child: Icon(Icons.security_rounded, color: color, size: 28),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: Theme.of(context)
                      .textTheme
                      .titleMedium
                      ?.copyWith(
                          color: Colors.white, fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 3),
                Text(
                  subtitle,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: Colors.white.withValues(alpha: 0.72)),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _moduleList(BuildContext context, bool modulesOk) {
    final entries = [
      (Icons.description_rounded, 'File protection', 'Static file scanning'),
      (Icons.link_rounded, 'URL protection', 'Link & download analysis'),
      (Icons.phone_android_rounded, 'APK protection', 'Android package analysis'),
      (Icons.email_rounded, 'Phishing / email protection', 'Email & text analysis'),
    ];
    return Card(
      child: Column(
        children: entries.map((e) {
          final ok = modulesOk;
          return ListTile(
            leading: Icon(e.$1, color: Theme.of(context).colorScheme.primary),
            title: Text(e.$2,
                style: const TextStyle(fontWeight: FontWeight.w600)),
            subtitle: Text(e.$3),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: (ok ? const Color(0xFF2FA84F) : const Color(0xFFE8A33D))
                        .withValues(alpha: 0.14),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Text(
                    ok ? 'Ready' : 'Sign in',
                    style: TextStyle(
                      color: ok ? const Color(0xFF2FA84F) : const Color(0xFFE8A33D),
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ],
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _capabilityList(BuildContext context, AppCapabilities caps,
      ColorScheme scheme) {
    final items = caps.permissionSummary();
    return Card(
      child: Column(
        children: items.map((c) {
          final (label, color) = switch ((c.available, c.enabled)) {
            (true, true) => ('Active', const Color(0xFF2FA84F)),
            (true, false) => ('Not enabled', const Color(0xFFE8A33D)),
            (false, _) => ('Not supported here', scheme.outline),
          };
          return ListTile(
            leading: Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.14),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(
                _iconFor(c.id),
                size: 19,
                color: color,
              ),
            ),
            title: Text(c.title,
                style: const TextStyle(fontWeight: FontWeight.w600)),
            subtitle: Text(c.purpose, maxLines: 3, overflow: TextOverflow.ellipsis),
            trailing: Wrap(
              spacing: 4,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.14),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Text(
                    label,
                    style: TextStyle(
                      color: color,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ],
            ),
            onTap: () => _showCapabilitySheet(context, c),
          );
        }).toList(),
      ),
    );
  }

  IconData _iconFor(String id) => switch (id) {
        'storage' => Icons.folder_rounded,
        'file_scan' => Icons.search_rounded,
        'background' => Icons.bolt_rounded,
        'startup' => Icons.power_settings_new_rounded,
        'network' => Icons.wifi_rounded,
        'notifications' => Icons.notifications_outlined,
        _ => Icons.info_outline_rounded,
      };

  void _showCapabilitySheet(BuildContext context, Capability capability) {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                capability.title,
                style: Theme.of(context)
                    .textTheme
                    .titleMedium
                    ?.copyWith(fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 8),
              Text(
                'Purpose: ${capability.purpose}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: capability.isActive
                      ? const Color(0xFF2FA84F).withValues(alpha: 0.12)
                      : Theme.of(context)
                          .colorScheme
                          .surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  capability.isActive
                      ? 'Active on this build.'
                      : capability.note ??
                          'Not available on this platform/build. CyberShield '
                              'does not claim it.',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _batteryCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Battery saver protection',
              style: Theme.of(context)
                  .textTheme
                  .titleSmall
                  ?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            _batteryRow(context, 'On-demand scanning',
                'Scans run only when you start them — never in a loop.', true),
            _batteryRow(context, 'Incremental rescanning',
                'Re-scans skip unchanged files via a local SHA-256 + size + '
                'mtime cache.',
                true),
            _batteryRow(context, 'Background monitoring',
                'Not enabled in this build (OS-gated and not wired).', false),
            _batteryRow(context, 'Scheduled scans',
                'Not enabled in this build.', false),
            const SizedBox(height: 6),
            Text(
              'Battery-saver mode keeps the above behaviour; any future '
              'background work will pause non-critical scheduled scans on '
              'low battery while never stopping scans you start yourself.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }

  Widget _batteryRow(
      BuildContext context, String title, String subtitle, bool enabled) {
    final scheme = Theme.of(context).colorScheme;
    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      leading: Icon(
        enabled ? Icons.check_circle_rounded : Icons.remove_circle_outline_rounded,
        color:
            enabled ? const Color(0xFF2FA84F) : scheme.onSurfaceVariant,
      ),
      title: Text(title),
      subtitle: Text(subtitle),
    );
  }

  Widget _secondarySections(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final items = [
      (Icons.history_rounded, 'Quarantine',
          'Flagged copies stored on the server',
          () => Navigator.of(context).push(MaterialPageRoute<void>(
              builder: (_) => const QuarantineScreen()))),
      (Icons.travel_explore_rounded, 'Threat Intel',
          'Third-party reputation reports',
          () => Navigator.of(context).push(MaterialPageRoute<void>(
              builder: (_) => const IntelScreen()))),
      (Icons.apps_rounded, 'Installed apps',
          'Package-manager metadata (Android)',
          () => Navigator.of(context).push(MaterialPageRoute<void>(
              builder: (_) => const AppsScreen()))),
    ];
    return Card(
      child: Column(
        children: items
            .map((e) => ListTile(
                  leading:
                      Icon(e.$1, color: scheme.primary),
                  title: Text(e.$2,
                      style: const TextStyle(fontWeight: FontWeight.w600)),
                  subtitle: Text(e.$3),
                  trailing: const Icon(Icons.chevron_right_rounded),
                  onTap: e.$4,
                ))
            .toList(),
      ),
    );
  }

  Widget _honestyNote(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.info_outline_rounded, size: 18, color: scheme.primary),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                'Honest by design: CyberShield never claims access it does '
                'not have. Background, startup, network and OS-notification '
                'protection are gated by the operating system and are not '
                'wired in this build — the app says exactly that above.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ),
          ],
        ),
      ),
    );
  }
}