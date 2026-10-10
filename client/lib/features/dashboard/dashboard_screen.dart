import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/app_errors.dart';
import '../../core/models/dashboard.dart';
import '../../core/models/enums.dart';
import '../../core/models/scan.dart';
import '../../core/protection_status.dart';
import '../../widgets/app_error.dart';
import '../../widgets/error_view.dart';
import '../../widgets/scan_shield_animation.dart';
import '../../widgets/verdict_style.dart';
import '../auth/sign_in_sheet.dart';
import '../fullscan/full_scan_screen.dart';
import '../history/history_screen.dart';
import '../scan/scan_hub_screen.dart';

/// Home — the mobile-first landing page.
///
/// Drive-by honesty rules:
/// - The hero status comes from [protectionState], which derives ONLY from
///   real inputs (session, engine reachability, actual verdict counts).
/// - "Scan now" opens the full-device scan; the app never claims to protect
///   anything it did not scan.
/// - No scans yet => an explicit "No scans yet" state, not a fake "no
///   threats detected".
class DashboardScreen extends StatefulWidget {
  const DashboardScreen({
    super.key,
    required this.onOpenScan,
    this.onOpenHistory,
  });

  /// Switches the shell to a scan-hub tab (file, url…).
  final ValueChanged<int> onOpenScan;

  /// Switches the shell to the History section (optional; falls back to a
  /// pushed route when absent).
  final VoidCallback? onOpenHistory;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  DashboardStats? _stats;
  List<ScanSummary>? _recent;
  ApiException? _errorEx;
  bool _loading = true;
  bool _initialLoadDone = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final session = AppScope.of(context);
    if (!_initialLoadDone) {
      _initialLoadDone = true;
      _loadAll();
      return;
    }
    if (!session.isAuthenticated) {
      // Signed out (or the session expired): drop the previous account's data
      // so the Home page shows a clean sign-in prompt, never stale numbers.
      if (_stats != null || _errorEx != null || _recent != null) {
        setState(() {
          _stats = null;
          _recent = null;
          _errorEx = null;
        });
      }
    } else if (!_loading && _stats == null && _errorEx == null) {
      // Freshly signed in from the first-run prompt: load the numbers now
      // that a session exists.
      _loadAll();
    }
  }

  Future<void> _loadAll() async {
    await Future.wait([_load(), _loadRecent()]);
  }

  Future<void> _load() async {
    final session = AppScope.of(context);
    setState(() {
      _loading = true;
      _errorEx = null;
    });
    try {
      final data = await session.api.getJson('/api/v1/dashboard');
      if (!mounted) return;
      setState(() {
        _stats = DashboardStats.fromJson(
            Map<String, dynamic>.from(data as Map));
        _loading = false;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorEx = e;
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _errorEx = ApiException(
          code: 'unexpected',
          message: 'Could not load the security centre.',
          statusCode: 0,
        );
        _loading = false;
      });
    }
  }

  Future<void> _loadRecent() async {
    final session = AppScope.of(context);
    if (!session.isAuthenticated) return;
    try {
      final data = await session.api.getJson('/api/v1/scans', query: {
        'page_size': '5',
        'page_number': '1',
      });
      if (!mounted || !session.isAuthenticated) return;
      setState(() {
        _recent = ScansPage.fromJson(Map<String, dynamic>.from(data as Map))
            .items;
      });
    } on ApiException {
      // Recent activity is secondary; a failure here must not obscure the
      // main status. Leave _recent null — the section falls back quietly.
    } catch (_) {
      // ignored (secondary section)
    }
  }

  void _openHistory() {
    if (widget.onOpenHistory != null) {
      widget.onOpenHistory!();
    } else {
      Navigator.of(context).push(
        MaterialPageRoute<void>(builder: (_) => const HistoryScreen()),
      );
    }
  }

  void _startFullScan() {
    Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => const FullScanScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final session = AppScope.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('CyberShield'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loading ? null : _loadAll,
          ),
          if (session.user != null)
            IconButton(
              tooltip: session.user!.email,
              icon: const Icon(Icons.account_circle_outlined),
              onPressed: () {},
            ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _loadAll,
        child: _buildBody(),
      ),
    );
  }

  Widget _buildBody() {
    if (_loading && _stats == null) {
      return const LoadingView(label: 'Loading security centre…');
    }
    final session = AppScope.of(context);
    final signedIn = session.isAuthenticated;
    final stats = _stats ?? const DashboardStats();
    final error =
        _errorEx == null ? null : friendlyAppError(_errorEx!, signedIn: signedIn);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        if (!signedIn) ...[
          SignInPromptCard(onSignIn: () => showSignInSheet(context)),
          const SizedBox(height: 16),
        ],
        if (signedIn && error != null) ...[
          AppErrorBanner(
            message: error,
            onRetry: _loadAll,
          ),
          const SizedBox(height: 14),
        ],
        _protectionHero(stats, signedIn),
        const SizedBox(height: 20),
        _sectionHeader(context, 'Protection modules'),
        _moduleGrid(context, signedIn),
        const SizedBox(height: 20),
        _sectionHeader(context, 'Scan activity'),
        _recentCard(signedIn),
        if (signedIn && (stats.totalScans > 0 || stats.verdictTotal > 0)) ...[
          const SizedBox(height: 20),
          _sectionHeader(context, 'Threat summary'),
          _summaryCard(stats),
        ],
        const SizedBox(height: 20),
        _honestyNote(context),
        const SizedBox(height: 24),
      ],
    );
  }

  // -------------------------------------------------------------------
  // Hero
  // -------------------------------------------------------------------

  Widget _protectionHero(DashboardStats stats, bool signedIn) {
    final cyan = const Color(0xFF38D6F5);
    final state = protectionState(
      booting: false,
      signedIn: signedIn,
      offline: _errorEx != null && isOfflineError(_errorEx!),
      engineReady: _stats != null,
      scanning: false,
      stats: _stats,
    );
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF081226), Color(0xFF0E2A5C)],
        ),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF000000).withValues(alpha: 0.35),
            blurRadius: 18,
            offset: const Offset(0, 6),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              ScanShieldAnimation(
                size: 64,
                color: state.color,
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _statusChip(state),
                    const SizedBox(height: 8),
                    Text(
                      state.title,
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            color: Colors.white,
                            fontWeight: FontWeight.w800,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      state.subtitle,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Colors.white.withValues(alpha: 0.74),
                          ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          FilledButton.icon(
            onPressed: signedIn ? _startFullScan : () => showSignInSheet(context),
            style: FilledButton.styleFrom(
              minimumSize: const Size.fromHeight(52),
              backgroundColor: cyan,
              foregroundColor: const Color(0xFF00252E),
            ),
            icon: const Icon(Icons.shield_rounded),
            label: const Text('Scan now'),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: signedIn
                      ? () => widget.onOpenScan(ScanTab.file)
                      : () => showSignInSheet(context),
                  style: OutlinedButton.styleFrom(
                    minimumSize: const Size(0, 46),
                    foregroundColor: Colors.white,
                    side: BorderSide(
                        color: Colors.white.withValues(alpha: 0.5)),
                  ),
                  icon: const Icon(Icons.description_outlined, size: 18),
                  label: const Text('Scan a file'),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: signedIn
                      ? () => widget.onOpenScan(ScanTab.url)
                      : () => showSignInSheet(context),
                  style: OutlinedButton.styleFrom(
                    minimumSize: const Size(0, 46),
                    foregroundColor: Colors.white,
                    side: BorderSide(
                        color: Colors.white.withValues(alpha: 0.5)),
                  ),
                  icon: const Icon(Icons.link_rounded, size: 18),
                  label: const Text('Scan a URL'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _statusChip(ProtectionState state) {
    return Align(
      alignment: Alignment.centerLeft,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: state.color.withValues(alpha: 0.18),
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: state.color.withValues(alpha: 0.7)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(state.icon, size: 15, color: state.color),
            const SizedBox(width: 6),
            Text(
              _statusShortLabel(state.status),
              style: TextStyle(
                color: state.color,
                fontSize: 11,
                fontWeight: FontWeight.w800,
                letterSpacing: 0.6,
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _statusShortLabel(ProtectionStatus status) => switch (status) {
        ProtectionStatus.protected => 'PROTECTED',
        ProtectionStatus.warning => 'WARNING',
        ProtectionStatus.atRisk => 'AT RISK',
        ProtectionStatus.scanning => 'SCANNING',
        ProtectionStatus.actionRequired => 'ACTION REQUIRED',
        ProtectionStatus.offline => 'OFFLINE',
        ProtectionStatus.initializing => 'INITIALIZING',
      };

  // -------------------------------------------------------------------
  // Modules
  // -------------------------------------------------------------------

  Widget _moduleGrid(BuildContext context, bool modulesOk) {
    final modules = [
      (
        Icons.description_rounded,
        'File protection',
        'Static analysis of picked files',
        modulesOk,
      ),
      (
        Icons.link_rounded,
        'URL protection',
        'Link & download analysis',
        modulesOk,
      ),
      (
        Icons.phone_android_rounded,
        'APK protection',
        'Android package analysis',
        modulesOk,
      ),
      (
        Icons.email_rounded,
        'Phishing / email',
        'Email & text analysis',
        modulesOk,
      ),
    ];
    final tiles = modules
        .map((m) => _moduleTile(context, m.$1, m.$2, m.$3, m.$4))
        .toList(growable: false);

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth >= 600) {
          return Wrap(
            spacing: 12,
            runSpacing: 12,
            children: tiles
                .map((c) => SizedBox(
                    width: (constraints.maxWidth - 12) / 2, child: c))
                .toList(),
          );
        }
        return Column(
          children: [
            for (var i = 0; i < tiles.length; i++) ...[
              tiles[i],
              if (i != tiles.length - 1) const SizedBox(height: 12),
            ],
          ],
        );
      },
    );
  }

  Widget _moduleTile(BuildContext context, IconData icon, String title,
      String purpose, bool ready) {
    final scheme = Theme.of(context).colorScheme;
    final okColor = ready ? const Color(0xFF2FA84F) : const Color(0xFFE8A33D);
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: scheme.primary.withValues(alpha: 0.14),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(icon, size: 21, color: scheme.primary),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title,
                      style: const TextStyle(fontWeight: FontWeight.w700)),
                  const SizedBox(height: 2),
                  Text(purpose,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context)
                          .textTheme
                          .labelSmall
                          ?.copyWith(color: scheme.onSurfaceVariant)),
                ],
              ),
            ),
            const SizedBox(width: 8),
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: okColor.withValues(alpha: 0.14),
                borderRadius: BorderRadius.circular(999),
              ),
              child: Text(
                ready ? 'Ready' : 'Sign in',
                style: TextStyle(
                  color: okColor,
                  fontSize: 11,
                  fontWeight: FontWeight.w800,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // -------------------------------------------------------------------
  // Recent activity
  // -------------------------------------------------------------------

  Widget _recentCard(bool signedIn) {
    if (!signedIn) {
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Text(
            'Sign in to see your scan history across devices.',
            style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant),
          ),
        ),
      );
    }
    final recent = _recent;
    if (recent == null) {
      // Still loading, or the secondary fetch quietly failed.
      return const Card(
        child: Padding(
          padding: EdgeInsets.all(16),
          child: Row(children: [
            SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
            SizedBox(width: 12),
            Text('Loading recent scans…'),
          ]),
        ),
      );
    }
    if (recent.isEmpty) {
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.history_rounded,
                  size: 30, color: Theme.of(context).colorScheme.outline),
              const SizedBox(height: 8),
              const Text('No scans yet',
                  style: TextStyle(fontWeight: FontWeight.w800)),
              const SizedBox(height: 4),
              Text(
                'Run your first scan — results from every scan appear here, '
                'including full-device runs.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant),
              ),
            ],
          ),
        ),
      );
    }
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Column(
        children: [
          for (final item in recent)
            ListTile(
              dense: true,
              leading: Container(
                width: 34,
                height: 34,
                decoration: BoxDecoration(
                  color: verdictColorFor(
                          item.verdict ?? Verdict.unknown)
                      .withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Icon(
                  _verdictIcon(item.verdict ?? Verdict.unknown),
                  size: 17,
                  color: verdictColorFor(item.verdict ?? Verdict.unknown),
                ),
              ),
              title: Text(
                _targetLabel(item),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
              subtitle: Text(
                _recentSubtitle(item),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context)
                    .textTheme
                    .labelSmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              trailing: const Icon(Icons.chevron_right_rounded, size: 18),
              onTap: _openHistory,
            ),
          const Divider(height: 1),
          ListTile(
            dense: true,
            title: Text(
              'Open full history',
              style: TextStyle(
                  color: scheme.primary, fontWeight: FontWeight.w700),
            ),
            trailing: const Icon(Icons.arrow_forward_rounded, size: 18),
            onTap: _openHistory,
          ),
        ],
      ),
    );
  }

  String _targetLabel(ScanSummary item) {
    var target = item.target.trim();
    if (target.isEmpty) target = item.scanType.label;
    return target;
  }

  String _recentSubtitle(ScanSummary item) {
    final when = item.createdAt == null
        ? ''
        : DateFormat('MMM d, HH:mm').format(item.createdAt!);
    final parts = [
      item.scanType.label,
      if (item.verdict != null) item.verdict!.label,
      when,
    ];
    return parts.where((p) => p.isNotEmpty).join(' · ');
  }

  IconData _verdictIcon(Verdict v) => v == Verdict.safe || v == Verdict.lowRisk
      ? Icons.check_circle_rounded
      : v == Verdict.unknown
          ? Icons.help_outline_rounded
          : Icons.warning_amber_rounded;

  // -------------------------------------------------------------------
  // Threat summary
  // -------------------------------------------------------------------

  Widget _summaryCard(DashboardStats stats) {
    final scheme = Theme.of(context).colorScheme;
    final row = [
      ('SAFE', stats.safeCount + stats.lowRiskCount, const Color(0xFF2FA84F)),
      ('SUSPICIOUS', stats.suspiciousCount, const Color(0xFFE8A33D)),
      ('MALICIOUS',
          stats.highRiskCount + stats.maliciousCount, const Color(0xFFD64545)),
    ];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    '${stats.totalScans}',
                    style: Theme.of(context)
                        .textTheme
                        .headlineMedium
                        ?.copyWith(fontWeight: FontWeight.w800),
                  ),
                ),
                Text(
                  'scans total',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
            ),
            const SizedBox(height: 12),
            for (final (label, count, color) in row)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: Row(
                  children: [
                    Expanded(
                      flex: 2,
                      child: Text(label,
                          style: const TextStyle(
                              fontWeight: FontWeight.w700, fontSize: 13)),
                    ),
                    Expanded(
                      flex: 5,
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(4),
                        child: LinearProgressIndicator(
                          value: stats.totalScans == 0
                              ? 0
                              : (count / stats.totalScans).clamp(0.0, 1.0),
                          minHeight: 6,
                          color: color,
                          backgroundColor: color.withValues(alpha: 0.15),
                        ),
                      ),
                    ),
                    SizedBox(
                      width: 56,
                      child: Text(
                        '$count',
                        textAlign: TextAlign.end,
                        style: TextStyle(
                            color: color, fontWeight: FontWeight.w800),
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  // -------------------------------------------------------------------
  // Shared
  // -------------------------------------------------------------------

  Widget _sectionHeader(BuildContext context, String title) => Padding(
        padding: const EdgeInsets.only(left: 2, bottom: 10),
        child: Text(
          title,
          style: Theme.of(context)
              .textTheme
              .titleMedium
              ?.copyWith(fontWeight: FontWeight.w800),
        ),
      );

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
                'Static analysis only. CyberShield never executes files, never '
                'monitors in the background and never claims protection it has '
                'not earned. "No threats detected" is shown only when there '
                'are real scans to back it up.',
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