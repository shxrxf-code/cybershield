import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/models/dashboard.dart';
import '../../core/models/enums.dart';
import '../auth/sign_in_sheet.dart';
import '../scan/scan_hub_screen.dart';
import '../../widgets/error_view.dart';
import '../../widgets/verdict_style.dart';

/// Security-centre overview in the style of a modern antivirus dashboard:
/// a large shield status hero, prominent scan actions, metrics and recent
/// signal breakdowns. Claims stay honest — the app is a static analyzer, not
/// a live-protection product, so the hero never says "protected".
class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key, required this.onOpenScan});

  final ValueChanged<int> onOpenScan;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  DashboardStats? _stats;
  String? _error;
  bool _loading = true;
  bool _initialLoadDone = false;

  @override
  void initState() {
    super.initState();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // AppScope is an inherited widget — only safe to read here, not in
    // initState.
    final session = AppScope.of(context);
    if (!_initialLoadDone) {
      _initialLoadDone = true;
      _load();
      return;
    }
    if (!session.isAuthenticated) {
      // Signed out (or the stored session expired): drop the previous
      // account's numbers so the Status page shows the sign-in prompt with
      // neutral zeroes, never stale data for an account that is no longer
      // active on this device.
      if (_stats != null || _error != null) {
        _stats = null;
        _error = null;
      }
    } else if (!_loading && _stats == null && _error != null) {
      // Signed in from the first-run prompt: the earlier 401 (or failed)
      // attempt left no stats, so pull them now that there is a session.
      _load();
    }
  }

  Future<void> _load() async {
    final session = AppScope.of(context);
    setState(() {
      _loading = true;
      _error = null;
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
        _error = e.message;
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _error = 'Could not load the dashboard.';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = AppScope.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Security Center'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loading ? null : _load,
          ),
          if (session.user != null)
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: IconButton(
                tooltip: session.user!.email,
                icon: const Icon(Icons.account_circle_outlined),
                onPressed: () {},
              ),
            ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _load,
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
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        if (!signedIn) ...[
          SignInPromptCard(onSignIn: () => showSignInSheet(context)),
          const SizedBox(height: 16),
        ],
        if (signedIn && _error != null) ...[
          _errorBanner(_error!),
          const SizedBox(height: 16),
        ],
        _statusHero(stats),
        const SizedBox(height: 20),
        _sectionHeader('Scans'),
        _quickTiles(),
        const SizedBox(height: 20),
        _statGrid(stats),
        const SizedBox(height: 20),
        _verdictCounts(stats),
        const SizedBox(height: 20),
        _timelineCard(stats),
        if (stats.topThreatTypes.isNotEmpty) ...[
          const SizedBox(height: 20),
          _topThreats(stats),
        ],
        const SizedBox(height: 20),
        _honestyNote(),
        const SizedBox(height: 24),
      ],
    );
  }

  // -------------------------------------------------------------------
  // Status hero
  // -------------------------------------------------------------------

  Widget _statusHero(DashboardStats stats) {
    final cyan = const Color(0xFF38D6F5);
    final softCyan = const Color(0xFFB5ECFF);
    return Container(
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
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 66,
                height: 66,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: cyan,
                  boxShadow: [
                    BoxShadow(
                      color: cyan.withValues(alpha: 0.55),
                      blurRadius: 26,
                      spreadRadius: 3,
                    ),
                  ],
                ),
                child: Icon(Icons.shield_rounded,
                    color: const Color(0xFF00252E), size: 36),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: cyan.withValues(alpha: 0.14),
                        borderRadius: BorderRadius.circular(999),
                        border: Border.all(color: cyan.withValues(alpha: 0.5)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Container(
                            width: 7,
                            height: 7,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: cyan,
                              boxShadow: [
                                BoxShadow(
                                    color: cyan.withValues(alpha: 0.9),
                                    blurRadius: 6)
                              ],
                            ),
                          ),
                          const SizedBox(width: 7),
                          Text(
                            'STATIC ENGINE · READY',
                            style: TextStyle(
                              color: softCyan,
                              fontSize: 10,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 1.1,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 10),
                    Text(
                      'Analysis engine ready',
                      style: Theme.of(context)
                          .textTheme
                          .headlineSmall
                          ?.copyWith(
                            color: Colors.white,
                            fontWeight: FontWeight.w800,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'CyberShield statically inspects files, APKs, URLs, '
                      'email and pasted text. Nothing is executed, and '
                      'nothing scans automatically.',
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(
                            color: Colors.white.withValues(alpha: 0.75),
                          ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              FilledButton.icon(
                onPressed: () => widget.onOpenScan(ScanTab.device),
                icon: const Icon(Icons.folder_copy_rounded, size: 18),
                label: const Text('Device folder scan'),
              ),
              OutlinedButton.icon(
                onPressed: () => widget.onOpenScan(ScanTab.file),
                icon: const Icon(Icons.description_outlined, size: 18),
                label: const Text('Scan a file'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.white,
                  side: BorderSide(
                      color: Colors.white.withValues(alpha: 0.6)),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          Container(height: 1, color: Colors.white.withValues(alpha: 0.18)),
          const SizedBox(height: 14),
          Wrap(
            spacing: 28,
            runSpacing: 10,
            children: [
              _HeroMetric(
                value: _fmtInt(stats.totalScans),
                label: 'analyses run',
              ),
              _HeroMetric(
                value: _fmtInt(stats.quarantinedFiles),
                label: 'quarantined',
              ),
              _HeroMetric(
                value: '${stats.averageScore.toStringAsFixed(1)}/100',
                label: 'avg risk score',
              ),
            ],
          ),
        ],
      ),
    );
  }

  // -------------------------------------------------------------------
  // Section headers & scan shortcut grid
  // -------------------------------------------------------------------

  Widget _errorBanner(String message) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      color: scheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
        child: Row(
          children: [
            Icon(Icons.error_outline_rounded,
                color: scheme.onErrorContainer, size: 20),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                message,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onErrorContainer),
              ),
            ),
            TextButton(
              onPressed: _load,
              style: TextButton.styleFrom(
                  foregroundColor: scheme.onErrorContainer),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _sectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.only(left: 2, bottom: 10),
      child: Text(
        title,
        style: Theme.of(context)
            .textTheme
            .titleMedium
            ?.copyWith(fontWeight: FontWeight.w800, letterSpacing: 0.2),
      ),
    );
  }

  Widget _quickTiles() {
    final items = [
      _ScanTileData(
        'Folder scan',
        'Every file in a folder you pick',
        Icons.folder_copy_rounded,
        const Color(0xFF38D6F5),
        ScanTab.device,
      ),
      _ScanTileData(
        'File scan',
        'A single file',
        Icons.description_rounded,
        const Color(0xFFE8A33D),
        ScanTab.file,
      ),
      _ScanTileData(
        'APK scan',
        'Android app package',
        Icons.phone_android_rounded,
        const Color(0xFFE07B2D),
        ScanTab.apk,
      ),
      _ScanTileData(
        'URL scan',
        'Links and download URLs',
        Icons.link_rounded,
        const Color(0xFF4E9BE8),
        ScanTab.url,
      ),
      _ScanTileData(
        'Email scan',
        'RFC 822 message',
        Icons.mail_outline_rounded,
        const Color(0xFF9B6BE8),
        ScanTab.email,
      ),
      _ScanTileData(
        'Text scan',
        'Pasted free text',
        Icons.notes_rounded,
        const Color(0xFF36B37E),
        ScanTab.text,
      ),
    ];
    return LayoutBuilder(
      builder: (context, constraints) {
        final columns = constraints.maxWidth >= 860
            ? 3
            : (constraints.maxWidth >= 480 ? 2 : 1);
        final spacing = 12.0;
        final width =
            (constraints.maxWidth - spacing * (columns - 1)) / columns;
        return Wrap(
          spacing: spacing,
          runSpacing: spacing,
          children: items
              .map((t) => SizedBox(
                    width: width,
                    child: _ScanTile(
                      data: t,
                      onTap: () => widget.onOpenScan(t.scanTab),
                    ),
                  ))
              .toList(),
        );
      },
    );
  }

  // -------------------------------------------------------------------
  // Stats grid
  // -------------------------------------------------------------------

  Widget _statGrid(DashboardStats stats) {
    final widgets = [
      _StatCard(
        label: 'Total scans',
        value: _fmtInt(stats.totalScans),
        icon: Icons.analytics_outlined,
      ),
      _StatCard(
        label: 'Avg risk score',
        value: stats.averageScore.toStringAsFixed(1),
        suffix: '/100',
        icon: Icons.speed_rounded,
      ),
      _StatCard(
        label: 'Avg confidence',
        value: '${(stats.averageConfidence * 100).round()}%',
        icon: Icons.track_changes_rounded,
      ),
      _StatCard(
        label: 'Quarantined',
        value: _fmtInt(stats.quarantinedFiles),
        icon: Icons.shield_outlined,
      ),
    ];
    return LayoutBuilder(
      builder: (context, constraints) {
        final columns = constraints.maxWidth >= 700 ? 4 : 2;
        final spacing = 12.0;
        final width = (constraints.maxWidth - spacing * (columns - 1)) / columns;
        return Wrap(
          spacing: spacing,
          runSpacing: spacing,
          children: widgets
              .map((w) => SizedBox(
                    width: width,
                    child: w,
                  ))
              .toList(),
        );
      },
    );
  }

  // -------------------------------------------------------------------
  // Verdict counts
  // -------------------------------------------------------------------

  Widget _verdictCounts(DashboardStats stats) {
    final counts = <(Verdict, int)>[
      (Verdict.safe, stats.safeCount),
      (Verdict.lowRisk, stats.lowRiskCount),
      (Verdict.suspicious, stats.suspiciousCount),
      (Verdict.highRisk, stats.highRiskCount),
      (Verdict.malicious, stats.maliciousCount),
      (Verdict.unknown, stats.unknownCount),
    ];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Verdict distribution',
                style: Theme.of(context)
                    .textTheme
                    .titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: counts.map((row) {
                final verdict = row.$1;
                final count = row.$2;
                return Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color:
                        verdictFillFor(verdict, brightness: Theme.of(context).brightness),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                        color: verdictColorFor(verdict)
                            .withValues(alpha: 0.5)),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        _fmtInt(count),
                        style: TextStyle(
                          color: verdictColorFor(verdict),
                          fontWeight: FontWeight.w800,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        verdict.label.toUpperCase(),
                        style: TextStyle(
                          color: verdictColorFor(verdict),
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          letterSpacing: 0.6,
                        ),
                      ),
                    ],
                  ),
                );
              }).toList(),
            ),
          ],
        ),
      ),
    );
  }

  // -------------------------------------------------------------------
  // Timeline
  // -------------------------------------------------------------------

  Widget _timelineCard(DashboardStats stats) {
    final data = stats.timeline;
    if (data.isEmpty) {
      return const Card(
        child: Padding(
          padding: EdgeInsets.all(16),
          child: Text('No scan activity in the last 30 days yet.'),
        ),
      );
    }
    final maxTotal = math.max(1, data.fold(0, (m, b) => math.max(m, b.total)));
    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Last 30 days',
                style: Theme.of(context)
                    .textTheme
                    .titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 4),
            _legend(),
            const SizedBox(height: 12),
            SizedBox(
              height: 120,
              child: StackedBarChart(data: data, maxTotal: maxTotal),
            ),
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  data.first.date != null
                      ? DateFormat.MMMd().format(data.first.date!)
                      : '',
                  style: Theme.of(context).textTheme.labelSmall,
                ),
                Text(
                  data.last.date != null
                      ? DateFormat.MMMd().format(data.last.date!)
                      : '',
                  style: Theme.of(context).textTheme.labelSmall,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _legend() {
    const rows = [
      ('SAFE/LOW', Color(0xFF2FA84F)),
      ('SUSP/HIGH', Color(0xFFE8A33D)),
      ('MALICIOUS', Color(0xFFD64545)),
    ];
    return Row(
      children: rows
          .map((row) => Padding(
                padding: const EdgeInsets.only(right: 14),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 10,
                      height: 10,
                      decoration: BoxDecoration(
                        color: row.$2,
                        borderRadius: BorderRadius.circular(3),
                      ),
                    ),
                    const SizedBox(width: 5),
                    Text(row.$1,
                        style: Theme.of(context).textTheme.labelSmall),
                  ],
                ),
              ))
          .toList(),
    );
  }

  // -------------------------------------------------------------------
  // Top threats
  // -------------------------------------------------------------------

  Widget _topThreats(DashboardStats stats) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Top signal categories',
                style: Theme.of(context)
                    .textTheme
                    .titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 8),
            ...stats.topThreatTypes.map((t) => ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.flag_outlined, size: 20),
                  title: Text(t.category),
                  trailing: Text(_fmtInt(t.count),
                      style: Theme.of(context)
                          .textTheme
                          .titleSmall
                          ?.copyWith(fontWeight: FontWeight.w700)),
                )),
          ],
        ),
      ),
    );
  }

  // -------------------------------------------------------------------
  // Honesty note
  // -------------------------------------------------------------------

  Widget _honestyNote() {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 34,
              height: 34,
              decoration: BoxDecoration(
                color: scheme.primaryContainer,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(Icons.info_outline_rounded,
                  size: 18, color: scheme.primary),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'Static analysis only — CyberShield never executes scanned '
                'objects and performs no background monitoring, live '
                'protection or web filtering on this device.',
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

class _HeroMetric extends StatelessWidget {
  const _HeroMetric({required this.value, required this.label});

  final String value;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          value,
          style: Theme.of(context)
              .textTheme
              .titleLarge
              ?.copyWith(color: Colors.white, fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 2),
        Text(
          label,
          style: Theme.of(context)
              .textTheme
              .labelSmall
              ?.copyWith(color: Colors.white.withValues(alpha: 0.7)),
        ),
      ],
    );
  }
}

class _ScanTileData {
  const _ScanTileData(this.title, this.subtitle, this.icon, this.color, this.scanTab);
  final String title;
  final String subtitle;
  final IconData icon;
  final Color color;
  final int scanTab;
}

class _ScanTile extends StatelessWidget {
  const _ScanTile({required this.data, required this.onTap});

  final _ScanTileData data;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Row(
            children: [
              Container(
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color: data.color.withValues(alpha: 0.16),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(data.icon, color: data.color, size: 22),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      data.title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context)
                          .textTheme
                          .titleSmall
                          ?.copyWith(fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      data.subtitle,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(color: scheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
              Icon(Icons.chevron_right_rounded,
                  color: scheme.onSurfaceVariant),
            ],
          ),
        ),
      ),
    );
  }
}

class _StatCard extends StatelessWidget {
  const _StatCard({
    required this.label,
    required this.value,
    this.suffix,
    required this.icon,
  });

  final String label;
  final String value;
  final String? suffix;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, size: 20, color: scheme.primary),
            const SizedBox(height: 10),
            Text(
              '$value${suffix ?? ''}',
              style: Theme.of(context)
                  .textTheme
                  .headlineSmall
                  ?.copyWith(fontWeight: FontWeight.w800),
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 2),
            Text(
              label,
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
}

/// Hand-rolled stacked bar chart, one column per day.
class StackedBarChart extends StatelessWidget {
  const StackedBarChart({
    super.key,
    required this.data,
    required this.maxTotal,
  });

  final List<StatsBucket> data;
  final int maxTotal;

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.end,
      children: data.map((bucket) {
        final total = bucket.total;
        final fraction = total == 0 ? 0.0 : total / maxTotal;
        final heightPx = 120.0 * fraction;
        return Expanded(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 1),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                SizedBox(
                  height: heightPx,
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      if (bucket.malicious > 0)
                        _segment(bucket.malicious / maxTotal,
                            const Color(0xFFD64545)),
                      if (bucket.suspicious > 0)
                        _segment(bucket.suspicious / maxTotal,
                            const Color(0xFFE8A33D)),
                      if (bucket.safe > 0)
                        _segment(bucket.safe / maxTotal,
                            const Color(0xFF2FA84F)),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      }).toList(),
    );
  }

  Widget _segment(double fraction, Color color) {
    return FractionallySizedBox(
      widthFactor: 1,
      heightFactor: fraction.clamp(0.0, 1.0),
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 0.5),
        decoration: BoxDecoration(
          color: color,
          borderRadius: BorderRadius.circular(2),
        ),
      ),
    );
  }
}

String _fmtInt(int value) {
  final s = value.toString();
  if (s.length <= 3) return s;
  final buffer = StringBuffer();
  for (var i = 0; i < s.length; i++) {
    if (i > 0 && (s.length - i) % 3 == 0) buffer.write(',');
    buffer.write(s[i]);
  }
  return buffer.toString();
}