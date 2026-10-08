import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/disclaimer.dart';
import '../../core/models/enums.dart';
import '../../core/models/scan.dart';
import '../../core/utils/json.dart';
import '../../widgets/disclaimer_banner.dart';
import '../../widgets/error_view.dart';
import '../../widgets/risk_gauge.dart';
import '../../widgets/verdict_chip.dart';
import '../../widgets/verdict_style.dart';
import 'breakdown_card.dart';
import 'feedback_card.dart';
import 'signal_tile.dart';

/// Shows one scan report. Accepts an already-finished [ScanReport] or a
/// `pollPath` (async submission / history detail) that is polled until the
/// job reaches a terminal state.
class ReportScreen extends StatefulWidget {
  const ReportScreen.report(this.report, {super.key}) : pollPath = null;

  const ReportScreen.polling(String this.pollPath, {super.key}) : report = null;

  final ScanReport? report;
  final String? pollPath;

  @override
  State<ReportScreen> createState() => _ReportScreenState();
}

class _ReportScreenState extends State<ReportScreen> {
  ScanReport? _report;
  String? _pollError;
  bool _polling = false;
  bool _pollStarted = false;

  @override
  void initState() {
    super.initState();
    _report = widget.report;
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // AppScope is an inherited widget — only safe to read here, not in
    // initState, and _pollLoop reads it synchronously before its first await.
    if (!_pollStarted && widget.pollPath != null) {
      _pollStarted = true;
      _polling = true;
      _pollLoop();
    }
  }

  @override
  void dispose() {
    _polling = false;
    super.dispose();
  }

  Future<void> _pollLoop() async {
    final path = widget.pollPath!;
    final session = AppScope.of(context);
    var delay = const Duration(milliseconds: 700);
    var notFoundTries = 0;
    final deadline = DateTime.now().add(const Duration(minutes: 6));
    while (_polling && mounted && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(delay);
      if (!mounted || !_polling) return;
      try {
        final data = await session.api.getJson(path);
        if (!mounted || !_polling) return;
        final report = ScanReport.fromScanDetail(
            Map<String, dynamic>.from(data as Map));
        setState(() {
          _report = report;
          _pollError = null;
        });
        if (report.status.isTerminal) {
          _polling = false;
          return;
        }
      } on ApiException catch (e) {
        if (!mounted || !_polling) return;
        if (e.isNotFound && notFoundTries < 3) {
          notFoundTries += 1;
        } else if (e.isRateLimited) {
          delay = Duration(seconds: e.retryAfterSeconds ?? 3);
        } else {
          setState(() {
            _pollError = e.message;
            _polling = false;
          });
          return;
        }
      } catch (_) {
        if (!mounted || !_polling) return;
        setState(() {
          _pollError = 'Could not reach the server while waiting.';
          _polling = false;
        });
        return;
      }
      delay = delay < const Duration(seconds: 6)
          ? delay * 2
          : const Duration(seconds: 6);
    }
    if (mounted && _polling) {
      setState(() {
        _pollError = 'Still waiting after several minutes. Check History.';
        _polling = false;
      });
    }
  }

  void _retryPoll() {
    _pollError = null;
    _polling = true;
    _pollLoop();
  }

  @override
  Widget build(BuildContext context) {
    final report = _report;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan report'),
        actions: [
          if (report != null)
            Padding(
              padding: const EdgeInsets.only(right: 12),
              child: Center(
                child: Text(
                  report.scanId.length > 10
                      ? '…${report.scanId.substring(report.scanId.length - 10)}'
                      : report.scanId,
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant),
                ),
              ),
            ),
        ],
      ),
      body: report == null
          ? const LoadingView(label: 'Preparing report…')
          : _buildBody(report),
    );
  }

  Widget _buildBody(ScanReport report) {
    if (_pollError != null) {
      return ErrorView(message: _pollError!, onRetry: _retryPoll);
    }
    if (!report.status.isTerminal || !report.hasReport) {
      return ListView(
        padding: const EdgeInsets.all(24),
        children: [
          _StatusWaiting(report: report),
          const SizedBox(height: 20),
          const DisclaimerBanner(),
        ],
      );
    }
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _headerCard(report),
        if (report.isQuarantined) const SizedBox(height: 12),
        if (report.isQuarantined) _quarantinedNote(report),
        const SizedBox(height: 14),
        _verdictBanner(report),
        const SizedBox(height: 14),
        if (report.recommendationText != null) _recommendationCard(report),
        if (report.reasons.isNotEmpty) ...[
          const SizedBox(height: 14),
          _reasonsCard(report),
        ],
        if (report.signals.isNotEmpty) ...[
          const SizedBox(height: 14),
          _signalsCard(report),
        ],
        if (report.indicators.isNotEmpty) ...[
          const SizedBox(height: 14),
          _indicatorsCard(report),
        ],
        if (report.scoreBreakdown != null) ...[
          const SizedBox(height: 14),
          BreakdownCard(breakdown: report.scoreBreakdown),
        ],
        const SizedBox(height: 14),
        _detailsCard(report),
        const SizedBox(height: 14),
        _analysisCard(report),
        if (report.scanType == ScanType.file || report.scanType == ScanType.apk)
          const SizedBox(height: 14),
        if (report.scanType == ScanType.file || report.scanType == ScanType.apk)
          const LimitCallout(text: staticOnlyNote),
        const SizedBox(height: 14),
        FeedbackCard(
          report: report,
          onSubmitted: _submitFeedback,
        ),
        const SizedBox(height: 16),
        const DisclaimerBanner(),
        const SizedBox(height: 24),
      ],
    );
  }

  // ------------------------------------------------------------------
  // Header
  // ------------------------------------------------------------------

  Widget _headerCard(ScanReport report) {
    final scheme = Theme.of(context).colorScheme;
    final verdict = report.verdict ?? Verdict.unknown;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            Row(
              children: [
                Icon(_iconForType(report.scanType),
                    color: scheme.primary, size: 30),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        report.scanType.label,
                        style: Theme.of(context)
                            .textTheme
                            .labelSmall
                            ?.copyWith(
                                letterSpacing: 1.2,
                                color: scheme.onSurfaceVariant),
                      ),
                      Text(
                        report.primaryLabel,
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w700),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                VerdictChip(verdict: verdict),
              ],
            ),
            const SizedBox(height: 16),
            RiskGauge(
              score: report.score ?? 0,
              confidence: report.confidence,
            ),
          ],
        ),
      ),
    );
  }

  Widget _verdictBanner(ScanReport report) {
    final scheme = Theme.of(context).colorScheme;
    final verdict = report.verdict ?? Verdict.unknown;
    final color = verdictColorFor(verdict);
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: verdictFillFor(verdict, brightness: Theme.of(context).brightness),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            verdict == Verdict.safe
                ? Icons.verified_rounded
                : verdict == Verdict.malicious
                    ? Icons.gpp_bad_rounded
                    : Icons.info_outline_rounded,
            color: color,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              'This is an automated, evidence-based assessment graded '
              '${verdict.label}'
              '${report.confidence == null ? '.' : ' with ${(report.confidence! * 100).round()}% confidence.'}'
              ' It is not a guarantee that the object is '
              '${verdict.isSafeEnough ? 'benign' : 'malicious'} — false '
              'positives and negatives are possible.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurface),
            ),
          ),
        ],
      ),
    );
  }

  Widget _recommendationCard(ScanReport report) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.flag_outlined, size: 22, color: scheme.tertiary),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Recommendation — ${report.recommendation ?? 'none'}',
                    style: Theme.of(context)
                        .textTheme
                        .labelMedium
                        ?.copyWith(
                            fontWeight: FontWeight.w700,
                            letterSpacing: 0.4),
                  ),
                  const SizedBox(height: 4),
                  Text(report.recommendationText!,
                      style: Theme.of(context).textTheme.bodyMedium),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _reasonsCard(ScanReport report) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionTitle('Why this verdict'),
            const SizedBox(height: 10),
            ...report.reasons.asMap().entries.map((entry) => Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '${entry.key + 1}.',
                        style: Theme.of(context)
                            .textTheme
                            .labelMedium
                            ?.copyWith(
                                fontWeight: FontWeight.w800,
                                color:
                                    Theme.of(context).colorScheme.primary),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(report.reasons[entry.key],
                            style: Theme.of(context).textTheme.bodyMedium),
                      ),
                    ],
                  ),
                )),
          ],
        ),
      ),
    );
  }

  Widget _signalsCard(ScanReport report) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _sectionTitle('Detection signals (${report.signals.length})'),
        const SizedBox(height: 10),
        ...report.signals.map((s) => SignalTile(signal: s)),
      ],
    );
  }

  Widget _indicatorsCard(ScanReport report) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionTitle('Indicators (${report.indicators.length})'),
            const SizedBox(height: 10),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: report.indicators
                  .map((ind) => Tooltip(
                        message: '${ind.type}: ${ind.value}',
                        child: Chip(
                          avatar: Icon(Icons.link_rounded,
                              size: 16,
                              color: scheme.primary),
                          label: Text(
                            ind.value.length > 48
                                ? '${ind.value.substring(0, 48)}…'
                                : ind.value,
                            style: const TextStyle(fontSize: 12),
                          ),
                        ),
                      ))
                  .toList(),
            ),
          ],
        ),
      ),
    );
  }

  // ------------------------------------------------------------------
  // Detailed metadata
  // ------------------------------------------------------------------

  Widget _detailsCard(ScanReport report) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionTitle('Details'),
            const SizedBox(height: 10),
            _metaRow('Scan ID', report.scanId, monospace: true),
            if (report.createdAt != null)
              _metaRow('Analysed at',
                  DateFormat('yyyy-MM-dd HH:mm').format(report.createdAt!)),
            if (report.objectType != ObjectType.unknown)
              _metaRow('Object type', report.objectType.label),
            ..._typeSpecificRows(report),
          ],
        ),
      ),
    );
  }

  List<Widget> _typeSpecificRows(ScanReport report) {
    final rows = <Widget>[];
    switch (report.scanType) {
      case ScanType.url:
        _add(rows, 'URL', report.targetUrl);
        _add(rows, 'Normalised', report.normalisedUrl);
        _add(rows, 'Host', report.targetHost);
        if (report.resolvedIps.isNotEmpty) {
          _add(rows, 'Resolved IPs', report.resolvedIps.join(', '));
        }
        if (report.pageTitle != null) _add(rows, 'Page title', report.pageTitle);
        if (report.httpStatus != null) {
          _add(rows, 'HTTP status', '${report.httpStatus}');
        }
        _add(rows, 'Fetch', report.fetchBlockedReason == null ? 'allowed'
            : 'blocked — ${report.fetchBlockedReason}');
      case ScanType.email:
        _add(rows, 'Sender', report.targetEmail);
        _add(rows, 'Sender domain', report.senderDomain);
        _add(rows, 'Reply-to', report.replyTo);
        _add(rows, 'Return-path', report.returnPath);
        _add(rows, 'Subject', report.emailSubject);
        _add(rows, 'Attachments',
            report.attachmentCount > 0 ? '${report.attachmentCount}' : '0');
        final auth = report.authentication;
        if (auth.isNotEmpty) {
          final spf = asString(auth['spf']) ?? asString(auth['spf_result']);
          final dkim = asString(auth['dkim']) ?? asString(auth['dkim_result']);
          final dmarc = asString(auth['dmarc']) ?? asString(auth['dmarc_result']);
          if (spf != null) _add(rows, 'SPF', spf);
          if (dkim != null) _add(rows, 'DKIM', dkim);
          if (dmarc != null) _add(rows, 'DMARC', dmarc);
        }
      case ScanType.file:
        _add(rows, 'File name', report.originalFilename);
        _add(rows, 'Detected type', report.detectedType);
        if (report.sizeBytes != null) {
          _add(rows, 'Size', _formatBytes(report.sizeBytes!));
        }
        _add(rows, 'SHA-256', report.sha256, monospace: true);
        _add(rows, 'SHA-1', report.sha1, monospace: true);
        _add(rows, 'MD5', report.md5, monospace: true);
        if (report.entropy != null) {
          _add(rows, 'Entropy', report.entropy!.toStringAsFixed(3));
        }
      case ScanType.apk:
        _add(rows, 'Package', report.packageName);
        _add(rows, 'Version', [
          if (report.versionName != null) report.versionName!,
          if (report.versionCode != null) 'code ${report.versionCode}',
        ].join(' '));
        _add(rows, 'File name', report.originalFilename);
        if (report.sizeBytes != null) {
          _add(rows, 'Size', _formatBytes(report.sizeBytes!));
        }
        _add(rows, 'SHA-256', report.sha256, monospace: true);
        if (report.permissionsRequested.isNotEmpty) {
          _add(rows, 'Permissions requested',
              '${report.permissionsRequested.length}');
        }
        if (report.dangerousPermissions.isNotEmpty) {
          rows.add(Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Dangerous permissions',
                    style: Theme.of(context)
                        .textTheme
                        .labelMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 4),
                Wrap(
                  spacing: 6,
                  runSpacing: 4,
                  children: report.dangerousPermissions
                      .map((p) => Chip(
                            visualDensity: VisualDensity.compact,
                            label:
                                Text(p, style: const TextStyle(fontSize: 11)),
                          ))
                      .toList(),
                ),
              ],
            ),
          ));
        }
      case ScanType.quick:
        _add(rows, 'Characters',
            report.characterCount != null ? '${report.characterCount}' : null);
        if (report.extractedUrls.isNotEmpty) {
          _add(rows, 'Extracted URLs', '${report.extractedUrls.length}');
        }
        if (report.extractedEmails.isNotEmpty) {
          _add(rows, 'Extracted emails', '${report.extractedEmails.length}');
        }
      case ScanType.unknown:
        break;
    }
    if (report.metadataJson != null && report.metadataJson!.isNotEmpty) {
      rows.add(_metadataExpansion(report.metadataJson!));
    }
    return rows;
  }

  Widget _analysisCard(ScanReport report) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionTitle('Analysis'),
            const SizedBox(height: 10),
            if (report.durationMs != null)
              _metaRow('Duration',
                  report.durationMs! < 1000
                      ? '${report.durationMs} ms'
                      : '${(report.durationMs! / 1000).toStringAsFixed(1)} s'),
            const SizedBox(height: 6),
            Text('Analysers that ran',
                style: Theme.of(context)
                    .textTheme
                    .labelMedium
                    ?.copyWith(fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
            if (report.analyzers.isEmpty)
              Text(
                'No analyser details were reported.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              )
            else
              Wrap(
                spacing: 6,
                runSpacing: 6,
                children: report.analyzers
                    .map((a) => _analyzerChip(a, scheme))
                    .toList(),
              ),
            const SizedBox(height: 8),
            Text(
              'Scanner availability affects how much evidence was collected: '
              'a verdict reached with a scanner down carries that caveat.',
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

  Widget _metadataExpansion(Map<String, dynamic> metadata) {
    final pretty = const JsonEncoder.withIndent('  ').convert(metadata);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ExpansionTile(
          tilePadding: EdgeInsets.zero,
          title: Text('Technical metadata (incl. scanner status)',
              style: Theme.of(context)
                  .textTheme
                  .labelMedium
                  ?.copyWith(fontWeight: FontWeight.w600)),
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerLowest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                pretty,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(fontFamily: 'monospace'),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _quarantinedNote(ScanReport report) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.tertiaryContainer.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Icon(Icons.lock_rounded, size: 20, color: scheme.onTertiaryContainer),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'A copy of this file was moved to quarantine and is available '
              'under the Quarantine tab.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onTertiaryContainer),
            ),
          ),
        ],
      ),
    );
  }

  // ------------------------------------------------------------------
  // Feedback
  // ------------------------------------------------------------------

  Future<void> _submitFeedback(String label, String? comment) async {
    final session = AppScope.of(context);
    final report = _report!;
    final body = {'label': label, 'comment': ?comment};
    try {
      await session.api
          .postJson('/api/v1/scans/${report.scanId}/feedback', body: body);
    } on ApiException catch (e) {
      if (e.isConflict) {
        if (!mounted) return;
        // Correct, graceful handling: exactly one feedback per scan.
        await _showFeedbackConflict();
        return;
      }
      rethrow;
    }
  }

  Future<void> _showFeedbackConflict() async {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: Theme.of(context).colorScheme.tertiaryContainer,
        content: Text(
          'Feedback was already submitted for this scan — only one per scan '
          'is allowed.',
          style: TextStyle(
              color: Theme.of(context).colorScheme.onTertiaryContainer),
        ),
      ),
    );
  }

  // ------------------------------------------------------------------
  // Small helpers
  // ------------------------------------------------------------------

  Widget _sectionTitle(String text) => Text(
        text,
        style: Theme.of(context)
            .textTheme
            .titleSmall
            ?.copyWith(fontWeight: FontWeight.w700),
      );

  void _add(List<Widget> rows, String label, String? value,
      {bool monospace = false}) {
    if (value == null || value.isEmpty) return;
    rows.add(_metaRow(label, value, monospace: monospace));
  }

  Widget _metaRow(String label, String value, {bool monospace = false}) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 150,
            child: Text(
              label,
              style: Theme.of(context)
                  .textTheme
                  .labelMedium
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    fontFamily: monospace ? 'monospace' : null,
                    fontWeight: monospace ? FontWeight.w500 : null,
                  ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _analyzerChip(String name, ColorScheme scheme) {
    final active = name.toLowerCase() != 'heuristics' &&
        !name.toLowerCase().contains('unavailable');
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
            color: (active ? const Color(0xFF2FA84F) : scheme.outlineVariant)
                .withValues(alpha: 0.5)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            active ? Icons.check_circle_outline : Icons.help_outline_rounded,
            size: 14,
            color:
                active ? const Color(0xFF2FA84F) : scheme.onSurfaceVariant,
          ),
          const SizedBox(width: 5),
          Text(name,
              style: Theme.of(context)
                  .textTheme
                  .labelSmall
                  ?.copyWith(fontWeight: FontWeight.w600)),
        ],
      ),
    );
  }

  IconData _iconForType(ScanType type) => switch (type) {
        ScanType.url => Icons.link_rounded,
        ScanType.email => Icons.mail_outline_rounded,
        ScanType.file => Icons.description_outlined,
        ScanType.apk => Icons.phone_android_rounded,
        ScanType.quick => Icons.notes_rounded,
        ScanType.unknown => Icons.help_outline_rounded,
      };

  String _formatBytes(int bytes) {
    if (bytes >= 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MiB';
    }
    if (bytes >= 1024) return '${(bytes / 1024).toStringAsFixed(1)} KiB';
    return '$bytes B';
  }
}

/// Waiting state shown while an async scan is still queued/running.
class _StatusWaiting extends StatelessWidget {
  const _StatusWaiting({required this.report});

  final ScanReport report;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final status = report.status;
    return Column(
      children: [
        const SizedBox(height: 24),
        Container(
          width: 72,
          height: 72,
          decoration: BoxDecoration(
            color: scheme.primaryContainer,
            shape: BoxShape.circle,
          ),
          child: const Padding(
            padding: EdgeInsets.all(18),
            child: CircularProgressIndicator(strokeWidth: 2.6),
          ),
        ),
        const SizedBox(height: 16),
        Text(
          status.label,
          style: Theme.of(context)
              .textTheme
              .headlineSmall
              ?.copyWith(fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 6),
        Text(
          'The scan is running and will update automatically. '
          'Static analysis can take a little while for large files.',
          textAlign: TextAlign.center,
          style: Theme.of(context)
              .textTheme
              .bodyMedium
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: 6),
        Text(
          report.target,
          textAlign: TextAlign.center,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: scheme.primary),
        ),
      ],
    );
  }
}