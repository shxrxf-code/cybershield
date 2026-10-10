import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/app_errors.dart';
import '../../core/models/intel.dart';
import '../../widgets/error_view.dart';
import '../../widgets/signed_out_state.dart';
import '../auth/sign_in_sheet.dart';

class IntelScreen extends StatefulWidget {
  const IntelScreen({super.key});

  @override
  State<IntelScreen> createState() => _IntelScreenState();
}

class _IntelScreenState extends State<IntelScreen> {
  final _indicator = TextEditingController();
  final _provider = TextEditingController();
  IntelResult? _result;
  bool _loading = false;
  bool _notFound = false;
  String? _error;

  @override
  void dispose() {
    _indicator.dispose();
    _provider.dispose();
    super.dispose();
  }

  Future<void> _search() async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final indicator = _indicator.text.trim();
    if (indicator.isEmpty) {
      messenger.showSnackBar(
          const SnackBar(content: Text('Enter an indicator to look up.')));
      return;
    }
    setState(() {
      _loading = true;
      _result = null;
      _notFound = false;
      _error = null;
    });
    final query = <String, dynamic>{'indicator': indicator};
    final provider = _provider.text.trim();
    if (provider.isNotEmpty) query['provider'] = provider;

    try {
      final data = await session.api
          .getJson('/api/v1/intel/search', query: query);
      if (!mounted) return;
      setState(() {
        _result = IntelResult.fromJson(
            Map<String, dynamic>.from(data as Map));
        _loading = false;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        if (e.isNotFound) {
          _notFound = true;
        } else {
          _error = friendlyAppError(e, signedIn: session.isAuthenticated);
        }
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = 'Could not reach the Intel service.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final session = AppScope.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('Threat Intel')),
      body: !session.isAuthenticated
          ? SignedOutState(
              title: 'Sign in to search threat intelligence',
              message: 'Intel lookups use the reputation answers collected '
                  'during your account\'s scans.',
              onSignIn: () => showSignInSheet(context),
            )
          : ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'Search the reputation cache',
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Looks up an indicator against answers collected during '
                    'previous scans. This never triggers an outbound query: '
                    'nothing is sent to a third party by this request.',
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _indicator,
                    enabled: !_loading,
                    textInputAction: TextInputAction.next,
                    decoration: const InputDecoration(
                      labelText: 'Indicator',
                      hintText: 'IP, domain, URL, hash, or email',
                      prefixIcon: Icon(Icons.gps_fixed_rounded),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _provider,
                    enabled: !_loading,
                    textInputAction: TextInputAction.done,
                    onSubmitted: (_) => _search(),
                    decoration: const InputDecoration(
                      labelText: 'Provider (optional)',
                      hintText: 'e.g. GSB, VirusTotal, URLhaus',
                      prefixIcon: Icon(Icons.dns_outlined),
                    ),
                  ),
                  const SizedBox(height: 14),
                  FilledButton.icon(
                    onPressed: _loading ? null : _search,
                    style: FilledButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 14),
                    ),
                    icon: _loading
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2.2),
                          )
                        : const Icon(Icons.travel_explore_rounded),
                    label: const Text('Search'),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          if (_loading)
            const LoadingView(label: 'Querying the cache…')
          else if (_error != null)
            ErrorView(message: _error!)
          else if (_notFound)
            _notFoundCard()
          else if (_result != null)
            _resultCard(_result!),
        ],
      ),
    );
  }

  Widget _notFoundCard() {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: scheme.outlineVariant),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.search_off_rounded, color: scheme.onSurfaceVariant),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('No cached data for this indicator.',
                    style: Theme.of(context)
                        .textTheme
                        .titleSmall
                        ?.copyWith(fontWeight: FontWeight.w700)),
                const SizedBox(height: 4),
                Text(
                  'A missing entry means \'unknown from our cache\', never '
                  '\'clean\'. Nothing was sent to a third party by this request.',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _resultCard(IntelResult result) {
    final scheme = Theme.of(context).colorScheme;
    final (icon, color, label) = result.allMalicious
        ? (Icons.gpp_bad_rounded, const Color(0xFFD64545), 'Consensus: malicious')
        : result.mixed
            ? (Icons.hub_outlined, const Color(0xFFE8A33D), 'Consensus: mixed')
            : (Icons.gpp_good_rounded, const Color(0xFF4E9BE8),
                'Consensus: clean (cached)');
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(result.indicator,
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(fontWeight: FontWeight.w700)),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Icon(icon, color: color, size: 22),
                    const SizedBox(width: 8),
                    Text(
                      label,
                      style: TextStyle(
                        color: color,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  result.note ?? '',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        ...result.answers.map((answer) => _answerCard(answer)),
      ],
    );
  }

  Widget _answerCard(IntelAnswer answer) {
    final scheme = Theme.of(context).colorScheme;
    final verdictColor =
        answer.isMalicious ? const Color(0xFFD64545) : const Color(0xFF4E9BE8);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    answer.provider,
                    style: Theme.of(context)
                        .textTheme
                        .titleSmall
                        ?.copyWith(fontWeight: FontWeight.w700),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: verdictColor.withValues(alpha: 0.16),
                    borderRadius: BorderRadius.circular(999),
                    border: Border.all(
                        color: verdictColor.withValues(alpha: 0.5)),
                  ),
                  child: Text(
                    answer.isMalicious ? 'MALICIOUS' : 'CLEAN (cached)',
                    style: TextStyle(
                      color: verdictColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.6,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 10,
              runSpacing: 4,
              children: [
                _meta('confidence '
                    '${(answer.confidence * 100).round()}%'),
                if (answer.indicatorType != null)
                  _meta('type ${answer.indicatorType}'),
                if (answer.threatType != null)
                  _meta('threat: ${answer.threatType}'),
                if (answer.hitCount > 0)
                  _meta('hit ${answer.hitCount}x'),
                if (answer.cachedUntil != null)
                  _meta('cached until '
                      '${DateFormat('MMM d').format(answer.cachedUntil!)}'),
              ],
            ),
            if (answer.categories.isNotEmpty) ...[
              const SizedBox(height: 8),
              Wrap(
                spacing: 6,
                runSpacing: 4,
                children: answer.categories
                    .map((c) => Chip(
                          visualDensity: VisualDensity.compact,
                          label:
                              Text(c, style: const TextStyle(fontSize: 11)),
                        ))
                    .toList(),
              ),
            ],
            if (answer.reference != null) ...[
              const SizedBox(height: 6),
              Text(
                'Reference: ${answer.reference}',
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.primary),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _meta(String text) => Text(
        text,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant),
      );
}