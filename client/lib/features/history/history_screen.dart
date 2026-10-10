import 'dart:async';

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/app_errors.dart';
import '../../core/models/enums.dart';
import '../../core/models/scan.dart';
import '../../widgets/error_view.dart';
import '../../widgets/signed_out_state.dart';
import '../../widgets/verdict_chip.dart';
import '../auth/sign_in_sheet.dart';
import '../report/report_screen.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  ScansPage? _page;
  String? _error;
  bool _loading = true;
  int _pageNumber = 1;
  String? _scanType;
  String? _verdict;
  final _search = TextEditingController();
  Timer? _debounce;
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
    if (!_initialLoadDone) {
      _initialLoadDone = true;
      _load();
    }
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _search.dispose();
    super.dispose();
  }

  Future<void> _load({bool resetPage = false}) async {
    final session = AppScope.of(context);
    if (resetPage) _pageNumber = 1;
    setState(() {
      _loading = true;
      _error = null;
    });
    final params = <String, dynamic>{
      'page': _pageNumber,
      'page_size': 20,
    };
    if (_scanType != null) params['scan_type'] = _scanType;
    if (_verdict != null) params['verdict'] = _verdict;
    final term = _search.text.trim();
    if (term.isNotEmpty) params['search'] = term;
    try {
      final data = await session.api.getJson('/api/v1/scans', query: params);
      if (!mounted) return;
      setState(() {
        _page = ScansPage.fromJson(
            Map<String, dynamic>.from(data as Map));
        _loading = false;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = friendlyAppError(e, signedIn: session.isAuthenticated);
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _error = 'Could not load scan history.';
        _loading = false;
      });
    }
  }

  void _onSearchChanged() {
    _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 450), () {
      if (mounted) _load(resetPage: true);
    });
  }

  Future<void> _openScan(ScanSummary item) async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _loading = true);
    try {
      final data = await session.api.getJson('/api/v1/scans/${item.scanId}');
      if (!mounted) return;
      final report = ScanReport.fromScanDetail(
          Map<String, dynamic>.from(data as Map));
      setState(() => _loading = false);
      if (!report.status.isTerminal) {
        await Navigator.of(context).push(
          MaterialPageRoute<void>(
              builder: (_) => ReportScreen.polling(
                  '/api/v1/scans/${item.scanId}')),
        );
      } else {
        await Navigator.of(context).push(
          MaterialPageRoute<void>(
              builder: (_) => ReportScreen.report(report)),
        );
      }
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _loading = false);
      messenger.showSnackBar(SnackBar(
          content: Text(friendlyAppError(e, signedIn: true))));
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = AppScope.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('History'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loading ? null : () => _load(),
          ),
        ],
      ),
      body: !session.isAuthenticated
          ? SignedOutState(
              title: 'Sign in to view scan history',
              message: 'Your scan history is stored per account on the '
                  'CyberShield service.',
              onSignIn: () => showSignInSheet(context),
            )
          : Column(
              children: [
                _filterBar(),
                const Divider(height: 1),
                Expanded(child: _buildList()),
                _paginationBar(),
              ],
            ),
    );
  }

  Widget _filterBar() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 10, 16, 6),
      child: Column(
        children: [
          TextField(
            controller: _search,
            onChanged: (_) => _onSearchChanged(),
            decoration: const InputDecoration(
              hintText: 'Search URL, sender, filename…',
              prefixIcon: Icon(Icons.search_rounded),
              isDense: true,
            ),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: DropdownButtonFormField<String>(
                  initialValue: _scanType,
                  isDense: true,
                  decoration: const InputDecoration(labelText: 'Type'),
                  items: const [
                    DropdownMenuItem(value: null, child: Text('All types')),
                    DropdownMenuItem(value: 'url', child: Text('URL')),
                    DropdownMenuItem(value: 'email', child: Text('Email')),
                    DropdownMenuItem(value: 'text', child: Text('Text')),
                    DropdownMenuItem(value: 'file', child: Text('File')),
                    DropdownMenuItem(value: 'apk', child: Text('APK')),
                  ],
                  onChanged: (v) {
                    setState(() => _scanType = v);
                    _load(resetPage: true);
                  },
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: DropdownButtonFormField<String>(
                  initialValue: _verdict,
                  isDense: true,
                  decoration: const InputDecoration(labelText: 'Verdict'),
                  items: [
                    const DropdownMenuItem(
                        value: null, child: Text('Any verdict')),
                    ...Verdict.values.map((v) => DropdownMenuItem(
                          value: v.api,
                          child: Text(v.label),
                        )),
                  ],
                  onChanged: (v) {
                    setState(() => _verdict = v);
                    _load(resetPage: true);
                  },
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildList() {
    if (_loading && _page == null) {
      return const LoadingView(label: 'Loading history…');
    }
    if (_error != null && _page == null) {
      return ErrorView(message: _error!, onRetry: _load);
    }
    final page = _page;
    if (page == null || page.items.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.history_rounded,
                  size: 46, color: Theme.of(context).colorScheme.outline),
              const SizedBox(height: 10),
              Text('No scans match.',
                  style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 4),
              Text('Run your first scan from the Scan tab.',
                  style: Theme.of(context).textTheme.bodySmall),
            ],
          ),
        ),
      );
    }
    return RefreshIndicator(
      onRefresh: () => _load(),
      child: ListView.separated(
        padding: const EdgeInsets.all(16),
        itemCount: page.items.length,
        separatorBuilder: (_, _) => const SizedBox(height: 10),
        itemBuilder: (context, index) {
          final item = page.items[index];
          return InkWell(
            borderRadius: BorderRadius.circular(14),
            onTap: () => _openScan(item),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: Row(
                  children: [
                    _typeIcon(item.scanType),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            item.target,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: Theme.of(context)
                                .textTheme
                                .titleSmall
                                ?.copyWith(fontWeight: FontWeight.w700),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            '${_typeLabel(item)} · '
                            '${item.createdAt == null ? '' : DateFormat('MMM d, HH:mm').format(item.createdAt!)}',
                            style: Theme.of(context)
                                .textTheme
                                .bodySmall
                                ?.copyWith(
                                    color: Theme.of(context)
                                        .colorScheme
                                        .onSurfaceVariant),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 8),
                    if (item.status != ScanStatus.completed)
                      StatusChip(status: item.status, compact: true)
                    else if (item.verdict != null)
                      VerdictChip(verdict: item.verdict!, compact: true)
                    else
                      const Icon(Icons.chevron_right_rounded),
                    const SizedBox(width: 4),
                    const Icon(Icons.chevron_right_rounded, size: 20),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _paginationBar() {
    final page = _page;
    if (page == null) return const SizedBox.shrink();
    if (page.pages <= 1 && page.items.isNotEmpty) {
      return Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 10),
        child: Text(
          '${page.total} scan${page.total == 1 ? '' : 's'} total',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant),
        ),
      );
    }
    final canPrev = page.page > 1;
    final canNext = page.page < page.pages;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 6, 16, 10),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            '${page.total} total · page ${page.page} of '
            '${page.pages == 0 ? 1 : page.pages}',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          Row(
            children: [
              IconButton(
                tooltip: 'Previous page',
                onPressed: !canPrev || _loading
                    ? null
                    : () {
                        _pageNumber -= 1;
                        _load();
                      },
                icon: const Icon(Icons.chevron_left_rounded),
              ),
              IconButton(
                tooltip: 'Next page',
                onPressed: !canNext || _loading
                    ? null
                    : () {
                        _pageNumber += 1;
                        _load();
                      },
                icon: const Icon(Icons.chevron_right_rounded),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _typeIcon(ScanType type) {
    final (icon, color) = switch (type) {
      ScanType.url => (Icons.link_rounded, const Color(0xFF4E9BE8)),
      ScanType.email => (Icons.mail_outline_rounded, const Color(0xFF9B6BE8)),
      ScanType.quick => (Icons.notes_rounded, const Color(0xFF36B37E)),
      ScanType.file => (Icons.description_outlined, const Color(0xFFE8A33D)),
      ScanType.apk => (Icons.phone_android_rounded, const Color(0xFFE07B2D)),
      ScanType.unknown => (Icons.help_outline_rounded, const Color(0xFF8A93A6)),
    };
    return Container(
      width: 38,
      height: 38,
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.16),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Icon(icon, size: 20, color: color),
    );
  }

  String _typeLabel(ScanSummary item) =>
      item.scanType == ScanType.quick ? 'Text' : item.scanType.label;
}