import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/models/quarantine.dart';
import '../../widgets/error_view.dart';
import '../../widgets/verdict_chip.dart';
import 'download_service.dart';

class QuarantineScreen extends StatefulWidget {
  const QuarantineScreen({super.key});

  @override
  State<QuarantineScreen> createState() => _QuarantineScreenState();
}

class _QuarantineScreenState extends State<QuarantineScreen> {
  List<QuarantineItem>? _items;
  String? _error;
  bool _loading = true;
  String? _busyItemId;
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

  Future<void> _load() async {
    final session = AppScope.of(context);
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final data = await session.api.getJson('/api/v1/quarantine');
      if (!mounted) return;
      final items = (data as List)
          .map((e) => QuarantineItem.fromJson(
              Map<String, dynamic>.from(e as Map)))
          .toList(growable: false);
      setState(() {
        _items = items;
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
        _error = 'Could not load the quarantine list.';
        _loading = false;
      });
    }
  }

  Future<void> _download(QuarantineItem item) async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    _setBusy(item.id);
    try {
      final response = await session.api
          .getBytes('/api/v1/quarantine/${item.id}/download');
      final path = await saveBytesToDisk(response.bodyBytes, item.originalFilename);
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(content: Text('Saved to $path', maxLines: 2)),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    } catch (_) {
      if (!mounted) return;
      messenger.showSnackBar(const SnackBar(
          content: Text('Could not save the file on this device.')));
    } finally {
      _setBusy(null);
    }
  }

  Future<void> _release(QuarantineItem item) async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final confirmed = await _confirm(
      title: 'Release ${item.originalFilename}?',
      body: 'The file will be decrypted, returned to you and marked released.',
      action: 'Release',
      isDestructive: false,
    );
    if (confirmed != true || !mounted) return;
    _setBusy(item.id);
    try {
      final response = await session.api
          .getBytes('/api/v1/quarantine/${item.id}/release');
      final path =
          await saveBytesToDisk(response.bodyBytes, item.originalFilename);
      await _load();
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(content: Text('Released and saved to $path', maxLines: 2)),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    } catch (_) {
      if (!mounted) return;
      messenger.showSnackBar(const SnackBar(
          content: Text('Could not release the file on this device.')));
    } finally {
      _setBusy(null);
    }
  }

  Future<void> _delete(QuarantineItem item) async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final confirmed = await _confirm(
      title: 'Delete from quarantine?',
      body: 'This permanently removes the stored sample and its bytes. '
          'This cannot be undone.',
      action: 'Delete',
      isDestructive: true,
    );
    if (confirmed != true || !mounted) return;
    _setBusy(item.id);
    try {
      await session.api.delete('/api/v1/quarantine/${item.id}');
      await _load();
      if (!mounted) return;
      messenger.showSnackBar(
          SnackBar(content: Text('${item.originalFilename} deleted.')));
    } on ApiException catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    } catch (_) {
      if (!mounted) return;
      messenger.showSnackBar(const SnackBar(
          content: Text('Could not delete the quarantine item.')));
    } finally {
      _setBusy(null);
    }
  }

  void _setBusy(String? id) {
    if (mounted) setState(() => _busyItemId = id);
  }

  Future<bool?> _confirm({
    required String title,
    required String body,
    required String action,
    required bool isDestructive,
  }) {
    return showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: Text(body),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: isDestructive
                ? FilledButton.styleFrom(
                    backgroundColor: Theme.of(context).colorScheme.error,
                    foregroundColor:
                        Theme.of(context).colorScheme.onError,
                  )
                : null,
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(action),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Quarantine'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loading ? null : _load,
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading && _items == null) {
      return const LoadingView(label: 'Loading quarantine…');
    }
    if (_error != null && _items == null) {
      return ErrorView(message: _error!, onRetry: _load);
    }
    final items = _items ?? const <QuarantineItem>[];
    if (items.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.health_and_safety_outlined,
                  size: 48, color: Theme.of(context).colorScheme.outline),
              const SizedBox(height: 10),
              Text('Nothing quarantined.',
                  style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 4),
              Text(
                'Files are stored here when the scan request asks to '
                'quarantine a copy.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.separated(
        padding: const EdgeInsets.all(16),
        itemCount: items.length,
        separatorBuilder: (_, _) => const SizedBox(height: 10),
        itemBuilder: (context, index) =>
            _itemCard(items[index]),
      ),
    );
  }

  Widget _itemCard(QuarantineItem item) {
    final scheme = Theme.of(context).colorScheme;
    final busy = _busyItemId == item.id;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: scheme.tertiaryContainer,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(Icons.shield_outlined,
                      size: 22, color: scheme.onTertiaryContainer),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              item.originalFilename,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: Theme.of(context)
                                  .textTheme
                                  .titleSmall
                                  ?.copyWith(fontWeight: FontWeight.w700),
                            ),
                          ),
                          if (item.verdict != null) ...[
                            const SizedBox(width: 8),
                            VerdictChip(verdict: item.verdict!),
                          ],
                        ],
                      ),
                      const SizedBox(height: 4),
                      Wrap(
                        spacing: 10,
                        runSpacing: 2,
                        children: [
                          _meta(_formatBytes(item.sizeBytes)),
                          _meta('sha256 ${item.sha256Short}…'),
                          if (item.detectedType != null)
                            _meta(item.detectedType!),
                          if (item.createdAt != null)
                            _meta(DateFormat('MMM d, HH:mm')
                                .format(item.createdAt!)),
                          if (item.isReleased) _meta('released'),
                          if (item.isEncrypted) _meta('encrypted at rest'),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const Divider(height: 20),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                _actionButton(
                  label: 'Download',
                  icon: Icons.download_rounded,
                  busy: busy,
                  onPressed: () => _download(item),
                ),
                const SizedBox(width: 8),
                _actionButton(
                  label: 'Release',
                  icon: Icons.eject_rounded,
                  busy: busy,
                  onPressed: () => _release(item),
                ),
                const SizedBox(width: 8),
                _actionButton(
                  label: 'Delete',
                  icon: Icons.delete_outline_rounded,
                  busy: busy,
                  destructive: true,
                  onPressed: () => _delete(item),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _actionButton({
    required String label,
    required IconData icon,
    required bool busy,
    required VoidCallback onPressed,
    bool destructive = false,
  }) {
    final scheme = Theme.of(context).colorScheme;
    final color = destructive ? scheme.error : scheme.primary;
    return OutlinedButton.icon(
      onPressed: busy ? null : onPressed,
      style: OutlinedButton.styleFrom(
        foregroundColor: color,
        visualDensity: VisualDensity.compact,
        padding: const EdgeInsets.symmetric(horizontal: 12),
      ),
      icon: busy
          ? SizedBox(
              width: 14,
              height: 14,
              child: CircularProgressIndicator(strokeWidth: 2, color: color),
            )
          : Icon(icon, size: 16),
      label: Text(label),
    );
  }

  Widget _meta(String text) => Text(
        text,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant),
      );

  String _formatBytes(int bytes) {
    if (bytes >= 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MiB';
    }
    if (bytes >= 1024) return '${(bytes / 1024).toStringAsFixed(1)} KiB';
    return '$bytes B';
  }
}