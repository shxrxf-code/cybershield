import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// One installed application as reported by the platform package manager.
///
/// This is the *metadata the OS publishes about the app* — its display name,
/// version and the permissions it declares in its manifest. It is not a
/// runtime inspection and none of it is read from app data.
class InstalledApp {
  const InstalledApp({
    required this.packageName,
    required this.label,
    this.versionName,
    this.requestedPermissions = const [],
  });

  final String packageName;
  final String label;
  final String? versionName;
  final List<String> requestedPermissions;

  factory InstalledApp.fromJson(Map<String, dynamic> json) => InstalledApp(
        packageName: json['packageName'] as String? ?? '',
        label: json['label'] as String? ?? '',
        versionName: json['versionName'] as String?,
        requestedPermissions: (json['requestedPermissions'] as List?)
                ?.map((e) => e.toString())
                .toList(growable: false) ??
            const [],
      );
}

/// Informational installed-apps view.
///
/// Only functional on Android where the host side provides a package-manager
/// listing via a `MethodChannel`. On every other platform this screen shows an
/// honest "not available" state — it never fakes a list.
class AppsScreen extends StatefulWidget {
  const AppsScreen({super.key});

  @override
  State<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends State<AppsScreen> {
  static const _channel = MethodChannel('cybershield.device/apps');

  bool _loading = true;
  bool _supported = true;
  String? _error;
  List<InstalledApp>? _apps;
  String _query = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final raw = await _channel
          .invokeMethod<List>('listInstalledApps')
          // A hung platform channel must never pin the UI to a spinner.
          .timeout(const Duration(seconds: 5));
      if (!mounted) return;
      setState(() {
        _apps = (raw ?? const [])
            .map((e) => InstalledApp.fromJson(
                Map<String, dynamic>.from(e as Map)))
            .toList(growable: false);
        _loading = false;
        _supported = true;
      });
    } on MissingPluginException {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _supported = false;
      });
    } on PlatformException {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _supported = true;
        _error = 'Could not list installed apps on this device.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _supported = true;
        _error = 'Could not list installed apps.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Apps'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loading ? null : _load,
          ),
        ],
      ),
      body: _buildBody(scheme),
    );
  }

  Widget _buildBody(ColorScheme scheme) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (!_supported) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.phone_android_rounded,
                      size: 44, color: scheme.onSurfaceVariant),
                  const SizedBox(height: 12),
                  Text(
                    'Installed apps is Android-only',
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'This platform does not expose an installed-apps list to '
                    'applications. The list is available on Android builds.',
                    textAlign: TextAlign.center,
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
    }
    if (_error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline_rounded, size: 40, color: scheme.error),
              const SizedBox(height: 12),
              Text(_error!, textAlign: TextAlign.center),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: _load,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('Try again'),
              ),
            ],
          ),
        ),
      );
    }
    return _list();
  }

  Widget _list() {
    final apps = _apps ?? const <InstalledApp>[];
    final filtered = _query.trim().isEmpty
        ? apps
        : apps
            .where((a) =>
                a.label.toLowerCase().contains(_query.trim().toLowerCase()) ||
                a.packageName
                    .toLowerCase()
                    .contains(_query.trim().toLowerCase()))
            .toList(growable: false);
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
          child: TextField(
            decoration: const InputDecoration(
              hintText: 'Search installed apps',
              prefixIcon: Icon(Icons.search_rounded),
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 8, 16, 8),
          child: Row(
            children: [
              Icon(Icons.info_outline_rounded, size: 16),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Package-manager metadata only — nothing is read at runtime '
                  'and nothing is uploaded.',
                  style: TextStyle(fontSize: 12),
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: filtered.isEmpty
              ? const Center(child: Text('No matching apps.'))
              : ListView.builder(
                  itemCount: filtered.length,
                  itemBuilder: (context, index) {
                    final app = filtered[index];
                    return ListTile(
                      leading: const CircleAvatar(
                        child: Icon(Icons.apps_rounded),
                      ),
                      title: Text(
                        app.label.isEmpty ? app.packageName : app.label,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      subtitle: Text(
                        app.versionName == null
                            ? app.packageName
                            : '${app.packageName} · v${app.versionName}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      onTap: () => _showDetails(app),
                      trailing: const Icon(Icons.chevron_right_rounded),
                    );
                  },
                ),
        ),
      ],
    );
  }

  void _showDetails(InstalledApp app) {
    final scheme = Theme.of(context).colorScheme;
    final permissions = app.requestedPermissions;
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                app.label.isEmpty ? app.packageName : app.label,
                style: Theme.of(context)
                    .textTheme
                    .titleMedium
                    ?.copyWith(fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 4),
              Text(
                '${app.packageName}'
                '${app.versionName == null ? '' : ' · v${app.versionName}'}',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: 16),
              Text(
                'Declared permissions',
                style: Theme.of(context)
                    .textTheme
                    .titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 8),
              if (permissions.isEmpty)
                Text(
                  'None declared. (On Android 11+ a permission may only be '
                  'listed when the app is visible to you.)',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                )
              else ...[
                ConstrainedBox(
                  constraints: const BoxConstraints(maxHeight: 320),
                  child: ListView.builder(
                    shrinkWrap: true,
                    itemCount: permissions.length,
                    itemBuilder: (context, i) => ListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.lock_outline_rounded,
                          size: 18),
                      title: Text(
                        permissions[i].replaceFirst(
                            'android.permission.', ''),
                        style: const TextStyle(fontSize: 13),
                      ),
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              Text(
                'This list shows what the app asked for at install time. It is '
                'not a claim that it is safe or that a permission was granted.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ],
          ),
        ),
      ),
    );
  }
}