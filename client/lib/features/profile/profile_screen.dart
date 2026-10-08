import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';

import '../../app.dart';
import '../../core/api_client.dart';
import '../../core/api_exception.dart';
import '../../core/config.dart';
import '../../core/models/api_key.dart';
import '../../core/models/user.dart';
import '../../core/session_controller.dart';
import '../../features/auth/sign_in_sheet.dart';
import '../../widgets/error_view.dart';
import '../../widgets/password_strength_meter.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  List<ApiKeyItem>? _keys;
  List<User>? _users;
  bool _loadingKeys = true;
  bool _loadingUsers = true;
  String? _keysError;
  String? _usersError;
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
      _loadKeys();
      _maybeLoadUsers();
    }
  }

  Future<void> _loadKeys() async {
    final session = AppScope.of(context);
    setState(() {
      _loadingKeys = true;
      _keysError = null;
    });
    try {
      final data = await session.api.getJson('/api/v1/api-keys');
      if (!mounted) return;
      setState(() {
        _keys = (data as List)
            .map((e) => ApiKeyItem.fromJson(
                Map<String, dynamic>.from(e as Map)))
            .toList(growable: false);
        _loadingKeys = false;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _keysError = e.message;
        _loadingKeys = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _keysError = 'Could not load API keys.';
        _loadingKeys = false;
      });
    }
  }

  Future<void> _maybeLoadUsers() async {
    final session = AppScope.of(context);
    if (!session.isAdmin) {
      _loadingUsers = false;
      return;
    }
    await _loadUsers();
  }

  Future<void> _loadUsers() async {
    final session = AppScope.of(context);
    setState(() {
      _loadingUsers = true;
      _usersError = null;
    });
    try {
      final data = await session.api.getJson('/api/v1/users');
      if (!mounted) return;
      setState(() {
        _users = (data as List)
            .map((e) => User.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(growable: false);
        _loadingUsers = false;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _usersError = e.message;
        _loadingUsers = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _usersError = 'Could not load users.';
        _loadingUsers = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = AppScope.of(context);
    final scheme = Theme.of(context).colorScheme;
    final user = session.user;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Profile'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded),
            onPressed: () {
              _loadKeys();
              _maybeLoadUsers();
              session.refreshUser();
            },
          ),
        ],
      ),
      body: session.status != SessionStatus.authenticated
          ? const _SignedOutView()
          : user == null
              ? ErrorView(
                  message:
                      "Couldn't load your profile. Your session is still "
                      'active — retry or sign out below.',
                  onRetry: () => session.refreshUser(),
                )
              : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                _userCard(user, session),
                const SizedBox(height: 14),
                if (session.usesApiKey)
                  _apiKeyModeBanner(scheme),
                if (session.usesApiKey) const SizedBox(height: 14),
                _passwordCard(session),
                const SizedBox(height: 14),
                _apiKeysCard(session),
                if (session.isAdmin) ...[
                  const SizedBox(height: 14),
                  _adminCard(session),
                ],
                const SizedBox(height: 20),
                OutlinedButton.icon(
                  onPressed: _confirmLogout,
                  style: OutlinedButton.styleFrom(
                    foregroundColor: scheme.error,
                    side: BorderSide(color: scheme.error.withValues(alpha: 0.6)),
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                  icon: const Icon(Icons.logout_rounded),
                  label: const Text('Sign out'),
                ),
                const SizedBox(height: 24),
              ],
            ),
    );
  }

  // ------------------------------------------------------------------
  // User card
  // ------------------------------------------------------------------

  Widget _userCard(User user, SessionController session) {
    final scheme = Theme.of(context).colorScheme;
    final initial =
        (user.displayName.isEmpty ? '?' : user.displayName[0]).toUpperCase();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  radius: 26,
                  backgroundColor: scheme.primaryContainer,
                  child: Text(
                    initial,
                    style: Theme.of(context)
                        .textTheme
                        .headlineSmall
                        ?.copyWith(
                            color: scheme.primary,
                            fontWeight: FontWeight.w800),
                  ),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        user.displayName,
                        style: Theme.of(context)
                            .textTheme
                            .titleMedium
                            ?.copyWith(fontWeight: FontWeight.w800),
                      ),
                      Text(
                        user.email,
                        style: Theme.of(context)
                            .textTheme
                            .bodySmall
                            ?.copyWith(color: scheme.onSurfaceVariant),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  tooltip: 'Edit name',
                  icon: const Icon(Icons.edit_outlined),
                  onPressed: () => _editName(user),
                ),
              ],
            ),
            const Divider(height: 20),
            Wrap(
              spacing: 8,
              runSpacing: 6,
              children: [
                _badge(scheme, user.isAdmin ? 'ADMIN' : 'USER',
                    user.isAdmin ? const Color(0xFFE07B2D) : scheme.primary),
                _badge(scheme, user.isVerified ? 'VERIFIED' : 'UNVERIFIED',
                    user.isVerified ? const Color(0xFF2FA84F) : const Color(0xFF8A93A6)),
                _badge(scheme, user.isActive ? 'ACTIVE' : 'DISABLED',
                    user.isActive ? const Color(0xFF2FA84F) : const Color(0xFFD64545)),
              ],
            ),
            const SizedBox(height: 10),
            _row('Member since',
                user.createdAt == null ? '—' : DateFormat('MMM d, yyyy').format(user.createdAt!)),
            _row(
                'Last login',
                user.lastLoginAt == null
                    ? '—'
                    : DateFormat('MMM d, yyyy HH:mm').format(user.lastLoginAt!)),
          ],
        ),
      ),
    );
  }

  Future<void> _editName(User user) async {
    final session = AppScope.of(context);
    final controller = TextEditingController(text: user.fullName ?? '');
    final saved = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Edit display name'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'Full name'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (saved != true) return;
    final name = controller.text.trim();
    try {
      await session.api
          .patchJson('/api/v1/users/me', body: {'full_name': name});
      await session.refreshUser();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Profile updated.')));
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  Widget _apiKeyModeBanner(ColorScheme scheme) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.tertiaryContainer.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Icon(Icons.vpn_key_rounded, color: scheme.onTertiaryContainer),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'Signed in with an API key. Password, refresh and logout are '
              'managed through the key\'s lifecycle.',
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
  // Change password
  // ------------------------------------------------------------------

  Widget _passwordCard(SessionController session) {
    if (session.usesApiKey) return const SizedBox.shrink();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Change password',
                style: Theme.of(context)
                    .textTheme
                    .titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 4),
            Text(
              'Passwords must be at least ${AppConfig.passwordMinLength} '
              'characters. Rotating it revokes other sessions best-effort.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant),
            ),
            const SizedBox(height: 14),
            _PasswordForm(api: session.api),
          ],
        ),
      ),
    );
  }

  // ------------------------------------------------------------------
  // API keys
  // ------------------------------------------------------------------

  Widget _apiKeysCard(SessionController session) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text('API keys',
                      style: Theme.of(context)
                          .textTheme
                          .titleSmall
                          ?.copyWith(fontWeight: FontWeight.w700)),
                ),
                FilledButton.tonalIcon(
                  onPressed: () => _createApiKey(session),
                  icon: const Icon(Icons.add_rounded, size: 18),
                  label: const Text('Create'),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              'Plaintext is shown exactly once at creation — it cannot be '
              'recovered later, by anyone.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 12),
            if (_loadingKeys && _keys == null)
              const Padding(
                padding: EdgeInsets.all(8),
                child: LinearProgressIndicator(),
              )
            else if (_keysError != null && _keys == null)
              ErrorView(message: _keysError!, onRetry: _loadKeys)
            else if (_keys == null || _keys!.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 10),
                child: Text('No API keys yet.',
                    style: TextStyle(color: scheme.onSurfaceVariant)),
              )
            else
              ..._keys!.map((k) => _keyTile(session, k)),
          ],
        ),
      ),
    );
  }

  Future<void> _createApiKey(SessionController session) async {
    final name = TextEditingController();
    final days = TextEditingController();
    const defaultScopes = ['scan:read'];
    final scopes = List<String>.from(defaultScopes);

    final created = await showDialog<bool?>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) {
          void toggleScope(String scope, bool on) {
            setDialogState(() {
              if (on) {
                if (!scopes.contains(scope)) scopes.add(scope);
              } else {
                scopes.remove(scope);
              }
            });
          }

          return AlertDialog(
            title: const Text('Create API key'),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(
                    controller: name,
                    autofocus: true,
                    decoration: const InputDecoration(
                      labelText: 'Key name',
                      hintText: 'e.g. CI pipeline',
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: days,
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                      labelText: 'Expires in days (1–365, empty = default)',
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text('Scopes',
                      style: Theme.of(context).textTheme.labelMedium),
                  for (final scope in const [
                    'scan:read',
                    'scan:write',
                    'quarantine:read',
                    'quarantine:write',
                  ])
                    CheckboxListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      title: Text(scope, style: const TextStyle(fontSize: 13)),
                      value: scopes.contains(scope),
                      onChanged: (v) => toggleScope(scope, v ?? false),
                    ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(context).pop(false),
                child: const Text('Cancel'),
              ),
              FilledButton(
                onPressed: () => Navigator.of(context).pop(true),
                child: const Text('Create'),
              ),
            ],
          );
        },
      ),
    );
    if (created != true) return;
    if (!mounted) return;

    final keyName = name.text.trim();
    if (keyName.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Give the key a name.')));
      return;
    }
    if (scopes.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Pick at least one scope.')));
      return;
    }
    final parsedDays = int.tryParse(days.text.trim());
    final body = <String, dynamic>{
      'name': keyName,
      'scopes': scopes,
    };
    if (parsedDays != null) body['expires_in_days'] = parsedDays;

    try {
      final data = await session.api.postJson('/api/v1/api-keys', body: body);
      if (!mounted) return;
      final key = ApiKeyItem.fromJson(
          Map<String, dynamic>.from(data as Map));
      _loadKeys();
      await _showPlaintext(key);
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(e.message)));
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Could not create the API key.')));
    }
  }

  Future<void> _showPlaintext(ApiKeyItem key) async {
    final plaintext = key.plaintext;
    if (plaintext == null) return;
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        icon: Icon(Icons.warning_amber_rounded,
            color: Theme.of(context).colorScheme.tertiary),
        title: const Text('Key created'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'This is the only time the full key is shown. Store it now — '
              'it cannot be recovered later.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            SelectableText(
              plaintext,
              style: const TextStyle(
                  fontFamily: 'monospace', fontWeight: FontWeight.w600),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () async {
              await _copyToClipboard(plaintext);
              if (context.mounted) Navigator.of(context).pop();
            },
            child: const Text('Copy & close'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Done'),
          ),
        ],
      ),
    );
  }

  Future<void> _copyToClipboard(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(const SnackBar(content: Text('Copied.')));
  }

  Future<void> _revokeKey(SessionController session, ApiKeyItem key) async {
    final confirmed = await _confirm(
      title: 'Revoke ${key.name}?',
      body: 'Authentication with this key stops immediately. The key cannot '
          'be re-enabled.',
      action: 'Revoke',
      destructive: true,
    );
    if (confirmed != true || !mounted) return;
    try {
      await session.api
          .postJson('/api/v1/api-keys/${key.id}/revoke', body: const {});
      _loadKeys();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Key ${key.name} revoked.')));
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  // ------------------------------------------------------------------
  // Admin
  // ------------------------------------------------------------------

  Widget _adminCard(SessionController session) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.admin_panel_settings_outlined,
                    size: 20, color: scheme.error),
                const SizedBox(width: 8),
                Expanded(
                  child: Text('Administration',
                      style: Theme.of(context)
                          .textTheme
                          .titleSmall
                          ?.copyWith(fontWeight: FontWeight.w700)),
                ),
                FilledButton.tonalIcon(
                  onPressed: () => _createUser(session),
                  icon: const Icon(Icons.person_add_alt_1_rounded, size: 18),
                  label: const Text('Create user'),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              'Create accounts and deactivate users. Deactivation is a '
              'soft-delete that disables login immediately.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 12),
            if (_loadingUsers && _users == null)
              const Padding(
                padding: EdgeInsets.all(8),
                child: LinearProgressIndicator(),
              )
            else if (_usersError != null && _users == null)
              ErrorView(message: _usersError!, onRetry: _loadUsers)
            else if (_users == null)
              const SizedBox.shrink()
            else
              ..._users!.map((u) => _userRow(session, u)),
          ],
        ),
      ),
    );
  }

  Future<void> _createUser(SessionController session) async {
    final email = TextEditingController();
    final name = TextEditingController();
    final password = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Create account'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: email,
                keyboardType: TextInputType.emailAddress,
                decoration: const InputDecoration(labelText: 'Email'),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: name,
                decoration: const InputDecoration(labelText: 'Full name'),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: password,
                obscureText: true,
                decoration: InputDecoration(
                  labelText:
                      'Password (min ${AppConfig.passwordMinLength} chars)',
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Create'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await session.api.postJson('/api/v1/users', body: {
        'email': email.text.trim(),
        'password': password.text,
        if (name.text.trim().isNotEmpty) 'full_name': name.text.trim(),
      });
      _loadUsers();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Account created for ${email.text.trim()}.')));
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  Widget _userRow(SessionController session, User u) {
    final scheme = Theme.of(context).colorScheme;
    final isSelf = session.user?.id == u.id;
    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      leading: CircleAvatar(
        radius: 16,
        backgroundColor: scheme.surfaceContainerHighest,
        child: Text(
          (u.displayName.isNotEmpty ? u.displayName[0] : '?').toUpperCase(),
          style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
        ),
      ),
      title: Text(u.displayName),
      subtitle: Text(u.email,
          style: Theme.of(context).textTheme.bodySmall),
      trailing: Wrap(
        spacing: 6,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          if (u.isAdmin)
            _badge(scheme, 'ADMIN', const Color(0xFFE07B2D)),
          if (!u.isActive)
            _badge(scheme, 'DISABLED', const Color(0xFFD64545)),
          if (!isSelf)
            IconButton(
              tooltip: u.isActive ? 'Deactivate' : 'Deactivated',
              onPressed: u.isActive
                  ? () => _deactivateUser(session, u)
                  : null,
              icon: Icon(
                u.isActive
                    ? Icons.person_off_outlined
                    : Icons.person_off_rounded,
                size: 20,
                color: u.isActive
                    ? scheme.error
                    : scheme.outline,
              ),
            ),
        ],
      ),
    );
  }

  Future<void> _deactivateUser(SessionController session, User u) async {
    final confirmed = await _confirm(
      title: 'Deactivate ${u.email}?',
      body: 'The account is soft-deleted: they can no longer sign in. '
          'Existing access tokens stop working.',
      action: 'Deactivate',
      destructive: true,
    );
    if (confirmed != true || !mounted) return;
    try {
      await session.api.delete('/api/v1/users/${u.id}');
      _loadUsers();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('${u.email} deactivated.')));
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  // ------------------------------------------------------------------
  // Shared
  // ------------------------------------------------------------------

  Future<void> _confirmLogout() async {
    final session = AppScope.of(context);
    final confirmed = await _confirm(
      title: 'Sign out?',
      body: session.usesApiKey
          ? 'The API key will be removed from this device.'
          : 'Your access token is revoked on the server and refreshed tokens '
              'are cleared from this device.',
      action: 'Sign out',
      destructive: false,
    );
    if (confirmed == true) await session.logout();
  }

  Future<bool?> _confirm({
    required String title,
    required String body,
    required String action,
    required bool destructive,
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
            style: destructive
                ? FilledButton.styleFrom(
                    backgroundColor: Theme.of(context).colorScheme.error,
                    foregroundColor: Theme.of(context).colorScheme.onError,
                  )
                : null,
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(action),
          ),
        ],
      ),
    );
  }

  Widget _badge(ColorScheme scheme, String text, Color color) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.14),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: color.withValues(alpha: 0.5)),
        ),
        child: Text(
          text,
          style: TextStyle(
            color: color,
            fontSize: 10,
            fontWeight: FontWeight.w800,
            letterSpacing: 0.8,
          ),
        ),
      );

  Widget _row(String label, String value) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          children: [
            SizedBox(
              width: 110,
              child: Text(label,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant)),
            ),
            Expanded(
              child: Text(value,
                  style: Theme.of(context).textTheme.bodySmall),
            ),
          ],
        ),
      );

  Widget _keyTile(SessionController session, ApiKeyItem key) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: scheme.outlineVariant.withValues(alpha: 0.5)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  key.name,
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
              ),
              if (!key.isActive)
                _badge(scheme, 'REVOKED', const Color(0xFFD64545))
              else if (key.expiresAt != null &&
                  key.expiresAt!.isBefore(DateTime.now()))
                _badge(scheme, 'EXPIRED', const Color(0xFFE8A33D))
              else
                _badge(scheme, 'ACTIVE', const Color(0xFF2FA84F)),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            key.masked,
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(fontFamily: 'monospace'),
          ),
          const SizedBox(height: 6),
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: key.scopes
                .map((s) => Chip(
                      visualDensity: VisualDensity.compact,
                      label: Text(s, style: const TextStyle(fontSize: 10)),
                    ))
                .toList(),
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              Expanded(
                child: Text(
                  'Created '
                  '${key.createdAt == null ? '—' : DateFormat('MMM d, yyyy').format(key.createdAt!)}'
                  '${key.expiresAt == null ? '' : ' · expires ${DateFormat('MMM d, yyyy').format(key.expiresAt!)}'}',
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: scheme.onSurfaceVariant),
                ),
              ),
              if (key.isActive)
                TextButton(
                  onPressed: () => _revokeKey(session, key),
                  child: const Text('Revoke'),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

/// Change-password form with the advisory strength meter.
class _PasswordForm extends StatefulWidget {
  const _PasswordForm({required this.api});
  final ApiClient api;

  @override
  State<_PasswordForm> createState() => _PasswordFormState();
}

class _PasswordFormState extends State<_PasswordForm> {
  final _formKey = GlobalKey<FormState>();
  final _current = TextEditingController();
  final _newPassword = TextEditingController();
  final _confirm = TextEditingController();
  bool _busy = false;
  bool _obscure = true;

  @override
  void dispose() {
    _current.dispose();
    _newPassword.dispose();
    _confirm.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    if (!_formKey.currentState!.validate()) return;
    setState(() => _busy = true);
    try {
      await session.api.postJson('/api/v1/auth/change-password', body: {
        'current_password': _current.text,
        'new_password': _newPassword.text,
      });
      if (!mounted) return;
      messenger.showSnackBar(
          const SnackBar(content: Text('Password changed.')));
      _current.clear();
      _newPassword.clear();
      _confirm.clear();
    } on ApiException catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Form(
      key: _formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextFormField(
            controller: _current,
            enabled: !_busy,
            obscureText: _obscure,
            decoration: const InputDecoration(
              labelText: 'Current password',
              prefixIcon: Icon(Icons.lock_outline_rounded),
            ),
            validator: (v) =>
                (v == null || v.isEmpty) ? 'Enter your current password.' : null,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _newPassword,
            enabled: !_busy,
            obscureText: _obscure,
            decoration: InputDecoration(
              labelText: 'New password',
              prefixIcon: const Icon(Icons.lock_reset_rounded),
              suffixIcon: IconButton(
                icon: Icon(
                    _obscure ? Icons.visibility_outlined : Icons.visibility_off_outlined),
                onPressed: () => setState(() => _obscure = !_obscure),
              ),
            ),
            validator: (v) {
              final value = v ?? '';
              if (value.isEmpty) return 'Enter a new password.';
              if (value.length < AppConfig.passwordMinLength) {
                return 'At least ${AppConfig.passwordMinLength} characters.';
              }
              return null;
            },
          ),
          const SizedBox(height: 8),
          PasswordStrengthMeter(
            api: widget.api,
            passwordController: _newPassword,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _confirm,
            enabled: !_busy,
            obscureText: _obscure,
            decoration: const InputDecoration(
              labelText: 'Confirm new password',
              prefixIcon: Icon(Icons.lock_reset_rounded),
            ),
            validator: (v) =>
                v != _newPassword.text ? 'Passwords do not match.' : null,
          ),
          const SizedBox(height: 14),
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.tonal(
              onPressed: _busy ? null : _submit,
              child: _busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2.2),
                    )
                  : const Text('Change password'),
            ),
          ),
        ],
      ),
    );
  }
}

/// Shown in place of the profile when the session is not authenticated.
///
/// This build has no login *screen* — instead a sign-in bottom sheet (from
/// here or from the Status page) starts a remembered session. The view is
/// honest: it never fakes a session or reports a user that isn't there.
class _SignedOutView extends StatelessWidget {
  const _SignedOutView();

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.shield_outlined, size: 44, color: scheme.primary),
                const SizedBox(height: 12),
                Text(
                  'Not signed in',
                  style: Theme.of(context)
                      .textTheme
                      .titleMedium
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 8),
                Text(
                  'There is no login screen in this build. Sign in below '
                  '(or from the Status page) and the session is remembered '
                  'on this device.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: 10),
                SelectableText(
                  AppConfig.apiBaseUrl,
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.primary),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: () => showSignInSheet(context),
                  icon: const Icon(Icons.login_rounded, size: 18),
                  label: const Text('Sign in'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

