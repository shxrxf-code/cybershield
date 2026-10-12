/// Inline sign-in sheet — the only authentication entry point in this build.
///
/// The login *screen* was removed, so instead of a dedicated page the app
/// offers a bottom sheet that can be opened from the Status page (first-run
/// prompt) or the Profile page. Credentials and API keys use the same
/// `POST /api/v1/auth/login` / `X-API-Key` flows as before; the session is
/// remembered in the secure store when "remember" is on.
library;

import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/app_errors.dart';
import '../../core/config.dart';

/// Opens the sign-in bottom sheet.
Future<void> showSignInSheet(BuildContext context) {
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    showDragHandle: true,
    useSafeArea: true,
    builder: (_) => const SignInSheet(),
  );
}

enum _SignInMode { credentials, apiKey }

class SignInSheet extends StatefulWidget {
  const SignInSheet({super.key});

  @override
  State<SignInSheet> createState() => _SignInSheetState();
}

class _SignInSheetState extends State<SignInSheet> {
  _SignInMode _mode = _SignInMode.credentials;
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _apiKey = TextEditingController();
  bool _remember = true;
  bool _obscure = true;
  bool _submitting = false;
  String? _error;

  /// A dev-only convenience: when demo login is enabled (see [AppConfig]) the
  /// sign-in sheet arrives pre-filled so a reviewer can start a session with a
  /// single tap. Set ``--dart-define=DEMO_LOGIN=false`` for real builds.
  bool get _demoPrefill => AppConfig.demoLogin;

  @override
  void initState() {
    super.initState();
    if (_demoPrefill) {
      _email.text = AppConfig.demoEmail;
      _password.text = AppConfig.demoPassword;
    }
  }

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    _apiKey.dispose();
    super.dispose();
  }

  bool get _canSubmit {
    if (_submitting) return false;
    if (_mode == _SignInMode.credentials) {
      return _email.text.contains('@') && _password.text.isNotEmpty;
    }
    return _apiKey.text.trim().isNotEmpty;
  }

  Future<void> _submit() async {
    final session = AppScope.of(context);
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      if (_mode == _SignInMode.credentials) {
        await session.signInWithPassword(
          email: _email.text,
          password: _password.text,
          remember: _remember,
        );
      } else {
        await session.signInWithApiKey(_apiKey.text, remember: _remember);
      }
      if (!mounted) return;
      Navigator.of(context).pop();
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        // Never surface backend/JWT text. A 401 on the sign-in form means the
        // credential was rejected; everything else maps through the central
        // friendly-error table.
        _error = e.isUnauthorized
            ? (_mode == _SignInMode.credentials
                ? 'Incorrect email or password.'
                : 'That API key was not accepted.')
            : friendlyAppError(e, signedIn: false);
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        _error = 'Could not reach the server. Check the API base URL.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final bottomInset = MediaQuery.viewInsetsOf(context).bottom;
    return Padding(
      padding: EdgeInsets.fromLTRB(20, 4, 20, 20 + bottomInset),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Sign in',
              style: Theme.of(context)
                  .textTheme
                  .titleLarge
                  ?.copyWith(fontWeight: FontWeight.w800),
            ),
            const SizedBox(height: 4),
            Text(
              'Scans, history and quarantine are stored per account on the '
              'server (API base: ${AppConfig.apiBaseUrl}). This build has no '
              'login screen — sign in here once and the session is remembered '
              'on this device.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 16),
            SegmentedButton<_SignInMode>(
              segments: const [
                ButtonSegment(
                  value: _SignInMode.credentials,
                  label: Text('Credentials'),
                  icon: Icon(Icons.person_outline_rounded, size: 18),
                ),
                ButtonSegment(
                  value: _SignInMode.apiKey,
                  label: Text('API key'),
                  icon: Icon(Icons.key_rounded, size: 18),
                ),
              ],
              selected: {_mode},
              onSelectionChanged: (selection) => setState(() {
                _mode = selection.first;
                _error = null;
              }),
            ),
            const SizedBox(height: 16),
            if (_mode == _SignInMode.credentials) ...[
              if (_demoPrefill) ...[
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  decoration: BoxDecoration(
                    color: scheme.primaryContainer,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.bolt_rounded,
                          size: 18, color: scheme.onPrimaryContainer),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Demo credentials are pre-filled — just tap Sign in.',
                          style: TextStyle(color: scheme.onPrimaryContainer),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
              ],
              TextField(
                controller: _email,
                enabled: !_submitting,
                keyboardType: TextInputType.emailAddress,
                autocorrect: false,
                textInputAction: TextInputAction.next,
                onChanged: (_) => setState(() {}),
                decoration: const InputDecoration(
                  labelText: 'Email',
                  hintText: 'you@example.com',
                  prefixIcon: Icon(Icons.mail_outline_rounded, size: 20),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _password,
                enabled: !_submitting,
                obscureText: true,
                textInputAction: TextInputAction.done,
                onChanged: (_) => setState(() {}),
                onSubmitted: (_) {
                  if (_canSubmit) _submit();
                },
                decoration: const InputDecoration(
                  labelText: 'Password',
                  hintText: 'Your password',
                  prefixIcon: Icon(Icons.lock_outline_rounded, size: 20),
                ),
              ),
            ] else ...[
              TextField(
                controller: _apiKey,
                enabled: !_submitting,
                obscureText: _obscure,
                autocorrect: false,
                textInputAction: TextInputAction.done,
                onChanged: (_) => setState(() {}),
                onSubmitted: (_) {
                  if (_canSubmit) _submit();
                },
                decoration: InputDecoration(
                  labelText: 'API key',
                  prefixIcon: const Icon(Icons.key_rounded, size: 20),
                  suffixIcon: IconButton(
                    tooltip: _obscure ? 'Show' : 'Hide',
                    icon: Icon(
                      _obscure
                          ? Icons.visibility_outlined
                          : Icons.visibility_off_outlined,
                      size: 20,
                    ),
                    onPressed: () => setState(() => _obscure = !_obscure),
                  ),
                  helperText: 'Create a key in Profile → API keys.',
                ),
              ),
            ],
            const SizedBox(height: 8),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Remember this device'),
              subtitle: const Text('Keeps the session in the secure store '
                  'so the app starts signed in.'),
              value: _remember,
              onChanged: _submitting
                  ? null
                  : (v) => setState(() => _remember = v),
            ),
            if (_error != null) ...[
              const SizedBox(height: 8),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                decoration: BoxDecoration(
                  color: scheme.errorContainer,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Row(
                  children: [
                    Icon(Icons.error_outline_rounded,
                        size: 18, color: scheme.onErrorContainer),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _error!,
                        style: TextStyle(color: scheme.onErrorContainer),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 14),
            SizedBox(
              width: double.infinity,
              child: FilledButton(
                onPressed: _canSubmit ? _submit : null,
                child: _submitting
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2.2),
                      )
                    : const Text('Sign in'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// First-run prompt shown on the Status page so users can start a session
/// without a dedicated login screen. Hidden once signed in.
class SignInPromptCard extends StatelessWidget {
  const SignInPromptCard({super.key, required this.onSignIn});

  final VoidCallback onSignIn;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      color: scheme.primaryContainer,
      child: LayoutBuilder(
        builder: (context, constraints) {
          final button = FilledButton.icon(
            onPressed: onSignIn,
            icon: const Icon(Icons.login_rounded, size: 18),
            label: const Text('Sign in'),
          );
          return Padding(
            padding: const EdgeInsets.all(14),
            child: constraints.maxWidth < 420
                ? Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _graphic(scheme),
                      const SizedBox(height: 12),
                      _texts(context),
                      const SizedBox(height: 12),
                      SizedBox(width: double.infinity, child: button),
                    ],
                  )
                : Row(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      _graphic(scheme),
                      const SizedBox(width: 14),
                      Expanded(child: _texts(context)),
                      const SizedBox(width: 12),
                      button,
                    ],
                  ),
          );
        },
      ),
    );
  }

  Widget _graphic(ColorScheme scheme) {
    return Container(
      width: 46,
      height: 46,
      decoration: BoxDecoration(
        color: scheme.primary,
        borderRadius: BorderRadius.circular(13),
      ),
      child: Icon(Icons.lock_open_rounded, color: scheme.onPrimary, size: 24),
    );
  }

  Widget _texts(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Sign in to store scans',
          style: Theme.of(context)
              .textTheme
              .titleSmall
              ?.copyWith(fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 2),
        Text(
          'Scans, history and quarantine are kept per account. There is no '
          'login screen — start a remembered session here.',
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
      ],
    );
  }
}