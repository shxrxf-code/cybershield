import 'package:flutter/material.dart';

/// Honest signed-out state: shown on authenticated screens (History,
/// Quarantine, Profile…) when no session is stored. It never fakes content —
/// it asks the user to start a session via the same in-app sign-in sheet used
/// on the Home page.
class SignedOutState extends StatelessWidget {
  const SignedOutState({
    super.key,
    this.title = 'Sign in to continue',
    this.message =
        'This content is stored per account on the CyberShield service.',
    required this.onSignIn,
  });

  final String title;
  final String message;
  final VoidCallback onSignIn;

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
                  title,
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .titleMedium
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 8),
                Text(
                  message,
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: onSignIn,
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