import 'package:flutter/material.dart';

import '../core/app_errors.dart';
import '../core/api_exception.dart';

/// Compact inline error banner. Shows only friendly text — never raw backend
/// messages, exception text or stack traces.
class AppErrorBanner extends StatelessWidget {
  const AppErrorBanner({
    super.key,
    required this.message,
    this.onRetry,
    this.dismissible = false,
  });

  final String message;
  final VoidCallback? onRetry;
  final bool dismissible;

  static AppErrorBanner from(BuildContext context, ApiException error,
      {required bool signedIn, VoidCallback? onRetry}) {
    return AppErrorBanner(
      message: friendlyAppError(error, signedIn: signedIn),
      onRetry: onRetry,
    );
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      color: scheme.errorContainer,
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 6, 8, 6),
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
            if (onRetry != null)
              TextButton(
                onPressed: onRetry,
                style: TextButton.styleFrom(
                    foregroundColor: scheme.onErrorContainer),
                child: const Text('Retry'),
              ),
          ],
        ),
      ),
    );
  }
}

/// Centred friendly error state with an optional retry action. Used for full
/// screens (History, Quarantine, Home…) when a section has no data to show.
class AppErrorState extends StatelessWidget {
  const AppErrorState({
    super.key,
    required this.message,
    this.details,
    this.onRetry,
    this.title,
    this.icon,
  });

  final String message;
  final String? details;
  final VoidCallback? onRetry;
  final String? title;
  final IconData? icon;

  static AppErrorState from(BuildContext context, ApiException error,
      {required bool signedIn, VoidCallback? onRetry}) {
    return AppErrorState(
      message: friendlyAppError(error, signedIn: signedIn),
      onRetry: onRetry,
    );
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon ?? Icons.error_outline_rounded,
                  size: 40, color: scheme.error),
              if (title != null) ...[
                const SizedBox(height: 10),
                Text(title!,
                    textAlign: TextAlign.center,
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(fontWeight: FontWeight.w700)),
              ],
              const SizedBox(height: 8),
              Text(
                message,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              if (details != null && details!.isNotEmpty) ...[
                const SizedBox(height: 6),
                Text(
                  details!,
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
              if (onRetry != null) ...[
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: onRetry,
                  icon: const Icon(Icons.refresh_rounded),
                  label: const Text('Retry'),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// Shown in place of an authenticated section when the partner service is
/// unreachable — distinct from authentication errors.
class OfflineState extends StatelessWidget {
  const OfflineState({super.key, this.onRetry});

  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.cloud_off_rounded, size: 44, color: scheme.outline),
            const SizedBox(height: 12),
            Text(
              offlineMessage,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            if (onRetry != null) ...[
              const SizedBox(height: 14),
              FilledButton.icon(
                onPressed: onRetry,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('Retry'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}