import 'package:flutter/material.dart';

/// Shared submit row for scan forms: quick + async toggles and the scan
/// button.
class ScanSubmitSection extends StatelessWidget {
  const ScanSubmitSection({
    super.key,
    required this.quick,
    required this.asyncMode,
    required this.onQuickChanged,
    required this.onAsyncChanged,
    required this.onSubmit,
    required this.busy,
    this.submitLabel = 'Scan',
    this.extra,
  });

  final bool quick;
  final bool asyncMode;
  final ValueChanged<bool> onQuickChanged;
  final ValueChanged<bool> onAsyncChanged;
  final VoidCallback onSubmit;
  final bool busy;
  final String submitLabel;
  final Widget? extra;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SwitchListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              title: const Text('Quick mode'),
              subtitle: const Text(
                  'Skips the slowest checks for a faster result.'),
              value: quick,
              onChanged: busy ? null : onQuickChanged,
            ),
            SwitchListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              title: const Text('Run in background'),
              subtitle: const Text(
                  'Submit asynchronously and poll until it completes.'),
              value: asyncMode,
              onChanged: busy ? null : onAsyncChanged,
            ),
            ?extra,
            const Divider(height: 8),
            FilledButton.icon(
              onPressed: busy ? null : onSubmit,
              style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 14),
              ),
              icon: busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2.2),
                    )
                  : Icon(
                      asyncMode
                          ? Icons.schedule_rounded
                          : Icons.shield_rounded,
                      size: 20,
                    ),
              label: Text(busy
                  ? 'Scanning…'
                  : asyncMode
                      ? '$submitLabel (background)'
                      : submitLabel),
            ),
            const SizedBox(height: 6),
            Text(
              asyncMode
                  ? 'You can leave this screen; the report will be available '
                      'under History once it finishes.'
                  : 'Files and APKs are analysed statically — nothing is '
                      'executed.',
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