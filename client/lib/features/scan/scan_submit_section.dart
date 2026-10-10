import 'package:flutter/material.dart';

import '../../core/scan_state.dart';
import '../../widgets/scan_button.dart';

/// Shared submit row for scan forms: quick + async toggles and the
/// phase-driven [ScanButton]. The scan button reflects the central
/// [SecurityScan] state machine, so it animates the moment a scan starts and
/// never appears frozen.
class ScanSubmitSection extends StatelessWidget {
  const ScanSubmitSection({
    super.key,
    required this.quick,
    required this.asyncMode,
    required this.onQuickChanged,
    required this.onAsyncChanged,
    required this.onSubmit,
    required this.phase,
    this.submitLabel = 'Scan',
    this.extra,
  });

  final bool quick;
  final bool asyncMode;
  final ValueChanged<bool> onQuickChanged;
  final ValueChanged<bool> onAsyncChanged;
  final VoidCallback onSubmit;
  final ScanPhase phase;
  final String submitLabel;
  final Widget? extra;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final running = phase.isRunning;
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
              onChanged: running ? null : onQuickChanged,
            ),
            SwitchListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              title: const Text('Run in background'),
              subtitle: const Text(
                  'Submit asynchronously and poll until it completes.'),
              value: asyncMode,
              onChanged: running ? null : onAsyncChanged,
            ),
            ?extra,
            const Divider(height: 8),
            ScanButton(
              phase: phase,
              onPressed: running ? () {} : onSubmit,
              label: asyncMode ? '$submitLabel (background)' : submitLabel,
              icon: asyncMode ? Icons.schedule_rounded : Icons.shield_rounded,
              expanded: true,
            ),
            const SizedBox(height: 6),
            Text(
              running
                  ? '${phase.label}… you can watch live on this page or leave '
                      'and find it under History once it finishes.'
                  : asyncMode
                      ? 'You can leave this screen; the report will be '
                          'available under History once it finishes.'
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