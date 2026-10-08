import 'package:flutter/material.dart';

import '../core/scan_state.dart';
import 'scan_shield_animation.dart';

/// Phase-aware scan button. Every scan entry-point goes through this so the
/// button never appears frozen after a tap: it is disabled and animated the
/// moment the scan is running, then flips to a terminal state.
class ScanButton extends StatelessWidget {
  const ScanButton({
    super.key,
    required this.phase,
    required this.onPressed,
    this.label = 'Scan',
    this.icon = Icons.shield_outlined,
    this.expanded = false,
    this.fillColor,
    this.foregroundColor,
  });

  final ScanPhase phase;
  final VoidCallback onPressed;
  final String label;
  final IconData icon;
  final bool expanded;
  final Color? fillColor;
  final Color? foregroundColor;

  @override
  Widget build(BuildContext context) {
    Widget child;
    switch (phase) {
      case ScanPhase.idle:
        child = FilledButton.icon(
          onPressed: onPressed,
          icon: Icon(icon, size: 20),
          label: Text(label),
          style: FilledButton.styleFrom(
            minimumSize: const Size(64, 52),
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
            backgroundColor: fillColor,
            foregroundColor: foregroundColor,
          ),
        );
      case ScanPhase.initializing ||
            ScanPhase.queued ||
            ScanPhase.scanning ||
            ScanPhase.analyzing:
        child = FilledButton(
          onPressed: null,
          style: FilledButton.styleFrom(
            minimumSize: const Size(64, 52),
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
            backgroundColor: fillColor,
            foregroundColor: foregroundColor,
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const SizedBox(
                width: 22,
                height: 22,
                child: ScanShieldAnimation(size: 22),
              ),
              const SizedBox(width: 10),
              Text('${phase.label}…'),
            ],
          ),
        );
      case ScanPhase.threatFound || ScanPhase.completed:
        child = FilledButton.icon(
          onPressed: onPressed,
          icon: Icon(
            phase == ScanPhase.threatFound
                ? Icons.warning_amber_rounded
                : Icons.check_circle_rounded,
            size: 20,
          ),
          label: Text(phase == ScanPhase.threatFound
              ? 'Threats found'
              : 'Scan complete'),
          style: FilledButton.styleFrom(
            minimumSize: const Size(64, 52),
            backgroundColor: fillColor,
            foregroundColor: foregroundColor,
          ),
        );
      case ScanPhase.cancelled:
        child = OutlinedButton.icon(
          onPressed: onPressed,
          icon: const Icon(Icons.refresh_rounded, size: 20),
          label: const Text('Scan again'),
        );
      case ScanPhase.failed:
        child = FilledButton.icon(
          onPressed: onPressed,
          icon: const Icon(Icons.refresh_rounded, size: 20),
          label: const Text('Try again'),
          style: FilledButton.styleFrom(
            minimumSize: const Size(64, 52),
            backgroundColor: fillColor,
            foregroundColor: foregroundColor,
          ),
        );
    }
    if (expanded) {
      return SizedBox(width: double.infinity, child: child);
    }
    return child;
  }
}