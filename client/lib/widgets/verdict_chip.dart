import 'package:flutter/material.dart';

import '../core/models/enums.dart';
import 'verdict_style.dart';

/// A verdict chip coloured by risk.
class VerdictChip extends StatelessWidget {
  const VerdictChip({super.key, required this.verdict, this.compact = false});

  final Verdict verdict;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final brightness = Theme.of(context).brightness;
    final color = verdictColorFor(verdict);
    return Container(
      padding: EdgeInsets.symmetric(
          horizontal: compact ? 8 : 12, vertical: compact ? 3 : 5),
      decoration: BoxDecoration(
        color: verdictFillFor(verdict, brightness: brightness),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.55)),
      ),
      child: Text(
        verdict.label.toUpperCase(),
        style: TextStyle(
          color: color,
          fontSize: compact ? 10 : 12,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.8,
        ),
      ),
    );
  }
}

/// A neutral status chip (QUEUED / SCANNING / COMPLETED / FAILED ...).
class StatusChip extends StatelessWidget {
  const StatusChip({super.key, required this.status, this.compact = false});

  final ScanStatus status;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final brightness = Theme.of(context).brightness;
    final Color color = switch (status) {
      ScanStatus.completed => const Color(0xFF2FA84F),
      ScanStatus.failed => const Color(0xFFD64545),
      ScanStatus.queued ||
      ScanStatus.scanning ||
      ScanStatus.analyzing =>
        const Color(0xFF4E9BE8),
      ScanStatus.unknown => const Color(0xFF8A93A6),
    };
    return Container(
      padding: EdgeInsets.symmetric(
          horizontal: compact ? 8 : 10, vertical: compact ? 3 : 4),
      decoration: BoxDecoration(
        color: color.withValues(
            alpha: brightness == Brightness.dark ? 0.22 : 0.14),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Text(
        status.label.toUpperCase(),
        style: TextStyle(
          color: color,
          fontSize: compact ? 10 : 11,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.6,
        ),
      ),
    );
  }
}