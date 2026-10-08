import 'package:flutter/material.dart';

import '../../core/models/scan.dart';

Color severityColor(String severity) => switch (severity) {
      'CRITICAL' => const Color(0xFFD64545),
      'HIGH' => const Color(0xFFE07B2D),
      'MEDIUM' => const Color(0xFFE8A33D),
      'LOW' => const Color(0xFF4E9BE8),
      'INFO' => const Color(0xFF8A93A6),
      _ => const Color(0xFF8A93A6),
    };

/// One detection signal, with a severity accent, provenance and evidence.
class SignalTile extends StatelessWidget {
  const SignalTile({super.key, required this.signal});

  final DetectionSignal signal;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = severityColor(signal.severity);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: scheme.outlineVariant.withValues(alpha: 0.5)),
      ),
      child: IntrinsicHeight(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(width: 4, color: color),
            Expanded(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          child: Text(
                            signal.title,
                            style: Theme.of(context)
                                .textTheme
                                .titleSmall
                                ?.copyWith(fontWeight: FontWeight.w700),
                          ),
                        ),
                        const SizedBox(width: 8),
                        _chip(color, signal.severity),
                      ],
                    ),
                    if (signal.description.isNotEmpty) ...[
                      const SizedBox(height: 4),
                      Text(
                        signal.description,
                        style: Theme.of(context)
                            .textTheme
                            .bodySmall
                            ?.copyWith(color: scheme.onSurfaceVariant),
                      ),
                    ],
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 8,
                      runSpacing: 4,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        _meta(context, '${signal.source} · ${signal.category}'),
                        const SizedBox(width: 4),
                        _meta(
                            context, 'confidence ${(signal.confidence * 100).round()}%'),
                        if (signal.code.isNotEmpty) _meta(context, signal.code),
                      ],
                    ),
                    if (signal.indicators.isNotEmpty) ...[
                      const SizedBox(height: 8),
                      Wrap(
                        spacing: 6,
                        runSpacing: 4,
                        children: signal.indicators
                            .map((ind) => Tooltip(
                                  message:
                                      '${ind.type}: ${ind.value}',
                                  child: Chip(
                                    visualDensity: VisualDensity.compact,
                                    label: Text(
                                      ind.value.length > 40
                                          ? '${ind.value.substring(0, 40)}…'
                                          : ind.value,
                                      style: const TextStyle(fontSize: 11),
                                    ),
                                  ),
                                ))
                            .toList(),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _chip(Color color, String text) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.16),
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: color.withValues(alpha: 0.5)),
        ),
        child: Text(
          text,
          style: TextStyle(
            color: color,
            fontSize: 10,
            fontWeight: FontWeight.w800,
            letterSpacing: 0.6,
          ),
        ),
      );

  Widget _meta(BuildContext context, String text) => Text(
        text,
        style: Theme.of(context)
            .textTheme
            .labelSmall
            ?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant),
      );
}