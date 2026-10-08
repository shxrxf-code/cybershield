import 'dart:math' as math;

import 'package:flutter/material.dart';

/// A 180° risk gauge showing score 0–100, a needle, band labels, and the
/// midpoint score. Confidence is shown separately as a linear bar.
class RiskGauge extends StatelessWidget {
  const RiskGauge({
    super.key,
    required this.score,
    required this.confidence,
  });

  final double score;
  final double? confidence;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        SizedBox(
          height: 170,
          child: CustomPaint(
            painter: _GaugePainter(score: score, scheme: scheme),
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    score.round().toString(),
                    style: Theme.of(context).textTheme.displayMedium?.copyWith(
                          fontWeight: FontWeight.w800,
                        ),
                  ),
                  Text(
                    'RISK SCORE · /100',
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                          letterSpacing: 1.4,
                          color: scheme.onSurfaceVariant,
                        ),
                  ),
                ],
              ),
            ),
          ),
        ),
        if (confidence != null) ...[
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text('Confidence',
                        style: Theme.of(context).textTheme.labelMedium),
                    Text('${(confidence! * 100).round()}%',
                        style: Theme.of(context)
                            .textTheme
                            .labelMedium
                            ?.copyWith(fontWeight: FontWeight.w700)),
                  ],
                ),
                const SizedBox(height: 6),
                ClipRRect(
                  borderRadius: BorderRadius.circular(99),
                  child: LinearProgressIndicator(
                    value: confidence!.clamp(0, 1),
                    minHeight: 8,
                    backgroundColor: scheme.surfaceContainerHighest,
                    color: confidence! >= 0.7
                        ? scheme.primary
                        : scheme.tertiary,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  'Automated estimate — not an absolute guarantee either way.',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}

class _GaugePainter extends CustomPainter {
  const _GaugePainter({required this.score, required this.scheme});

  final double score;
  final ColorScheme scheme;

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height * 0.82);
    final radius = size.width * 0.38;
    final start = math.pi;
    final sweep = math.pi;

    final track = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 12
      ..strokeCap = StrokeCap.round
      ..color = scheme.surfaceContainerHighest;

    // Background track.
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      start,
      sweep,
      false,
      track,
    );

    // Coloured verdict bands.
    const bands = <(double, double, String)>[
      (0, 19, 'SAFE'),
      (20, 39, 'LOW'),
      (40, 59, 'SUSP'),
      (60, 79, 'HIGH'),
      (80, 100, 'MAL'),
    ];
    for (final band in bands) {
      final low = band.$1 / 100 * math.pi;
      final high = band.$2 / 100 * math.pi;
      final bandPaint = Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 12
        ..strokeCap = StrokeCap.butt;
      bandPaint.color = switch (band.$3) {
        'SAFE' => const Color(0xFF2FA84F),
        'LOW' => const Color(0xFF98C93C),
        'SUSP' => const Color(0xFFE8A33D),
        'HIGH' => const Color(0xFFE07B2D),
        _ => const Color(0xFFD64545),
      };
      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        start + low + 0.02,
        high - low - 0.04,
        false,
        bandPaint,
      );
    }

    // Needle.
    final clamped = score.clamp(0, 100);
    final angle = start + clamped / 100 * sweep;
    final needleLen = radius - 12;
    final needleEnd = center +
        Offset(math.cos(angle) * needleLen, math.sin(angle) * needleLen);
    final needle = Paint()
      ..color = scheme.onSurface
      ..strokeWidth = 2.6
      ..strokeCap = StrokeCap.round;
    canvas.drawLine(center, needleEnd, needle);

    final pivot = Paint()..color = scheme.onSurface;
    canvas.drawCircle(center, 4.5, pivot);

    // Markers at 0, 25, 50, 75, 100.
    final markerPaint = Paint()
      ..color = scheme.onSurfaceVariant
      ..strokeWidth = 1;
    for (final v in const [0, 25, 50, 75, 100]) {
      final a = start + v / 100 * sweep;
      final outer = center + Offset(math.cos(a) * (radius + 10), math.sin(a) * (radius + 10));
      final inner = center + Offset(math.cos(a) * (radius + 4), math.sin(a) * (radius + 4));
      canvas.drawLine(outer, inner, markerPaint);
    }
  }

  @override
  bool shouldRepaint(_GaugePainter oldDelegate) =>
      oldDelegate.score != score || oldDelegate.scheme != scheme;
}