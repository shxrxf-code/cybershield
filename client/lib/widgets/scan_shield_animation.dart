import 'dart:math' as math;

import 'package:flutter/material.dart';

/// Professional cybersecurity animation: a shield at the centre with a
/// rotating dashed ring and a subtle pulse. GPU-friendly (a single repeating
/// [AnimationController] driving a [CustomPaint] + transforms — no heavy
/// layers), battery-lean, and it stops when the widget is disposed.
///
/// When a real [progress] fraction is available (0..1) the ring becomes a
/// determinate progress ring; otherwise it spins indeterminately. The UI never
/// fakes a percentage here.
class ScanShieldAnimation extends StatefulWidget {
  const ScanShieldAnimation({
    super.key,
    this.size = 84,
    this.color,
    this.progress,
    this.semanticsLabel,
  });

  final double size;
  final Color? color;
  final double? progress;
  final String? semanticsLabel;

  @override
  State<ScanShieldAnimation> createState() => _ScanShieldAnimationState();
}

class _ScanShieldAnimationState extends State<ScanShieldAnimation>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1600),
    )..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = widget.color ?? scheme.primary;
    final t = _controller;
    return Semantics(
      container: true,
      label: widget.semanticsLabel,
      child: AnimatedBuilder(
        animation: t,
        builder: (context, _) {
          final spin = t.value * 2 * math.pi;
          final pulse = 1 + 0.045 * math.sin(t.value * 2 * math.pi);
          return SizedBox(
            width: widget.size,
            height: widget.size,
            child: Stack(
              alignment: Alignment.center,
              children: [
                Positioned.fill(
                  child: CustomPaint(
                    painter: _RingPainter(
                      color: color,
                      spin: spin,
                      progress: widget.progress,
                    ),
                  ),
                ),
                Transform.scale(
                  scale: widget.progress != null ? 1.0 : pulse,
                  child: Icon(
                    Icons.shield_rounded,
                    size: widget.size * 0.52,
                    color: color,
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

class _RingPainter extends CustomPainter {
  const _RingPainter({
    required this.color,
    required this.spin,
    this.progress,
  });

  final Color color;
  final double spin;
  final double? progress;

  @override
  void paint(Canvas canvas, Size size) {
    final center = size.center(Offset.zero);
    final radius = size.width / 2 - 3;
    final trackPaint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.6
      ..color = color.withValues(alpha: 0.16);
    canvas.drawCircle(center, radius, trackPaint);

    // Four stationary tick dots, anti-aliased dots on the ring.
    final dotPaint = Paint()..color = color.withValues(alpha: 0.5);
    for (var i = 0; i < 4; i++) {
      final angle = i * math.pi / 2;
      final dotCenter = Offset(
        center.dx + radius * math.cos(angle),
        center.dy + radius * math.sin(angle),
      );
      canvas.drawCircle(dotCenter, 2, dotPaint);
    }

    final arcPaint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3
      ..strokeCap = StrokeCap.round
      ..color = color;

    final frac = progress;
    if (frac != null && frac >= 0 && frac < 1) {
      // Determinate: a fixed arc equal to the real progress fraction.
      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        -math.pi / 2,
        2 * math.pi * frac.clamp(0.0, 1.0),
        false,
        arcPaint,
      );
      // Keep a moving dot so an active-but-less-than-full scan still looks
      // alive without inventing progress.
      final head = -math.pi / 2 + 2 * math.pi * frac.clamp(0.0, 1.0);
      canvas.drawCircle(
        Offset(
            center.dx + radius * math.cos(head),
            center.dy + radius * math.sin(head)),
        3,
        arcPaint,
      );
    } else {
      // Indeterminate comet: a short bright arc rotating with a fading tail.
      const sweep = 0.35 * 2 * math.pi;
      final start = spin - 0.18 * 2 * math.pi;
      final tailPaint = arcPaint
        ..strokeWidth = 2.4
        ..color = color.withValues(alpha: 0.35);
      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        start - sweep + 0.3,
        sweep - 0.45,
        false,
        tailPaint,
      );
      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        start,
        sweep,
        false,
        arcPaint,
      );
    }
  }

  @override
  bool shouldRepaint(covariant _RingPainter old) =>
      old.spin != spin || old.progress != progress || old.color != color;
}