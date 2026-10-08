import 'dart:async';

import 'package:flutter/material.dart';

import '../core/api_client.dart';
import '../core/models/password_strength.dart';

/// Debounced advisory strength meter backed by
/// `POST /api/v1/auth/password-strength`. The result is advisory only —
/// it never grants access and is not a policy check.
class PasswordStrengthMeter extends StatefulWidget {
  const PasswordStrengthMeter({
    super.key,
    required this.api,
    required this.passwordController,
  });

  final ApiClient api;
  final TextEditingController passwordController;

  @override
  State<PasswordStrengthMeter> createState() => _PasswordStrengthMeterState();
}

class _PasswordStrengthMeterState extends State<PasswordStrengthMeter> {
  Timer? _debounce;
  PasswordStrength? _strength;
  bool _checking = false;
  int _requestSerial = 0;

  @override
  void initState() {
    super.initState();
    widget.passwordController.addListener(_onChanged);
  }

  @override
  void dispose() {
    widget.passwordController.removeListener(_onChanged);
    _debounce?.cancel();
    super.dispose();
  }

  void _onChanged() {
    _debounce?.cancel();
    final value = widget.passwordController.text;
    if (value.isEmpty) {
      setState(() {
        _strength = null;
        _checking = false;
      });
      return;
    }
    _debounce = Timer(const Duration(milliseconds: 420), () => _check(value));
  }

  Future<void> _check(String value) async {
    final serial = ++_requestSerial;
    setState(() => _checking = true);
    try {
      final data = await widget.api.postJson('/api/v1/auth/password-strength',
          body: {'password': value});
      if (!mounted || serial != _requestSerial) return;
      setState(() {
        _strength = PasswordStrength.fromJson(
            Map<String, dynamic>.from(data as Map));
        _checking = false;
      });
    } catch (_) {
      if (!mounted || serial != _requestSerial) return;
      setState(() {
        _strength = null;
        _checking = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final strength = _strength;
    if (strength == null) {
      return SizedBox(
        height: 18,
        child: Text(
          'Strength meter will appear as you type.',
          style: Theme.of(context)
              .textTheme
              .labelSmall
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
      );
    }
    final score = strength.score.clamp(0.0, 1.0);
    final color = _colorFor(score);
    final label = _labelFor(score);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: ClipRRect(
                borderRadius: BorderRadius.circular(99),
                child: LinearProgressIndicator(
                  value: score,
                  minHeight: 6,
                  backgroundColor: scheme.surfaceContainerHighest,
                  color: color,
                ),
              ),
            ),
            const SizedBox(width: 10),
            SizedBox(
              width: 100,
              child: Text(
                _checking ? '…' : label,
                textAlign: TextAlign.right,
                style: TextStyle(
                  color: color,
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
          ],
        ),
        if (strength.problems.isNotEmpty) ...[
          const SizedBox(height: 6),
          ...strength.problems.map(
            (p) => Text(
              '• $p',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
          ),
        ] else ...[
          const SizedBox(height: 6),
          Text(
            'Character classes: ${strength.characterClasses} · length '
            '${strength.length}',
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(color: scheme.onSurfaceVariant),
          ),
        ],
      ],
    );
  }

  Color _colorFor(double score) {
    if (score < 0.25) return const Color(0xFFD64545);
    if (score < 0.5) return const Color(0xFFE07B2D);
    if (score < 0.75) return const Color(0xFFE8A33D);
    return const Color(0xFF2FA84F);
  }

  String _labelFor(double score) {
    if (score < 0.25) return 'Very weak';
    if (score < 0.5) return 'Weak';
    if (score < 0.75) return 'Fair';
    return 'Strong';
  }
}