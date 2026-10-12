import 'package:flutter/material.dart';

import '../core/models/enums.dart';

/// Verdict → colour mapping. Fixed, brightness-independent brand colours so
/// verdicts read identically in both themes (kept in one pure function for
/// unit-testability).
Color verdictColorFor(Verdict verdict) {
  switch (verdict) {
    case Verdict.safe:
      return const Color(0xFF2FA84F);
    case Verdict.lowRisk:
      return const Color(0xFF98C93C);
    case Verdict.suspicious:
      return const Color(0xFFE8A33D);
    case Verdict.highRisk:
      return const Color(0xFFE07B2D);
    case Verdict.malicious:
      return const Color(0xFFD64545);
    case Verdict.unknown:
      return const Color(0xFF8A93A6);
  }
}

Color verdictFillFor(Verdict verdict, {required Brightness brightness}) =>
    verdictColorFor(verdict).withValues(
        alpha: brightness == Brightness.dark ? 0.22 : 0.16);

/// Verdict text colour. Kept identical to the accent colour in both themes so
/// a verdict reads the same regardless of brightness (the fill differs).
Color verdictTextFor(Verdict verdict, {required Brightness brightness}) =>
    verdictColorFor(verdict);

String scoreBandLabel(int score) {
  if (score < 20) return 'SAFE';
  if (score < 40) return 'LOW RISK';
  if (score < 60) return 'SUSPICIOUS';
  if (score < 80) return 'HIGH RISK';
  return 'MALICIOUS';
}