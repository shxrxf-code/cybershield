import 'package:flutter/material.dart';

import '../../core/utils/json.dart';

/// Renders a `score_breakdown` map as compact contribution bars. The backend
/// stores it as a generic dict, so this renderer is defensive.
class BreakdownCard extends StatelessWidget {
  const BreakdownCard({super.key, required this.breakdown});

  final Map<String, dynamic>? breakdown;

  @override
  Widget build(BuildContext context) {
    final map = breakdown ?? const <String, dynamic>{};
    if (map.isEmpty) return const SizedBox.shrink();
    final rows = _extractRows(map);
    if (rows.isEmpty) {
      return const SizedBox.shrink();
    }
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Score breakdown',
                style: Theme.of(context)
                    .textTheme
                    .titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 6),
            Text(
              'How the aggregated risk budget was allocated.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 12),
            ...rows.take(12).map(
                  (row) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Expanded(
                              child: Text(
                                row.label,
                                style:
                                    Theme.of(context).textTheme.labelMedium,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            if (row.detail != null)
                              Text(
                                row.detail!,
                                style: Theme.of(context)
                                    .textTheme
                                    .labelSmall
                                    ?.copyWith(
                                        color: scheme.onSurfaceVariant),
                              ),
                            const SizedBox(width: 8),
                            Text(
                              '${row.value.round()}',
                              style: Theme.of(context)
                                  .textTheme
                                  .labelMedium
                                  ?.copyWith(fontWeight: FontWeight.w700),
                            ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        ClipRRect(
                          borderRadius: BorderRadius.circular(99),
                          child: LinearProgressIndicator(
                            value: (row.value / 100).clamp(0, 1),
                            minHeight: 6,
                            backgroundColor: scheme.surfaceContainerHighest,
                            color: _colorFor(row.value),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
          ],
        ),
      ),
    );
  }

  Color _colorFor(double value) {
    if (value < 20) return const Color(0xFF2FA84F);
    if (value < 40) return const Color(0xFF98C93C);
    if (value < 60) return const Color(0xFFE8A33D);
    if (value < 80) return const Color(0xFFE07B2D);
    return const Color(0xFFD64545);
  }

  List<_BreakdownRow> _extractRows(Map<String, dynamic> map) {
    final rows = <_BreakdownRow>[];

    final categories = asMap(map['categories']);
    if (categories != null) {
      categories.forEach((name, value) {
        final v = asMap(value);
        if (v == null) return;
        final score = asNumOrNull(v['score']);
        final contribution = asNumOrNull(v['contribution']);
        if (score != null) {
          rows.add(_BreakdownRow(
            label: _titleCase(name),
            value: score.clamp(0, 100).toDouble(),
            detail: contribution == null
                ? null
                : '${(contribution * 100).round()}% weight',
          ));
        }
      });
    }

    final topSignals = asList(map['top_signals']);
    if (topSignals.isNotEmpty) {
      for (final raw in topSignals) {
        final item = asMap(raw);
        if (item == null) continue;
        final impact = asNumOrNull(item['impact']);
        if (impact != null) {
          rows.add(_BreakdownRow(
            label: asString(item['title']) ?? asStringOr(item['code'], 'signal'),
            value: (impact * 100).clamp(0, 100).toDouble(),
            detail: 'impact on score',
          ));
        }
      }
    }

    if (rows.isEmpty) {
      map.forEach((key, value) {
        final num = asNumOrNull(value);
        if (num != null) {
          rows.add(_BreakdownRow(
            label: _titleCase(key),
            value: num.clamp(0, 100).toDouble(),
          ));
        }
      });
    }

    rows.sort((a, b) => b.value.compareTo(a.value));
    return rows;
  }

  String _titleCase(String input) => input
      .split(RegExp(r'[_\s]+'))
      .where((w) => w.isNotEmpty)
      .map((w) => w[0].toUpperCase() + w.substring(1))
      .join(' ');
}

class _BreakdownRow {
  const _BreakdownRow({
    required this.label,
    required this.value,
    this.detail,
  });
  final String label;
  final double value;
  final String? detail;
}