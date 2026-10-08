import 'package:flutter/material.dart';

import '../../core/models/scan.dart';

/// Feedback on a finished report — one submission per scan (409 on
/// duplicates).
class FeedbackCard extends StatefulWidget {
  const FeedbackCard({
    super.key,
    required this.report,
    required this.onSubmitted,
  });

  final ScanReport report;
  final Future<void> Function(String label, String? comment) onSubmitted;

  @override
  State<FeedbackCard> createState() => _FeedbackCardState();
}

class _FeedbackCardState extends State<FeedbackCard> {
  static const _labels = {
    'true_positive': 'Correct — it was right to flag it',
    'false_positive': 'Incorrect — this is a false alarm',
    'false_negative': 'Missed — this should have been flagged',
    'unsure': 'Not sure',
  };

  final _comment = TextEditingController();
  String? _label;
  bool _busy = false;
  bool _done = false;

  @override
  void dispose() {
    _comment.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_label == null) {
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Pick a label before submitting.')));
      return;
    }
    setState(() => _busy = true);
    try {
      await widget.onSubmitted(_label!, _comment.text.trim().isEmpty
          ? null
          : _comment.text.trim());
      if (!mounted) return;
      setState(() => _done = true);
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('Feedback could not be submitted.')));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_done) {
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Icon(Icons.check_circle_outline_rounded,
                  color: const Color(0xFF2FA84F)),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Thank you — your feedback helps measure real-world '
                  'accuracy. Only one submission per scan is allowed.',
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ),
            ],
          ),
        ),
      );
    }
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Was this verdict accurate?',
                style: Theme.of(context)
                    .textTheme
                    .titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 10),
            RadioGroup<String>(
              groupValue: _label,
              onChanged: (v) {
                if (_busy) return;
                setState(() => _label = v);
              },
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  for (final entry in _labels.entries)
                    RadioListTile<String>(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      enabled: !_busy,
                      value: entry.key,
                      title:
                          Text(entry.value, style: const TextStyle(fontSize: 13)),
                    ),
                ],
              ),
            ),
            TextField(
              controller: _comment,
              enabled: !_busy,
              maxLength: 1000,
              minLines: 2,
              maxLines: 4,
              decoration: const InputDecoration(
                labelText: 'Comment (optional, max 1000 chars)',
                alignLabelWithHint: true,
              ),
            ),
            const SizedBox(height: 4),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.tonalIcon(
                onPressed: _busy || _label == null ? null : _submit,
                icon: _busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.send_rounded, size: 18),
                label: const Text('Submit feedback'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}