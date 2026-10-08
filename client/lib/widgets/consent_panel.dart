import 'package:flutter/material.dart';

import '../core/models/scan.dart';

/// Consent disclosures for a scan request.
///
/// All three flags default to ON (mirroring the backend), with a disclosure
/// that they can be disabled — nothing is sent outbound when a flag is off.
/// The chosen values are carried verbatim into the request body.
class ConsentPanel extends StatefulWidget {
  const ConsentPanel({
    super.key,
    required this.consent,
    this.showActiveFetch = true,
  });

  final ConsentOptions consent;
  final bool showActiveFetch;

  @override
  State<ConsentPanel> createState() => _ConsentPanelState();
}

class _ConsentPanelState extends State<ConsentPanel> {
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final options = widget.consent;
    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.travel_explore_rounded,
                    size: 18, color: scheme.primary),
                const SizedBox(width: 8),
                Text(
                  'Network consent',
                  style: Theme.of(context)
                      .textTheme
                      .titleSmall
                      ?.copyWith(fontWeight: FontWeight.w700),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              'Controls what the analysis is allowed to look up. All options '
              'are enabled by default and can be disabled here; nothing is '
              'submitted or resolved when the matching switch is off.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 4),
            CheckboxListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              value: options.thirdPartyLookup,
              title: const Text('Third-party lookup'),
              subtitle: const Text(
                  'Submit hashes / URLs to third-party reputation services.'),
              onChanged: (v) => setState(() => options.thirdPartyLookup = v ?? true),
            ),
            CheckboxListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              value: options.dnsLookup,
              title: const Text('DNS lookup'),
              subtitle: const Text(
                  'Resolve the hostname — a DNS query is observable by your resolver.'),
              onChanged: (v) => setState(() => options.dnsLookup = v ?? true),
            ),
            if (widget.showActiveFetch)
              CheckboxListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                controlAffinity: ListTileControlAffinity.leading,
                value: options.activeFetch,
                title: const Text('Active fetch'),
                subtitle: const Text(
                    'Fetch the URL’s content over the network for analysis.'),
                onChanged: (v) => setState(() => options.activeFetch = v ?? true),
              ),
          ],
        ),
      ),
    );
  }
}