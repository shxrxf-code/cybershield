import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/app_errors.dart';
import '../../core/models/scan.dart';
import '../../core/scan_state.dart';
import '../../widgets/consent_panel.dart';
import '../report/report_screen.dart';
import 'async_scan.dart';
import 'scan_submit_section.dart';

class UrlScanForm extends StatefulWidget {
  const UrlScanForm({super.key});

  @override
  State<UrlScanForm> createState() => _UrlScanFormState();
}

class _UrlScanFormState extends State<UrlScanForm> {
  final _formKey = GlobalKey<FormState>();
  final _url = TextEditingController();
  final _consent = ConsentOptions();
  bool _resolveDns = true;
  bool _quick = false;
  bool _asyncMode = false;
  final SecurityScan _scan = SecurityScan();

  @override
  void dispose() {
    _url.dispose();
    _scan.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    if (!_formKey.currentState!.validate()) return;
    _scan.start();
    try {
      final body = {
        'url': _url.text.trim(),
        'resolve_dns': _resolveDns,
        'quick': _quick,
        'consent': _consent.toJson(),
        'client_label': 'cybershield-flutter',
      };
      if (_asyncMode) {
        _scan.setAnalyzing();
        await submitAsyncAndOpenReport(context,
            submit: () => session.api.postJson(
                '/api/v1/scan/url',
                body: body,
                query: const {'async': 'true'}));
        _scan.complete();
      } else {
        _scan.setAnalyzing();
        final data =
            await session.api.postJson('/api/v1/scan/url', body: body);
        final report = ScanReport.fromUrlResponse(
            Map<String, dynamic>.from(data as Map));
        _scan.complete();
        if (!mounted) return;
        await Navigator.of(context).push(
          MaterialPageRoute<void>(
              builder: (_) => ReportScreen.report(report)),
        );
      }
    } on ApiException catch (e) {
      if (!mounted) return;
      _scan.fail(friendlyAppError(e, signedIn: session.isAuthenticated));
      messenger.showSnackBar(
          SnackBar(content: Text(friendlyAppError(e, signedIn: true))));
    } catch (_) {
      if (!mounted) return;
      _scan.fail(friendlyAppError(
          ApiException(code: 'network_unreachable', statusCode: 0),
          signedIn: true));
      messenger.showSnackBar(const SnackBar(content: Text(offlineMessage)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final busy = _scan.isRunning;
    return Form(
      key: _formKey,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Scan a URL',
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Analyses the link structurally and (when permitted) '
                    'fetches its content safely. The URL is never opened in a '
                    'browser.',
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: _url,
                    enabled: !busy,
                    textInputAction: TextInputAction.done,
                    keyboardType: TextInputType.url,
                    onFieldSubmitted: (_) => _submit(),
                    decoration: const InputDecoration(
                      labelText: 'URL or hostname',
                      hintText: 'https://example.com',
                      prefixIcon: Icon(Icons.link_rounded),
                    ),
                    validator: (v) {
                      final value = v?.trim() ?? '';
                      if (value.isEmpty) {
                        return 'Enter a URL or hostname to scan.';
                      }
                      if (!value.contains('://') &&
                          !value.contains('.') &&
                          value.toLowerCase() != 'localhost') {
                        return 'Provide a full URL including the scheme, or a '
                            'hostname containing a dot.';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 6),
                  SwitchListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Resolve DNS'),
                    subtitle: const Text(
                        'Report the addresses the host resolves to.'),
                    value: _resolveDns,
                    onChanged: busy
                        ? null
                        : (v) => setState(() => _resolveDns = v),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          ConsentPanel(consent: _consent),
          const SizedBox(height: 14),
          ScanSubmitSection(
            quick: _quick,
            asyncMode: _asyncMode,
            phase: _scan.phase,
            submitLabel: 'Scan URL',
            onSubmit: _submit,
            onQuickChanged: (v) => setState(() => _quick = v),
            onAsyncChanged: (v) => setState(() => _asyncMode = v),
          ),
        ],
      ),
    );
  }
}