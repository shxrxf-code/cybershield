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

class EmailScanForm extends StatefulWidget {
  const EmailScanForm({super.key});

  @override
  State<EmailScanForm> createState() => _EmailScanFormState();
}

class _EmailScanFormState extends State<EmailScanForm> {
  final _formKey = GlobalKey<FormState>();
  final _raw = TextEditingController();
  final _subject = TextEditingController();
  final _sender = TextEditingController();
  final _consent = ConsentOptions();
  bool _headersOnly = false;
  bool _quick = false;
  bool _asyncMode = false;
  final SecurityScan _scan = SecurityScan();

  @override
  void dispose() {
    _raw.dispose();
    _subject.dispose();
    _sender.dispose();
    _scan.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    if (!_formKey.currentState!.validate()) return;
    _scan.start();
    try {
      final body = <String, dynamic>{
        'raw_message': _raw.text,
        'analyse_headers_only': _headersOnly,
        'quick': _quick,
        'consent': _consent.toJson(),
        'client_label': 'cybershield-flutter',
      };
      final subject = _subject.text.trim();
      final sender = _sender.text.trim();
      if (subject.isNotEmpty) body['subject'] = subject;
      if (sender.isNotEmpty) body['sender'] = sender;

      if (_asyncMode) {
        _scan.setAnalyzing();
        await submitAsyncAndOpenReport(context,
            submit: () => session.api.postJson('/api/v1/scan/email',
                body: body, query: const {'async': 'true'}));
        _scan.complete();
      } else {
        _scan.setAnalyzing();
        final data =
            await session.api.postJson('/api/v1/scan/email', body: body);
        final report = ScanReport.fromEmailResponse(
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
      _scan.fail(offlineMessage);
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
                    'Scan an email',
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Paste the raw RFC 5322 message. Header-level '
                    'authentication results (SPF, DKIM, DMARC) are often the '
                    'most decisive evidence, so the full source is preferred.',
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: _raw,
                    enabled: !busy,
                    maxLines: 12,
                    minLines: 8,
                    style: const TextStyle(fontFamily: 'monospace'),
                    decoration: const InputDecoration(
                      labelText: 'Raw message (RFC 5322)',
                      alignLabelWithHint: true,
                      hintText: 'From: …\\nTo: …\\nSubject: …\\n\\nBody…',
                      prefixIcon:
                          Icon(Icons.subject_rounded, size: 20),
                    ),
                    validator: (v) {
                      final value = v?.trim() ?? '';
                      if (value.isEmpty) {
                        return 'Paste the raw email source to analyse.';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 14),
                  Row(
                    children: [
                      Expanded(
                        child: TextFormField(
                          controller: _subject,
                          enabled: !busy,
                          decoration: const InputDecoration(
                            labelText: 'Subject (optional)',
                            prefixIcon: Icon(Icons.title_rounded, size: 20),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  TextFormField(
                    controller: _sender,
                    enabled: !busy,
                    keyboardType: TextInputType.emailAddress,
                    decoration: const InputDecoration(
                      labelText: 'Sender (optional)',
                      hintText: 'attacker@example.com',
                      prefixIcon:
                          Icon(Icons.alternate_email_rounded, size: 20),
                    ),
                    validator: (v) {
                      final value = v?.trim() ?? '';
                      if (value.isEmpty) return null;
                      if (!value.contains('@')) {
                        return 'Enter a valid sender email or leave empty.';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 6),
                  SwitchListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Headers only'),
                    subtitle: const Text(
                        'Parse and analyse headers only — never submit the '
                        'message elsewhere.'),
                    value: _headersOnly,
                    onChanged: busy
                        ? null
                        : (v) => setState(() => _headersOnly = v),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          ConsentPanel(consent: _consent, showActiveFetch: false),
          const SizedBox(height: 14),
          ScanSubmitSection(
            quick: _quick,
            asyncMode: _asyncMode,
            phase: _scan.phase,
            submitLabel: 'Scan email',
            onSubmit: _submit,
            onQuickChanged: (v) => setState(() => _quick = v),
            onAsyncChanged: (v) => setState(() => _asyncMode = v),
          ),
        ],
      ),
    );
  }
}