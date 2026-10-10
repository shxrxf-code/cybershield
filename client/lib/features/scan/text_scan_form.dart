import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_exception.dart';
import '../../core/app_errors.dart';
import '../../core/models/scan.dart';
import '../../core/config.dart';
import '../../core/scan_state.dart';
import '../report/report_screen.dart';
import 'async_scan.dart';
import 'scan_submit_section.dart';

class TextScanForm extends StatefulWidget {
  const TextScanForm({super.key});

  @override
  State<TextScanForm> createState() => _TextScanFormState();
}

class _TextScanFormState extends State<TextScanForm> {
  final _formKey = GlobalKey<FormState>();
  final _text = TextEditingController();
  bool _quick = false;
  bool _asyncMode = false;
  final SecurityScan _scan = SecurityScan();

  @override
  void dispose() {
    _text.dispose();
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
        'text': _text.text,
        'quick': _quick,
        'client_label': 'cybershield-flutter',
      };
      if (_asyncMode) {
        _scan.setAnalyzing();
        await submitAsyncAndOpenReport(context,
            submit: () => session.api.postJson('/api/v1/scan/text',
                body: body, query: const {'async': 'true'}));
        _scan.complete();
      } else {
        _scan.setAnalyzing();
        final data =
            await session.api.postJson('/api/v1/scan/text', body: body);
        final report = ScanReport.fromTextResponse(
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
                    'Scan free text',
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Paste a message, chat excerpt or document snippet. The '
                    'analysis is local — nothing is submitted to a third '
                    'party.',
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: _text,
                    enabled: !busy,
                    maxLines: 12,
                    minLines: 8,
                    maxLength: 100000,
                    decoration: const InputDecoration(
                      labelText: 'Text to analyse',
                      alignLabelWithHint: true,
                      hintText: 'Paste content here…',
                      prefixIcon: Icon(Icons.notes_rounded, size: 20),
                      counterText: '',
                    ),
                    validator: (v) {
                      final value = v ?? '';
                      if (value.trim().isEmpty) {
                        return 'The text to scan must not be blank.';
                      }
                      if (value.length > 100000) {
                        return 'Text is limited to 100,000 characters.';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'Up to 100,000 characters.',
                    style: Theme.of(context)
                        .textTheme
                        .labelSmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          ScanSubmitSection(
            quick: _quick,
            asyncMode: _asyncMode,
            phase: _scan.phase,
            submitLabel: 'Scan text',
            onSubmit: _submit,
            onQuickChanged: (v) => setState(() => _quick = v),
            onAsyncChanged: (v) => setState(() => _asyncMode = v),
            extra: Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Text(
                'Maximum file upload in the CyberShield API is '
                '${AppConfig.maxUploadMib} MiB (files).',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ),
          ),
        ],
      ),
    );
  }
}