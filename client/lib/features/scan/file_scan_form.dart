import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_client.dart';
import '../../core/api_exception.dart';
import '../../core/config.dart';
import '../../core/models/scan.dart';
import '../report/report_screen.dart';
import 'async_scan.dart';
import 'scan_submit_section.dart';

enum FileScanKind { file, apk }

class FileScanForm extends StatefulWidget {
  const FileScanForm({super.key, required this.kind});

  final FileScanKind kind;

  @override
  State<FileScanForm> createState() => _FileScanFormState();
}

class _FileScanFormState extends State<FileScanForm> {
  final FileScanOptions _fileOptions = FileScanOptions();
  final ApkScanOptions _apkOptions = ApkScanOptions();

  PlatformFile? _selected;
  bool _quick = false;
  bool _asyncMode = false;
  bool _busy = false;
  bool _showAdvanced = false;

  bool get _isApk => widget.kind == FileScanKind.apk;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final isApk = _isApk;
    final title = isApk ? 'Scan an APK' : 'Scan a file';
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: Theme.of(context)
                      .textTheme
                      .titleMedium
                      ?.copyWith(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 4),
                Text(
                  isApk
                      ? 'Static analysis of an Android application package. '
                          'It is never installed or run, and anything requiring '
                          'execution is out of scope by design.'
                      : 'Upload a file for static analysis — never executed or '
                          'mounted, and optionally quarantined after analysis.',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: 16),
                if (_selected == null)
                  InkWell(
                    onTap: _busy ? null : _pick,
                    borderRadius: BorderRadius.circular(12),
                    child: Container(
                      padding: const EdgeInsets.symmetric(vertical: 32),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                            color: scheme.outlineVariant,
                            style: BorderStyle.solid),
                        color: scheme.surfaceContainerLowest,
                      ),
                      child: Column(
                        children: [
                          Icon(Icons.upload_file_rounded,
                              size: 40, color: scheme.primary),
                          const SizedBox(height: 10),
                          Text(
                            'Choose a file',
                            style: Theme.of(context)
                                .textTheme
                                .titleSmall
                                ?.copyWith(fontWeight: FontWeight.w600),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Up to ${AppConfig.maxUploadMib} MiB',
                            style: Theme.of(context)
                                .textTheme
                                .bodySmall
                                ?.copyWith(
                                    color: scheme.onSurfaceVariant),
                          ),
                        ],
                      ),
                    ),
                  )
                else
                  _selectedFileTile(scheme),
                if (_selected != null &&
                    _selected!.size > AppConfig.maxUploadBytes) ...[
                  const SizedBox(height: 10),
                  Text(
                    'This file exceeds the ${AppConfig.maxUploadMib} MiB '
                    'limit and will be rejected by the server.',
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.error),
                  ),
                ],
                const SizedBox(height: 12),
                OutlinedButton.icon(
                  onPressed: _busy ? null : _pick,
                  icon: const Icon(Icons.folder_open_rounded),
                  label: Text(_selected == null
                      ? 'Choose file'
                      : 'Choose a different file'),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                InkWell(
                  onTap: () => setState(
                      () => _showAdvanced = !_showAdvanced),
                  child: Row(
                    children: [
                      Icon(Icons.tune_rounded, size: 18, color: scheme.primary),
                      const SizedBox(width: 8),
                      Text(
                        'Analysis options',
                        style: Theme.of(context)
                            .textTheme
                            .titleSmall
                            ?.copyWith(fontWeight: FontWeight.w700),
                      ),
                      const Spacer(),
                      Icon(_showAdvanced
                          ? Icons.expand_less_rounded
                          : Icons.expand_more_rounded),
                    ],
                  ),
                ),
                if (_showAdvanced) ...[
                  const Divider(height: 24),
                  if (isApk) ...[
                    _boolOption(
                      'Inspect DEX bytecode',
                      'Decompile and inspect the Dalvik bytecode.',
                      _apkOptions.inspectDex,
                      (v) => _apkOptions.inspectDex = v,
                    ),
                    _boolOption(
                      'Inspect manifest',
                      'Parse the AndroidManifest for components and permissions.',
                      _apkOptions.inspectManifest,
                      (v) => _apkOptions.inspectManifest = v,
                    ),
                    _boolOption(
                      'Verify signature',
                      'Check the APK signing certificate.',
                      _apkOptions.verifySignature,
                      (v) => _apkOptions.verifySignature = v,
                    ),
                    const Divider(),
                  ],
                  _boolOption(
                    'Quarantine a copy',
                    'Store a copy in quarantine after analysis.',
                    isApk
                        ? _apkOptions.quarantine
                        : _fileOptions.quarantine,
                    (v) =>
                        setState(() => (isApk ? _apkOptions : _fileOptions).quarantine = v),
                  ),
                  _boolOption(
                    'Skip ClamAV',
                    'Bypass the antivirus engine (e.g. when the daemon is down).',
                    isApk
                        ? _apkOptions.skipAntivirus
                        : _fileOptions.skipAntivirus,
                    (v) => setState(
                        () => (isApk ? _apkOptions : _fileOptions).skipAntivirus = v),
                  ),
                  _boolOption(
                    'Skip YARA',
                    'Disable YARA rule matching.',
                    isApk ? _apkOptions.skipYara : _fileOptions.skipYara,
                    (v) =>
                        setState(() => (isApk ? _apkOptions : _fileOptions).skipYara = v),
                  ),
                  _boolOption(
                    'Inspect archives',
                    'Analyse nested archive contents (bounded).',
                    isApk
                        ? _apkOptions.inspectArchives
                        : _fileOptions.inspectArchives,
                    (v) => setState(() =>
                        (isApk ? _apkOptions : _fileOptions).inspectArchives = v),
                  ),
                  _boolOption(
                    'Extract document text',
                    'Extract text for phishing analysis (OCR is separate).',
                    isApk ? _apkOptions.extractText : _fileOptions.extractText,
                    (v) => setState(
                        () => (isApk ? _apkOptions : _fileOptions).extractText = v),
                  ),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        ScanSubmitSection(
          quick: _quick,
          asyncMode: _asyncMode,
          busy: _busy,
          submitLabel: isApk ? 'Scan APK' : 'Scan file',
          onSubmit: _submit,
          onQuickChanged: (v) => setState(() => _quick = v),
          onAsyncChanged: (v) => setState(() => _asyncMode = v),
        ),
      ],
    );
  }

  Widget _selectedFileTile(ColorScheme scheme) {
    final file = _selected!;
    final kib = file.size / 1024;
    final sizeText = file.size >= 1024 * 1024
        ? '${(file.size / (1024 * 1024)).toStringAsFixed(2)} MiB'
        : '${kib.toStringAsFixed(1)} KiB';
    return Row(
      children: [
        Container(
          width: 42,
          height: 42,
          decoration: BoxDecoration(
            color: scheme.primaryContainer,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(_isApk
              ? Icons.phone_android_rounded
              : Icons.description_rounded,
              color: scheme.primary, size: 22),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                file.name,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
              Text(
                sizeText,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ],
          ),
        ),
        IconButton(
          tooltip: 'Remove',
          icon: const Icon(Icons.close_rounded),
          onPressed: _busy ? null : () => setState(() => _selected = null),
        ),
      ],
    );
  }

  Widget _boolOption(
    String title,
    String subtitle,
    bool value,
    ValueChanged<bool> onChanged,
  ) {
    return CheckboxListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      controlAffinity: ListTileControlAffinity.leading,
      title: Text(title),
      subtitle: Text(subtitle),
      value: value,
      onChanged: _busy ? null : (v) => setState(() => onChanged(v ?? true)),
    );
  }

  Future<void> _pick() async {
    try {
      final result = await FilePicker.platform.pickFiles(withData: true);
      if (result == null || result.files.isEmpty) return;
      if (!mounted) return;
      setState(() => _selected = result.files.first);
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not open the file picker.')),
      );
    }
  }

  Future<void> _submit() async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final file = _selected;
    if (file == null) {
      messenger.showSnackBar(
          const SnackBar(content: Text('Choose a file to scan first.')));
      return;
    }
    final bytes = file.bytes;
    if (bytes == null) {
      messenger.showSnackBar(const SnackBar(
          content: Text('Could not read the file bytes. Try again.')));
      return;
    }
    if (file.size > AppConfig.maxUploadBytes) {
      messenger.showSnackBar(const SnackBar(
          content:
              Text('The file exceeds the 100 MiB upload limit.')));
      return;
    }
    setState(() => _busy = true);
    final options = _isApk ? _apkOptions : _fileOptions;
    options.quick = _quick;
    final endpoint = _isApk ? '/api/v1/scan/apk' : '/api/v1/scan/file';
    try {
      if (_asyncMode) {
        await submitAsyncAndOpenReport(context,
            submit: () => session.api.postMultipart(
                  endpoint,
                  parts: [
                    MultipartPart.file('file', file.name, bytes),
                    MultipartPart.text(
                        'options', jsonEncode(options.toJson())),
                  ],
                  query: const {'async': 'true'},
                ));
      } else {
        final data = await session.api.postMultipart(
          endpoint,
          parts: [
            MultipartPart.file('file', file.name, bytes),
            MultipartPart.text('options', jsonEncode(options.toJson())),
          ],
        );
        final report = ScanReport.fromFileResponse(
            Map<String, dynamic>.from(data as Map));
        if (!mounted) return;
        await Navigator.of(context).push(
          MaterialPageRoute<void>(
              builder: (_) => ReportScreen.report(report)),
        );
      }
    } on ApiException catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }
}