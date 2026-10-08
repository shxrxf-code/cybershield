import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_client.dart';
import '../../core/api_exception.dart';
import '../../core/config.dart';
import '../../core/models/enums.dart';
import '../../core/models/scan.dart';
import '../../widgets/verdict_style.dart';
import '../report/report_screen.dart';

/// Scans a user-granted folder (or a multi-selected set of files) file by
/// file through the static-analysis API.
///
/// Honest limits baked in:
/// - Only files the *user* grants access to are read (folder picker / file
///   picker). The app never walks the whole device on its own.
/// - Files larger than [AppConfig.maxUploadBytes] are skipped.
/// - The backend's `file_scan` rate bucket is 10 requests/minute by default,
///   so batches are paced to stay under it. A `429` stops the batch with a
///   clear message instead of hammering the API.
/// - Analysis is static only — nothing on the device is executed.
class DeviceScanForm extends StatefulWidget {
  const DeviceScanForm({super.key});

  @override
  State<DeviceScanForm> createState() => _DeviceScanFormState();
}

/// A file queued for scanning: either discovered by walking a folder or picked
/// by the user.
class _QueuedFile {
  _QueuedFile(this.path, this.name, this.size);
  final String path;
  final String name;
  final int size;
}

enum _ScanPhase { idle, collecting, scanning, done }
enum _EntryKind { ok, failed }

class _Outcome {
  _Outcome.ok(
    this.name, {
    required this.report,
  })  : kind = _EntryKind.ok,
        error = null;

  _Outcome.failed(this.name, this.error)
      : kind = _EntryKind.failed,
        report = null;

  final String name;
  final _EntryKind kind;
  final ScanReport? report;
  final String? error;
}

class _DeviceScanFormState extends State<DeviceScanForm> {
  /// Default pacing: stay under the backend's 10/min `file_scan` bucket with
  /// headroom for other requests from the same session.
  static const int _paceSeconds = 7;

  /// Hard cap per run so a huge folder can't queue unbounded work.
  static const int _maxFiles = 200;

  bool _useFolder = true;
  String? _folderPath;
  List<PlatformFile>? _picked;
  List<_QueuedFile>? _queued;
  String? _collectionError;

  bool _quick = true;
  bool _quarantine = false;

  _ScanPhase _phase = _ScanPhase.idle;
  String? _folderName;
  int _skippedTooLarge = 0;
  int _current = 0;
  String _currentName = '';
  bool _stopRequested = false;
  String? _stoppedReason;
  int? _retryAfterSeconds;
  final List<_Outcome> _outcomes = [];

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _introCard(scheme),
        const SizedBox(height: 14),
        if (_phase != _ScanPhase.idle) ..._progressAndResults(),
        if (_phase == _ScanPhase.idle || _phase == _ScanPhase.done) ...[
          const SizedBox(height: 14),
          _sourceCard(scheme),
        ],
        if (_phase == _ScanPhase.idle ||
            _phase == _ScanPhase.done) ...[
          const SizedBox(height: 14),
          _optionsCard(scheme),
        ],
        if (_phase == _ScanPhase.idle) ...[
          const SizedBox(height: 14),
          _startSection(scheme),
        ],
      ],
    );
  }

  // ------------------------------------------------------------------
  // Cards
  // ------------------------------------------------------------------

  Widget _introCard(ColorScheme scheme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Scan device files',
              style: Theme.of(context)
                  .textTheme
                  .titleMedium
                  ?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            Text(
              'Pick a folder (or a set of files) and each file is run through '
              'the static-analysis engine — files are never executed. Only the '
              'folder you grant is read; on iOS read access is limited to '
              'files you pick.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }

  Widget _sourceCard(ColorScheme scheme) {
    final title = _useFolder
        ? (_folderPath == null ? 'Choose a folder' : _folderName ?? _folderPath!)
        : (_picked == null || _picked!.isEmpty
            ? 'Choose files'
            : '${_picked!.length} files selected');
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Source',
              style: Theme.of(context)
                  .textTheme
                  .titleSmall
                  ?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 12),
            SegmentedButton<bool>(
              segments: const [
                ButtonSegment(
                  value: true,
                  label: Text('Folder'),
                  icon: Icon(Icons.folder_outlined),
                ),
                ButtonSegment(
                  value: false,
                  label: Text('Files'),
                  icon: Icon(Icons.attach_file_rounded),
                ),
              ],
              selected: {_useFolder},
              onSelectionChanged: (newSelection) => setState(() {
                final wantFolder = newSelection.first;
                if (wantFolder == _useFolder) return;
                _useFolder = wantFolder;
                _folderPath = null;
                _picked = null;
                _queued = null;
                _collectionError = null;
                _phase = _ScanPhase.idle;
              }),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: Text(
                    title,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontWeight: FontWeight.w600),
                  ),
                ),
                const SizedBox(width: 12),
                OutlinedButton.icon(
                  onPressed: _phase == _ScanPhase.done ? null : _chooseSource,
                  icon: Icon(_useFolder
                      ? Icons.folder_open_rounded
                      : Icons.attach_file_rounded),
                  label: Text(_useFolder ? 'Pick folder' : 'Pick files'),
                ),
              ],
            ),
            if (_collectionError != null) ...[
              const SizedBox(height: 10),
              Text(
                _collectionError!,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.error),
              ),
            ],
            if (_queued != null) ...[
              const SizedBox(height: 10),
              Text(
                '${_queued!.length} files queued'
                '${_skippedTooLarge > 0 ? ' · $_skippedTooLarge skipped (over ${AppConfig.maxUploadMib} MiB)' : ''}',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _optionsCard(ColorScheme scheme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Scan options',
              style: Theme.of(context)
                  .textTheme
                  .titleSmall
                  ?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            CheckboxListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              title: const Text('Quick scan'),
              subtitle: const Text('Fewer analyzers — faster per file.'),
              value: _quick,
              onChanged: (v) => setState(() => _quick = v ?? true),
            ),
            CheckboxListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              title: const Text('Quarantine a copy of flagged files'),
              subtitle: const Text('Off by default for batches — avoids '
                  'copying hundreds of files into quarantine.'),
              value: _quarantine,
              onChanged: (v) => setState(() => _quarantine = v ?? true),
            ),
            const SizedBox(height: 6),
            Text(
              'The server currently allows about 10 file scans per minute, so '
              'a batch proceeds at roughly one file every $_paceSeconds seconds. '
              'It stops politely if the rate limit is reached.',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }

  Widget _startSection(ColorScheme scheme) {
    final queued = _queued;
    final canStart = queued != null && queued.isNotEmpty;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              canStart
                  ? 'Ready to scan ${queued.length} files'
                  : 'Pick a source to begin',
              style: Theme.of(context)
                  .textTheme
                  .titleSmall
                  ?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: canStart ? _runScan : null,
              icon: const Icon(Icons.shield_outlined),
              label: Text(canStart
                  ? 'Scan ${queued.length} files'
                  : 'Scan device files'),
              style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(
                    horizontal: 20, vertical: 14),
              ),
            ),
          ],
        ),
      ),
    );
  }

  List<Widget> _progressAndResults() {
    final scheme = Theme.of(context).colorScheme;
    if (_phase == _ScanPhase.scanning || _phase == _ScanPhase.collecting) {
      final total = _phase == _ScanPhase.collecting
          ? null
          : (_queued?.length ?? 0);
      return [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _phase == _ScanPhase.collecting
                      ? 'Reading folder…'
                      : 'Scanning files…',
                  style: Theme.of(context)
                      .textTheme
                      .titleSmall
                      ?.copyWith(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 10),
                if (total != null && total > 0) ...[
                  LinearProgressIndicator(
                    value: (_current / total).clamp(0.0, 1.0),
                    minHeight: 6,
                    borderRadius: BorderRadius.circular(3),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '$_current / $total · $_currentName',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                ] else
                  const LinearProgressIndicator(minHeight: 6),
                const SizedBox(height: 12),
                Row(
                  children: [
                    if (_phase == _ScanPhase.scanning)
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: () => setState(() => _stopRequested = true),
                          icon: const Icon(Icons.stop_rounded),
                          label: const Text('Stop'),
                        ),
                      )
                    else
                      const Expanded(
                        child: Text(''),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ];
    }

    // Done — summary.
    final ok = _outcomes.where((o) => o.kind == _EntryKind.ok).toList();
    final failed = _outcomes.where((o) => o.kind == _EntryKind.failed).toList();
    final counts = <Verdict, int>{};
    for (final v in Verdict.values) {
      counts[v] = 0;
    }
    for (final o in ok) {
      counts[o.report?.verdict ?? Verdict.unknown] =
          (counts[o.report?.verdict ?? Verdict.unknown] ?? 0) + 1;
    }
    final flagged =
        ok.where((o) => (o.report?.verdict ?? Verdict.unknown) != Verdict.safe)
            .where((o) => (o.report?.verdict ?? Verdict.unknown) != Verdict.lowRisk)
            .toList();

    return [
      Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Batch complete',
                style: Theme.of(context)
                    .textTheme
                    .titleMedium
                    ?.copyWith(fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  _countChip('Scanned', ok.length, scheme.primary),
                  _countChip('Flagged', flagged.length, const Color(0xFFE8A33D)),
                  _countChip('Failed', failed.length, scheme.error),
                  _countChip('Too large', _skippedTooLarge, scheme.onSurfaceVariant),
                ],
              ),
              if (_stoppedReason != null) ...[
                const SizedBox(height: 10),
                Text(
                  _stoppedReason!,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.error),
                ),
              ],
              const SizedBox(height: 12),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Verdict mix',
                    style: Theme.of(context)
                        .textTheme
                        .labelMedium
                        ?.copyWith(fontWeight: FontWeight.w700),
                  ),
                  TextButton.icon(
                    onPressed: _reset,
                    icon: const Icon(Icons.refresh_rounded, size: 18),
                    label: const Text('New batch'),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: counts.entries
                    .where((e) => e.value > 0)
                    .map((e) => Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 10, vertical: 6),
                          decoration: BoxDecoration(
                            color: verdictFillFor(e.key,
                                brightness: Theme.of(context).brightness),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text(
                                '${e.value}',
                                style: TextStyle(
                                  color: verdictColorFor(e.key),
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                              const SizedBox(width: 6),
                              Text(
                                e.key.label.toUpperCase(),
                                style: TextStyle(
                                  color: verdictColorFor(e.key),
                                  fontSize: 11,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                        ))
                    .toList(),
              ),
            ],
          ),
        ),
      ),
      if (flagged.isNotEmpty || failed.isNotEmpty) ...[
        const SizedBox(height: 14),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Needs attention',
                  style: Theme.of(context)
                      .textTheme
                      .titleSmall
                      ?.copyWith(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 4),
                for (final o in [...flagged, ...failed])
                  ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: Icon(
                      o.kind == _EntryKind.failed
                          ? Icons.error_outline_rounded
                          : Icons.warning_amber_rounded,
                      color: o.kind == _EntryKind.failed
                          ? scheme.error
                          : verdictColorFor(
                              o.report!.verdict ?? Verdict.unknown),
                    ),
                    title: Text(
                      o.name,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    subtitle: Text(
                      o.kind == _EntryKind.failed
                          ? (o.error ?? 'Scan failed')
                          : '${scoreBandLabel(o.report!.score?.round() ?? 0)} · '
                              '${(o.report!.confidence ?? 0) * 100}% confidence',
                    ),
                    trailing: o.report == null
                        ? null
                        : const Icon(Icons.chevron_right_rounded),
                    onTap: o.report == null
                        ? null
                        : () => Navigator.of(context).push(
                              MaterialPageRoute<void>(
                                builder: (_) =>
                                    ReportScreen.report(o.report!),
                              ),
                            ),
                  ),
              ],
            ),
          ),
        ),
      ],
    ];
  }

  Widget _countChip(String label, int count, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('$count',
              style: TextStyle(
                  color: color,
                  fontWeight: FontWeight.w800,
                  fontSize: 15)),
          const SizedBox(width: 6),
          Text(label,
              style: TextStyle(color: color, fontSize: 11)),
        ],
      ),
    );
  }

  // ------------------------------------------------------------------
  // Source handling
  // ------------------------------------------------------------------

  Future<void> _chooseSource() async {
    if (_useFolder) {
      await _pickFolder();
    } else {
      await _pickFiles();
    }
  }

  Future<void> _pickFolder() async {
    try {
      final path = await FilePicker.platform.getDirectoryPath();
      if (path == null || path.isEmpty) return;
      if (!mounted) return;
      setState(() {
        _folderPath = path;
        _collectionError = null;
        _queued = null;
        _picked = null;
        final segments =
            path.split(RegExp(r'[/\\]')).where((s) => s.isNotEmpty).toList();
        _folderName = segments.isEmpty ? path : segments.last;
      });
      await _collect();
    } on ApiException {
      // Not expected from the picker; surfaced generically below.
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _collectionError =
            'Could not open the folder picker on this platform. '
            'Use the Files source instead.';
      });
    }
  }

  Future<void> _pickFiles() async {
    try {
      final result =
          await FilePicker.platform.pickFiles(allowMultiple: true);
      final files = result?.files ?? const <PlatformFile>[];
      if (files.isEmpty) return;
      if (!mounted) return;
      setState(() {
        _picked = files;
        _folderPath = null;
        _collectionError = null;
        _queued = files
            .where((f) => f.path != null)
            .map((f) {
              final size = File(f.path!).lengthSync();
              return _QueuedFile(f.path!, f.name, size);
            })
            .toList();
        _skippedTooLarge = files
            .where((f) => f.path != null)
            .where((f) {
              try {
                return File(f.path!).lengthSync() > AppConfig.maxUploadBytes;
              } catch (_) {
                return false;
              }
            })
            .length;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _collectionError = 'Could not open the file picker.';
      });
    }
  }

  Future<void> _collect() async {
    final root = _folderPath;
    if (root == null) return;
    setState(() => _phase = _ScanPhase.collecting);
    final queued = <_QueuedFile>[];
    var tooLarge = 0;
    String? error;
    try {
      await for (final entity in Directory(root).list(recursive: true)) {
        if (_stopRequested) break;
        if (entity is! File) continue;
        if (queued.length >= _maxFiles) break;
        try {
          final size = entity.lengthSync();
          if (size > AppConfig.maxUploadBytes) {
            tooLarge += 1;
            continue;
          }
          queued.add(_QueuedFile(entity.path, entity.uri.pathSegments.last, size));
        } on FileSystemException {
          // Unreadable file — skip silently and continue.
        }
      }
    } on FileSystemException {
      error =
          'Could not read the selected folder. On Android, folders from the '
          'storage picker are not always readable as paths — use the Files '
          'source instead.';
    } catch (_) {
      error = 'Could not read the selected folder.';
    }
    if (!mounted) return;
    setState(() {
      _phase = _ScanPhase.idle;
      _queued = queued;
      _skippedTooLarge = tooLarge;
      _collectionError = error;
      if (queued.length >= _maxFiles) {
        _collectionError ??=
            'Folder contains more than $_maxFiles files — only the first '
            '$_maxFiles were queued in this run.';
      }
    });
  }

  // ------------------------------------------------------------------
  // Scan loop
  // ------------------------------------------------------------------

  Future<void> _runScan() async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final files = _queued ?? const <_QueuedFile>[];
    if (files.isEmpty) return;

    setState(() {
      _phase = _ScanPhase.scanning;
      _current = 0;
      _outcomes.clear();
      _stopRequested = false;
      _stoppedReason = null;
      _retryAfterSeconds = null;
    });

    final options = FileScanOptions(quick: _quick, quarantine: _quarantine);

    for (var i = 0; i < files.length && !_stopRequested; i++) {
      final file = files[i];
      setState(() {
        _current = i + 1;
        _currentName = file.name;
      });

      Uint8List bytes;
      try {
        bytes = await File(file.path).readAsBytes();
      } catch (_) {
        setState(() {
          _outcomes.add(_Outcome.failed(file.name, 'Unreadable on this device'));
        });
        continue;
      }

      try {
        final data = await session.api.postMultipart(
          '/api/v1/scan/file',
          parts: [
            MultipartPart.file('file', file.name, bytes),
            MultipartPart.text('options', jsonEncode(options.toJson())),
          ],
        );
        final report = ScanReport.fromFileResponse(
            Map<String, dynamic>.from(data as Map));
        setState(() => _outcomes.add(_Outcome.ok(file.name, report: report)));
      } on ApiException catch (e) {
        if (!mounted) return;
        if (e.isRateLimited) {
          setState(() {
            _stoppedReason =
                'Stopped: the server rate limit was reached. ${(e.retryAfterSeconds ?? 0) > 0 ? "Wait ${e.retryAfterSeconds}s before continuing." : 'Wait for the window to reset and start a new batch.'}';
            _retryAfterSeconds = e.retryAfterSeconds;
          });
          break;
        }
        if (e.isUnauthorized) {
          setState(() {
            _stoppedReason =
                'Stopped: the session is not authenticated. Sign in again '
                'on a configured build.';
          });
          break;
        }
        setState(() =>
            _outcomes.add(_Outcome.failed(file.name, e.message)));
        // Continue with the next file — one bad scan shouldn't kill the batch.
      } catch (_) {
        setState(() =>
            _outcomes.add(_Outcome.failed(file.name, 'Network error')));
      }

      // Pace toward the server's file-scan rate limit. No pause after the
      // last file.
      if (i < files.length - 1 && !_stopRequested) {
        final stopFence = _stopRequested;
        await Future.delayed(Duration(seconds: _paceSeconds));
        if (stopFence) break;
      }
      if (!mounted) return;
    }

    if (!mounted) return;
    setState(() {
      _phase = _ScanPhase.done;
      if (_stopRequested) {
        _stoppedReason ??= 'Stopped by the user — results so far are below.';
      }
    });
    if (_stoppedReason == null && _retryAfterSeconds == null) {
      messenger.showSnackBar(SnackBar(
        content: Text(
            'Scanned ${_outcomes.where((o) => o.kind == _EntryKind.ok).length} files.'),
      ));
    }
  }

  void _reset() {
    setState(() {
      _phase = _ScanPhase.idle;
      _queued = null;
      _collectionError = null;
      _folderPath = null;
      _picked = null;
      _folderName = null;
      _outcomes.clear();
      _skippedTooLarge = 0;
      _stoppedReason = null;
    });
  }
}