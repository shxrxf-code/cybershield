import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_client.dart';
import '../../core/api_exception.dart';
import '../../core/app_errors.dart';
import '../../core/app_platform.dart';
import '../../core/config.dart';
import '../../core/models/enums.dart';
import '../../core/models/scan.dart';
import '../../core/scan_cache.dart';
import '../../core/scan_state.dart';
import '../../widgets/scan_shield_animation.dart';
import '../auth/sign_in_sheet.dart';
import '../history/history_screen.dart';
import '../report/report_screen.dart';
import '../../widgets/verdict_style.dart';

/// One file queued for the full-device scan.
class _QueuedFile {
  _QueuedFile(this.path, this.name, this.size);
  final String path;
  final String name;
  final int size;
}

/// Full device scan.
///
/// Honest scope: a "full" scan means "every accessible file under the location
/// you grant". The OS sandbox rules the reach:
/// - Desktop: a directory picker, plus a one-tap "home folder" short cut (only
///   what your account can read).
/// - Android/iOS: only the files/folders you pick through system pickers.
///
/// Unchanged files are skipped via the local [ScanCache] (SHA-256 + size +
/// mtime), so rescanning a location does not re-hash or re-upload
/// thousands of files. Progress reflects real counts; when the total is not
/// yet known the bar is indeterminate — no fake percentages.
class FullScanScreen extends StatefulWidget {
  const FullScanScreen({super.key});

  @override
  State<FullScanScreen> createState() => _FullScanScreenState();
}

enum _ScanPage { choose, running, done }

enum _EntryKind { ok, failed }

class _Outcome {
  _Outcome.ok(this.name, {this.report, this.cachedVerdict})
      : kind = _EntryKind.ok,
        error = null;

  _Outcome.failed(this.name, this.error)
      : kind = _EntryKind.failed,
        report = null;

  final String name;
  final _EntryKind kind;
  final ScanReport? report;
  final String? error;

  /// Non-null when the file was skipped from cache instead of re-scanned.
  final Verdict? cachedVerdict;
}

class _FullScanScreenState extends State<FullScanScreen> {
  static const int _maxFiles = 500;
  static const int _paceSeconds = 7;

  final SecurityScan _scan = SecurityScan();
  bool _stopRequested = false;

  _ScanPage _page = _ScanPage.choose;
  String? _rootPath;
  String? _rootName;
  List<_QueuedFile>? _queued;
  List<_Outcome> _outcomes = [];
  int _skippedTooLarge = 0;
  int _skippedFromCache = 0;
  String? _stoppedReason;
  String? _collectionError;

  bool _quick = true;
  bool _quarantine = false;
  bool _skipUnchanged = true;

  ScanCache? _cache;

  @override
  void dispose() {
    _scan.dispose();
    super.dispose();
  }

  // ------------------------------------------------------------------
  // Setup / choose page
  // ------------------------------------------------------------------

  Future<void> _pickRoot() async {
    final session = AppScope.of(context);
    if (!session.isAuthenticated) return;
    final platform = currentPlatform();
    if (platform == AppPlatform.android || platform == AppPlatform.ios) {
      // Storage-picker files only on mobile — honest by design.
      await _pickFiles();
      return;
    }
    try {
      final path = await FilePicker.platform.getDirectoryPath();
      if (path == null || path.isEmpty) return;
      await _setRoot(path);
    } catch (_) {
      if (!mounted) return;
      setState(() => _collectionError = _rootPath == null
          ? 'Could not open the folder picker. You can still scan files '
              'from the Scan tab.'
          : 'Could not change the folder.');
    }
  }

  Future<void> _pickFiles() async {
    try {
      final result =
          await FilePicker.platform.pickFiles(allowMultiple: true);
      final files = result?.files ?? const <PlatformFile>[];
      if (files.isEmpty) return;
      final queued = <_QueuedFile>[];
      var tooLarge = 0;
      for (final f in files) {
        final path = f.path;
        if (path == null) continue;
        try {
          final size = File(path).lengthSync();
          if (size > AppConfig.maxUploadBytes) {
            tooLarge += 1;
            continue;
          }
          queued.add(_QueuedFile(path, f.name, size));
        } catch (_) {
          // unreadable entry — skip
        }
      }
      if (!mounted) return;
      setState(() {
        _queued = queued;
        _skippedTooLarge = tooLarge;
        _rootName = '${queued.length} selected files';
        _collectionError = null;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() => _collectionError = 'Could not open the file picker.');
    }
  }

  Future<void> _setRoot(String path) async {
    setState(() {
      _rootPath = path;
      _collectionError = null;
      final segments =
          path.split(RegExp(r'[/\\]')).where((s) => s.isNotEmpty).toList();
      _rootName = segments.isEmpty ? path : segments.last;
    });
    await _collect();
  }

  Future<String?> _homePath() async {
    if (currentPlatform() == AppPlatform.windows) {
      return Platform.environment['USERPROFILE'];
    }
    return Platform.environment['HOME'];
  }

  Future<void> _useHome() async {
    final home = await _homePath();
    if (home == null || home.isEmpty) {
      if (!mounted) return;
      setState(() => _collectionError =
          'Could not determine your home directory on this device.');
      return;
    }
    await _setRoot(home);
  }

  Future<void> _collect() async {
    final root = _rootPath;
    if (root == null) return;
    _scan.start();
    setState(() => _page = _ScanPage.running);

    final queued = <_QueuedFile>[];
    var tooLarge = 0;
    var dirs = 0;
    String? error;
    try {
      await for (final entity in Directory(root).list(recursive: true)) {
        if (_stopRequested) break;
        if (entity is Directory) {
          dirs += 1;
          _scan.noteDirectoryScanned();
          continue;
        }
        if (entity is! File) continue;
        if (queued.length >= _maxFiles) break;
        try {
          final size = entity.lengthSync();
          if (size > AppConfig.maxUploadBytes) {
            tooLarge += 1;
            continue;
          }
          queued.add(_QueuedFile(
              entity.path, entity.uri.pathSegments.last, size));
        } on FileSystemException {
          // Unreadable file — skip silently.
        }
      }
    } on FileSystemException {
      error =
          'Could not read the whole location. Some protected folders may be '
          'excluded by the operating system — only accessible files were '
          'queued.';
    } catch (_) {
      error = 'Could not read the selected location.';
    }

    if (!mounted) return;
    if (queued.isEmpty) {
      _scan.fail('No readable files found at this location.');
      _runDoneWithError(error);
      return;
    }
    setState(() {
      _queued = queued;
      _skippedTooLarge = tooLarge;
      _collectionError = error;
      if (queued.length >= _maxFiles) {
        _collectionError ??= 'More than $_maxFiles files found — this run '
            'covers the first $_maxFiles.';
      }
    });
    await _runScan(queued);
  }

  // ------------------------------------------------------------------
  // Scan loop
  // ------------------------------------------------------------------

  Future<void> _runScan(List<_QueuedFile> files) async {
    final session = AppScope.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final cache = _skipUnchanged ? (ScanCache()) : null;

    _scan.beginScanning(queuedTotal: files.length);
    setState(() {
      _outcomes.clear();
      _stoppedReason = null;
    });

    final options = FileScanOptions(quick: _quick, quarantine: _quarantine);

    for (var i = 0; i < files.length && !_stopRequested; i++) {
      // Honour pause cooperatively.
      while (_scan.paused) {
        await Future.delayed(const Duration(milliseconds: 250));
        if (!mounted) return;
      }
      if (_stopRequested) break;

      final file = files[i];
      _scan.setCurrentItem(file.name);

      // Incremental scan: skip unchanged files entirely (cache hit).
      FileStat stat;
      try {
        stat = await File(file.path).stat();
      } catch (_) {
        setState(() {
          _outcomes.add(_Outcome.failed(file.name, 'Unreadable on this device'));
        });
        continue;
      }
      if (cache != null) {
        final cached = await cache.lookup(
            file.path, file.size, stat.modified.millisecondsSinceEpoch);
        if (cached != null) {
          final flagged = cached.verdict != null &&
              Verdict.fromApi(cached.verdict) != null &&
              !Verdict.fromApi(cached.verdict)!.isSafeEnough;
          _scan.recordFileScanned(threat: flagged);
          setState(() {
            _skippedFromCache += 1;
            _outcomes.add(_Outcome.ok(file.name,
                cachedVerdict: Verdict.fromApi(cached.verdict) ?? Verdict.unknown));
          });
          continue;
        }
      }

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
        final threat = (report.verdict ?? Verdict.unknown).isSafeEnough == false;
        _scan.recordFileScanned(threat: threat);
        setState(() => _outcomes.add(_Outcome.ok(file.name, report: report)));

        // Cache the outcome so a future run can skip this file.
        if (cache != null) {
          try {
            final sha = await sha256OfFile(File(file.path));
            await cache.store(ScanCacheEntry(
              path: file.path,
              size: file.size,
              modifiedMs: stat.modified.millisecondsSinceEpoch,
              sha256: sha,
              verdict: (report.verdict ?? Verdict.unknown).api,
              scannedAtMs: DateTime.now().millisecondsSinceEpoch,
            ));
          } catch (_) {
            // Cache is best-effort.
          }
        }
      } on ApiException catch (e) {
        if (!mounted) return;
        if (e.isRateLimited) {
          setState(() {
            _stoppedReason =
                'Stopped: the server rate limit was reached. '
                '${(e.retryAfterSeconds ?? 0) > 0 ? "Wait ${e.retryAfterSeconds}s before continuing." : "Start a new scan later."}';
          });
          break;
        }
        if (e.isUnauthorized) {
          setState(() {
            _stoppedReason = 'Stopped: the session ended. Sign in again and '
                'restart the scan.';
          });
          break;
        }
        setState(() => _outcomes.add(
            _Outcome.failed(file.name, friendlyAppError(e, signedIn: true))));
      } catch (_) {
        setState(() {
          _outcomes.add(_Outcome.failed(file.name, 'Could not reach the service'));
        });
      }

      // Pace toward the backend's file-scan rate limit (10/min default).
      if (i < files.length - 1 && !_stopRequested) {
        await Future.delayed(Duration(seconds: _paceSeconds));
        if (_stopRequested) break;
      }
      if (!mounted) return;
    }

    if (!mounted) return;
    final flagged = _outcomes
        .where((o) =>
            o.kind == _EntryKind.ok &&
            (o.report?.verdict ?? o.cachedVerdict ?? Verdict.unknown)
                    .isSafeEnough ==
                false)
        .length;
    final analyzed = _outcomes.where((o) => o.kind == _EntryKind.ok).length;
    if (_stopRequested) {
      _scan.cancel();
    } else if (!_scan.phase.isTerminal) {
      if (flagged > 0) {
        _scan.completeWithThreat(
            threatsDetected: flagged, objectsAnalyzed: analyzed);
      } else {
        _scan.complete();
      }
    }
    setState(() => _page = _ScanPage.done);
    if (_stoppedReason == null && !_stopRequested) {
      messenger.showSnackBar(SnackBar(
        content: Text(flagged > 0
            ? '${flagged.length} flagged item${flagged.length == 1 ? '' : 's'} — review below.'
            : 'Scan complete — ${analyzed} file${analyzed == 1 ? '' : 's'} analysed.'),
      ));
    }
  }

  // ------------------------------------------------------------------
  // Controls
  // ------------------------------------------------------------------

  Future<void> _confirmCancel() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        icon: const Icon(Icons.shield_outlined),
        title: const Text('Cancel this scan?'),
        content: const Text(
            'Progress so far is kept and shown below. You can start a new '
            'scan afterwards.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Keep scanning'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: FilledButton.styleFrom(
                backgroundColor: Theme.of(context).colorScheme.error),
            child: const Text('Cancel scan'),
          ),
        ],
      ),
    );
    if (confirmed == true && mounted) {
      _stopRequested = true;
    }
  }

  void _reset() {
    _scan.reset();
    setState(() {
      _page = _ScanPage.choose;
      _queued = null;
      _rootPath = null;
      _rootName = null;
      _outcomes.clear();
      _stoppedReason = null;
      _collectionError = null;
      _skippedTooLarge = 0;
      _skippedFromCache = 0;
    });
  }

  Future<void> _runDoneWithError(String? collectionError) async {
    if (!mounted) return;
    setState(() {
      _page = _ScanPage.done;
      _collectionError = collectionError;
    });
  }

  // ------------------------------------------------------------------
  // Build
  // ------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Full device scan')),
      body: ListenableBuilder(
        listenable: _scan,
        builder: (context, _) => switch (_page) {
          _ScanPage.choose => _buildChoose(context),
          _ScanPage.running => _buildRunning(context),
          _ScanPage.done => _buildDone(context),
        },
      ),
    );
  }

  Widget _buildChoose(BuildContext context) {
    final session = AppScope.of(context);
    final scheme = Theme.of(context).colorScheme;
    final platform = currentPlatform();
    final alreadyChosen = _queued != null;
    if (!session.isAuthenticated) {
      return SignedOutGate(
        title: 'Sign in to run a full scan',
        onSignIn: () => showSignInSheet(context),
      );
    }
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
                  'What a full scan covers',
                  style: Theme.of(context)
                      .textTheme
                      .titleMedium
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 6),
                Text(
                  platform == AppPlatform.android ||
                          platform == AppPlatform.ios
                      ? 'Privacy rules limit this platform: you grant access '
                          'through the system pickers and every file you '
                          'select is scanned. Private app data (WhatsApp, '
                          'banks, messengers…) is not reachable or scanned.'
                      : 'Desktop builds scan every accessible file under the '
                          'location you grant. Protected system folders stay '
                          'closed by the operating system.',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        Card(
          child: Column(
            children: [
              ListTile(
                leading: const Icon(Icons.home_rounded),
                title: const Text('My home folder'),
                subtitle: const Text('Your user directory (accessible files).',
                    maxLines: 2),
                enabled: currentPlatform() == AppPlatform.linux ||
                    currentPlatform() == AppPlatform.macos ||
                    currentPlatform() == AppPlatform.windows,
                trailing: _rootPath != null && _rootName == 'My home folder'
                    ? const Icon(Icons.check_rounded)
                    : const Icon(Icons.chevron_right_rounded),
                onTap: () => _useHome(),
              ),
              ListTile(
                leading: const Icon(Icons.folder_open_rounded),
                title: Text(currentPlatform() == AppPlatform.android ||
                        currentPlatform() == AppPlatform.ios
                    ? 'Pick files to scan'
                    : 'Pick a folder'),
                subtitle: const Text('Choose exactly what gets scanned.',
                    maxLines: 2),
                trailing: alreadyChosen
                    ? const Icon(Icons.check_rounded)
                    : const Icon(Icons.chevron_right_rounded),
                onTap: () => _pickRoot(),
              ),
            ],
          ),
        ),
        if (alreadyChosen) ...[
          const SizedBox(height: 14),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    _rootName ?? '${_queued!.length} files',
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${_queued!.length} files queued'
                    '${_skippedTooLarge > 0 ? ' · $_skippedTooLarge skipped (over ${AppConfig.maxUploadMib} MiB)' : ''}',
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                  if (_collectionError != null) ...[
                    const SizedBox(height: 6),
                    Text(
                      _collectionError!,
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(color: scheme.error),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
        const SizedBox(height: 14),
        Card(
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
                  subtitle: const Text(
                      'Off by default for batches — avoids copying hundreds '
                      'of files into the server quarantine.'),
                  value: _quarantine,
                  onChanged: (v) => setState(() => _quarantine = v ?? true),
                ),
                CheckboxListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  controlAffinity: ListTileControlAffinity.leading,
                  title: const Text('Skip unchanged files'),
                  subtitle: const Text(
                      'Uses a local SHA-256 + size + mtime cache so rescanning '
                      'does not re-upload files that already have a verdict.'),
                  value: _skipUnchanged,
                  onChanged: (v) => setState(() => _skipUnchanged = v ?? true),
                ),
                const SizedBox(height: 6),
                Text(
                  'The server allows about 10 file scans per minute, so a '
                  'batch proceeds at roughly one file every $_paceSeconds '
                  'seconds. It stops politely if the rate limit is reached.',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        SizedBox(
          height: 52,
          child: FilledButton.icon(
            onPressed: !alreadyChosen
                ? null
                : () => _collectQueuedAlready(),
            icon: const Icon(Icons.shield_rounded),
            label: Text(alreadyChosen
                ? 'Scan ${_queued!.length} ${_queued!.length == 1 ? 'file' : 'files'}'
                : 'Choose a location first'),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'Static analysis only — scanned files are never executed.',
          textAlign: TextAlign.center,
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
      ],
    );
  }

  Future<void> _collectQueuedAlready() async {
    final queued = _queued;
    if (queued == null || queued.isEmpty) return;
    setState(() => _page = _ScanPage.running);
    await _runScan(queued);
  }

  Widget _buildRunning(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final progress = _scan.progress;
    final fraction = progress.fraction;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                const SizedBox(height: 8),
                ScanShieldAnimation(
                  size: 96,
                  progress: fraction,
                  semanticsLabel: 'Scanning',
                ),
                const SizedBox(height: 14),
                Text(
                  _scan.paused
                      ? 'Paused'
                      : progress.phase == ScanPhase.scanning ||
                              progress.phase == ScanPhase.analyzing
                          ? 'Scanning ${_rootName ?? 'your files'}…'
                          : 'Preparing…',
                  style: Theme.of(context)
                      .textTheme
                      .titleLarge
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 4),
                Text(
                  '${progress.filesProcessed} of '
                  '${progress.filesQueued ?? '…'} files processed',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: 14),
                if (fraction != null) ...[
                  LinearProgressIndicator(
                    value: fraction,
                    minHeight: 8,
                    borderRadius: BorderRadius.circular(4),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    '${(fraction * 100).round()}%',
                    style: Theme.of(context).textTheme.labelMedium,
                  ),
                ] else ...[
                  const LinearProgressIndicator(minHeight: 8),
                ],
                if (progress.currentItem != null) ...[
                  const SizedBox(height: 10),
                  Text(
                    progress.currentItem!,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                _stat(context, '${progress.filesProcessed}', 'files scanned'),
                _stat(context, '${progress.directoriesScanned}', 'folders'),
                _stat(context, '${progress.threatsDetected}', 'threats'),
                _stat(context, _scan.elapsedLabel.isEmpty
                    ? '00:00'
                    : _scan.elapsedLabel, 'elapsed'),
              ],
            ),
          ),
        ),
        if (_skippedFromCache > 0) ...[
          const SizedBox(height: 10),
          Text(
            '$_skippedFromCache unchanged files were skipped from the local '
            'cache.',
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(color: scheme.onSurfaceVariant),
          ),
        ],
        const SizedBox(height: 18),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: _scan.paused
                    ? _scan.resume
                    : () => _scan.pause(),
                icon: Icon(_scan.paused
                    ? Icons.play_arrow_rounded
                    : Icons.pause_rounded),
                label: Text(_scan.paused ? 'Resume' : 'Pause'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: OutlinedButton.icon(
                onPressed: _confirmCancel,
                icon: const Icon(Icons.stop_rounded),
                label: const Text('Cancel'),
                style: OutlinedButton.styleFrom(
                    foregroundColor: scheme.error),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        _honesty(context),
      ],
    );
  }

  Widget _stat(BuildContext context, String value, String label) {
    return Expanded(
      child: Column(
        children: [
          Text(
            value,
            style: Theme.of(context)
                .textTheme
                .titleLarge
                ?.copyWith(fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 2),
          Text(
            label,
            style: Theme.of(context)
                .textTheme
                .labelSmall
                ?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant),
          ),
        ],
      ),
    );
  }

  Widget _buildDone(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final flagged =
        _outcomes.where((o) => o.kind == _EntryKind.ok &&
                (o.report?.verdict ?? o.cachedVerdict ?? Verdict.unknown)
                        .isSafeEnough ==
                    false).toList();
    final failed = _outcomes.where((o) => o.kind == _EntryKind.failed).toList();
    final scannedCount =
        _outcomes.where((o) => o.kind == _EntryKind.ok).length;

    final stoppedEarly = _scan.phase == ScanPhase.cancelled;
    final threatOutcome = _scan.phase == ScanPhase.threatFound;

    final ok = !stoppedEarly && !threatOutcome && failed.isEmpty;
    final title = stoppedEarly
        ? 'Scan stopped'
        : threatOutcome
            ? 'Threats detected'
            : failed.isNotEmpty
                ? 'Scan finished with warnings'
                : 'Scan complete';
    final subtitle = stoppedEarly
        ? 'You stopped the scan — results so far are below.'
        : threatOutcome
            ? '${flagged.length} suspicious or malicious item${flagged.length == 1 ? '' : 's'} found. Review them below.'
            : failed.isNotEmpty
                ? '${scannedCount} items analysed; ${failed.length} could not be read. Nothing was flagged.'
                : '${scannedCount} item${scannedCount == 1 ? '' : 's'} analysed — nothing flagged.';

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              children: [
                Icon(
                  stoppedEarly
                      ? Icons.stop_circle_outlined
                      : threatOutcome
                          ? Icons.warning_amber_rounded
                          : Icons.check_circle_outline_rounded,
                  size: 72,
                  color: threatOutcome
                      ? const Color(0xFFE8A33D)
                      : ok
                          ? const Color(0xFF2FA84F)
                          : scheme.primary,
                ),
                const SizedBox(height: 14),
                Text(
                  title,
                  style: Theme.of(context)
                      .textTheme
                      .headlineSmall
                      ?.copyWith(fontWeight: FontWeight.w800),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 6),
                Text(
                  subtitle,
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: 16),
                if (_stoppedReason != null) ...[
                  Text(
                    _stoppedReason!,
                    textAlign: TextAlign.center,
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.error),
                  ),
                  const SizedBox(height: 14),
                ],
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  alignment: WrapAlignment.center,
                  children: [
                    _chip(context, '$scannedCount', 'analysed'),
                    _chip(context, '${flagged.length}', 'flagged'),
                    _chip(context, '$failed.length', 'unreadable'),
                    _chip(context, _skippedFromCache > 0
                        ? '$_skippedFromCache'
                        : '—', 'from cache'),
                    _chip(context, _scan.elapsedLabel, 'duration'),
                  ],
                ),
                const SizedBox(height: 18),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    OutlinedButton(
                      onPressed: _reset,
                      child: const Text('Scan another location'),
                    ),
                    const SizedBox(width: 10),
                    FilledButton.icon(
                      onPressed: () => Navigator.of(context).push(
                        MaterialPageRoute<void>(
                            builder: (_) => const HistoryScreen()),
                      ),
                      icon: const Icon(Icons.history_rounded, size: 18),
                      label: const Text('View report'),
                    ),
                  ],
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
                                o.report?.verdict ?? o.cachedVerdict ??
                                    Verdict.unknown),
                      ),
                      title: Text(o.name,
                          maxLines: 1, overflow: TextOverflow.ellipsis),
                      subtitle: Text(o.kind == _EntryKind.failed
                          ? (o.error ?? 'Scan failed')
                          : '${scoreBandLabel((o.report?.score ?? 0).round())} · '
                              '${o.cachedVerdict != null ? "cached verdict" : "${((o.report?.confidence ?? 0) * 100).round()}% confidence"}'),
                      trailing: o.report == null
                          ? (o.cachedVerdict != null
                              ? const Icon(Icons.history_rounded)
                              : null)
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
        const SizedBox(height: 8),
        _honesty(context),
      ],
    );
  }

  Widget _chip(BuildContext context, String value, String label) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        children: [
          Text(value,
              style: const TextStyle(fontWeight: FontWeight.w800)),
          Text(label,
              style: const TextStyle(fontSize: 11),
          ),
        ],
      ),
    );
  }

  Widget _honesty(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.info_outline_rounded, size: 18, color: scheme.primary),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                'Static analysis only — files are never executed, and only '
                'the location you granted is read. Nothing is monitored or '
                'uploaded in the background.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ),
          ],
        ),
      ),
    );
  }
}