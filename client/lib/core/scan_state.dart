/// Central scan state machine.
///
/// Every scan — single URL/email/text/file/APK scans and folder/device batch
/// scans — drives one [SecurityScan] so the UI reacts to the same states
/// instead of hand-managing loading flags in each screen.
library;

import 'package:flutter/foundation.dart';

/// Phases every scan passes through. This is the one source of truth.
enum ScanPhase {
  idle,
  initializing,
  queued,
  scanning,
  analyzing,
  threatFound,
  completed,
  cancelled,
  failed;

  bool get isRunning =>
      this == initializing || this == queued || this == scanning || this == analyzing;

  bool get isTerminal => this == completed || this == cancelled || this == failed;

  /// Short label for status chips.
  String get label => switch (this) {
        ScanPhase.idle => 'Ready',
        ScanPhase.initializing => 'Initializing',
        ScanPhase.queued => 'Queued',
        ScanPhase.scanning => 'Scanning',
        ScanPhase.analyzing => 'Analyzing',
        ScanPhase.threatFound => 'Threat found',
        ScanPhase.completed => 'Complete',
        ScanPhase.cancelled => 'Cancelled',
        ScanPhase.failed => 'Failed',
      };
}

/// Immutable progress snapshot for a run.
class ScanProgress {
  const ScanProgress({
    this.filesDiscovered = 0,
    this.filesProcessed = 0,
    this.filesQueued,
    this.objectsAnalyzed = 0,
    this.threatsDetected = 0,
    this.directoriesScanned = 0,
    this.currentItem,
    this.phase = ScanPhase.idle,
    this.paused = false,
  });

  /// Number of files known to be part of this run (null while enumerating).
  final int? filesQueued;
  final int filesDiscovered;
  final int filesProcessed;
  final int objectsAnalyzed;
  final int threatsDetected;
  final int directoriesScanned;
  final String? currentItem;
  final ScanPhase phase;
  final bool paused;

  /// Deterministic progress only when the total is known; otherwise null so
  /// callers must show an indeterminate state (no fake percentages).
  double? get fraction {
    final total = filesQueued;
    if (total == null || total == 0) return null;
    return (filesProcessed / total).clamp(0.0, 1.0);
  }

  /// `shouldDetect` is a hint from the scan engine about whether progress can
  /// be shown deterministically; this build always has real counts.
  ScanProgress copyWith({
    int? filesDiscovered,
    int? filesProcessed,
    int? filesQueued,
    int? objectsAnalyzed,
    int? threatsDetected,
    int? directoriesScanned,
    String? currentItem,
    bool shouldDetect = false,
    ScanPhase? phase,
    bool? paused,
  }) =>
      ScanProgress(
        filesDiscovered: filesDiscovered ?? this.filesDiscovered,
        filesProcessed: filesProcessed ?? this.filesProcessed,
        filesQueued: filesQueued ?? this.filesQueued,
        objectsAnalyzed: objectsAnalyzed ?? this.objectsAnalyzed,
        threatsDetected: threatsDetected ?? this.threatsDetected,
        directoriesScanned: directoriesScanned ?? this.directoriesScanned,
        currentItem: currentItem ?? this.currentItem,
        phase: phase ?? this.phase,
        paused: paused ?? this.paused,
      );
}

/// Drives one scan through [ScanPhase]. Screens listen and rebuild; the
/// notifier also carries an elapsed stopwatch and, for batches, a friendly
/// error string when the run fails.
class SecurityScan extends ChangeNotifier {
  ScanPhase phase = ScanPhase.idle;
  ScanProgress progress = const ScanProgress();
  String? failureMessage;
  final Stopwatch elapsed = Stopwatch();

  bool get isRunning => phase.isRunning;
  bool get paused => progress.paused;

  /// Starts from scratch. `queuedTotal` is only set once enumeration happens;
  /// leave null while discovering so the UI stays indeterminate (honest).
  void start({bool withPacingNote = false, int? queuedTotal}) {
    elapsed
      ..reset()
      ..start();
    _set(
      phase: ScanPhase.initializing,
      progress: ScanProgress(
        phase: ScanPhase.initializing,
        filesQueued: queuedTotal,
        filesProcessed: 0,
      ),
      clearError: true,
    );
  }

  /// Enumeration finished; the run can transition into the scanning phase.
  void beginScanning({required int queuedTotal}) {
    _set(
      phase: ScanPhase.scanning,
      progress: progress.copyWith(
        phase: ScanPhase.scanning,
        filesQueued: queuedTotal,
      ),
    );
  }

  void setAnalyzing() => _set(phase: ScanPhase.analyzing);

  void noteDirectoryScanned() => _set(
        phase: ScanPhase.scanning,
        progress: progress.copyWith(
          phase: ScanPhase.scanning,
          directoriesScanned: progress.directoriesScanned + 1,
        ),
      );

  /// Record one file as read/hashed/uploaded; `threat` adds to the detected
  /// count when the verdict is not SAFE/LOW.
  void recordFileScanned({bool threat = false}) {
    _set(
      phase: ScanPhase.scanning,
      progress: progress.copyWith(
        phase: ScanPhase.scanning,
        filesProcessed: progress.filesProcessed + 1,
        objectsAnalyzed: progress.objectsAnalyzed + 1,
        threatsDetected: progress.threatsDetected + (threat ? 1 : 0),
      ),
    );
  }

  void setCurrentItem(String item) {
    if (phase == ScanPhase.idle) return;
    _set(phase: ScanPhase.scanning, progress: progress.copyWith(currentItem: item));
  }

  void pause() {
    if (!isRunning || progress.paused) return;
    elapsed.stop();
    _set(phase: phase, progress: progress.copyWith(paused: true));
  }

  void resume() {
    if (!progress.paused) return;
    elapsed.start();
    _set(phase: phase, progress: progress.copyWith(paused: false));
  }

  /// Cancel cooperatively; expected to be confirmed by the caller.
  void cancel() {
    elapsed.stop();
    _set(phase: ScanPhase.cancelled);
  }

  /// Complete flat: when the run produced no threats.
  void complete() {
    elapsed.stop();
    _set(phase: ScanPhase.completed);
  }

  /// Complete after flagging at least one threat.
  void completeWithThreat({
    required int threatsDetected,
    required int objectsAnalyzed,
  }) {
    elapsed.stop();
    _set(
      phase: ScanPhase.threatFound,
      progress: progress.copyWith(
        phase: ScanPhase.threatFound,
        threatsDetected: threatsDetected,
        objectsAnalyzed: objectsAnalyzed,
      ),
    );
  }

  /// Fail with a *friendly* message (never raw API text).
  void fail(String friendlyMessage) {
    elapsed.stop();
    failureMessage = friendlyMessage;
    _set(phase: ScanPhase.failed);
  }

  void reset() {
    elapsed
      ..reset()
      ..stop();
    failureMessage = null;
    _set(
      phase: ScanPhase.idle,
      progress: const ScanProgress(phase: ScanPhase.idle),
      clearError: true,
    );
  }

  String get elapsedLabel {
    final t = elapsed.elapsed.inSeconds;
    final m = (t ~/ 60).toString().padLeft(2, '0');
    final s = (t % 60).toString().padLeft(2, '0');
    return '$m:$s';
  }

  void _set({
    required ScanPhase phase,
    ScanProgress? progress,
    bool clearError = false,
  }) {
    this.phase = phase;
    if (progress != null) this.progress = progress;
    if (clearError) failureMessage = null;
    notifyListeners();
  }
}