/// Protection status engine.
///
/// A proper protection state (PROTECTED / WARNING / AT RISK / ACTION REQUIRED /
/// SCANNING / OFFLINE / INITIALIZING) derived from real inputs only:
/// session state, engine readiness, connectivity and actual detection counts.
/// Nothing is ever claimed that the data does not support.
library;

import 'package:flutter/material.dart';

import 'app_errors.dart';
import 'models/dashboard.dart' show DashboardStats;

enum ProtectionStatus {
  initializing,
  offline,
  actionRequired,
  scanning,
  warning,
  atRisk,
  protected,
}

class ProtectionState {
  const ProtectionState({
    required this.status,
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.color,
  });

  final ProtectionStatus status;
  final String title;
  final String subtitle;
  final IconData icon;
  final Color color;

  bool get isProtected => status == ProtectionStatus.protected;
  bool get isProblem => status == ProtectionStatus.offline ||
      status == ProtectionStatus.atRisk ||
      status == ProtectionStatus.actionRequired;
}

/// Computes the current honest protection state.
///
/// - `booting`: splash/restore in progress.
/// - `signedIn`: a session is authenticated.
/// - `offline`: the backend could not be reached.
/// - `engineReady`: GET /api/v1/dashboard succeeded and the engine row is
///   healthy.
/// - `scanning`: a [SecurityScan] is currently running.
/// - `stats`: last known dashboard numbers (only trusted when engineReady).
ProtectionState protectionState({
  required bool booting,
  required bool signedIn,
  required bool offline,
  required bool engineReady,
  required bool scanning,
  DashboardStats? stats,
}) {
  if (booting) {
    return const ProtectionState(
      status: ProtectionStatus.initializing,
      title: 'Starting protection',
      subtitle: 'Checking engine state…',
      icon: Icons.shield_outlined,
      color: Color(0xFF8AB4FF),
    );
  }
  if (offline && signedIn) {
    return const ProtectionState(
      status: ProtectionStatus.offline,
      title: 'Security service unreachable',
      subtitle: 'The backend is unavailable. Your device is unaffected '
          '(static analysis runs over the API).',
      icon: Icons.cloud_off_rounded,
      color: Color(0xFFE8A33D),
    );
  }
  if (!signedIn) {
    return const ProtectionState(
      status: ProtectionStatus.actionRequired,
      title: 'Sign in to start scanning',
      subtitle: 'Scans are stored per account. Sign in once — the session is '
          'remembered on this device.',
      icon: Icons.shield_outlined,
      color: Color(0xFF4E9BE8),
    );
  }
  if (!engineReady) {
    return const ProtectionState(
      status: ProtectionStatus.actionRequired,
      title: 'Engine status unavailable',
      subtitle: 'Could not load the security centre. Pull to refresh and '
          'try again.',
      icon: Icons.refresh_rounded,
      color: Color(0xFFE8A33D),
    );
  }
  if (scanning) {
    return const ProtectionState(
      status: ProtectionStatus.scanning,
      title: 'Scanning…',
      subtitle: 'An on-demand scan is in progress.',
      icon: Icons.radar_rounded,
      color: Color(0xFF38D6F5),
    );
  }

  final atRisk = (stats?.maliciousCount ?? 0) > 0 ||
      (stats?.highRiskCount ?? 0) > 0;
  final warned = (stats?.suspiciousCount ?? 0) > 0;

  if (atRisk) {
    return ProtectionState(
      status: ProtectionStatus.atRisk,
      title: 'Risky items found',
      subtitle: '${stats!.maliciousCount} malicious and '
          '${stats.highRiskCount} high-risk verdicts in your history — '
          'review them and quarantine copies.',
      icon: Icons.gpp_bad_outlined,
      color: const Color(0xFFD64545),
    );
  }
  if (warned) {
    return ProtectionState(
      status: ProtectionStatus.warning,
      title: 'Suspicious items found',
      subtitle: '${stats!.suspiciousCount} suspicious verdicts in your '
          'history — nothing proven malicious, but worth reviewing.',
      icon: Icons.warning_amber_rounded,
      color: const Color(0xFFE8A33D),
    );
  }
  if ((stats?.totalScans ?? 0) == 0) {
    return const ProtectionState(
      status: ProtectionStatus.protected,
      title: 'Engine ready — nothing scanned yet',
      subtitle: 'Run your first scan to see results here.',
      icon: Icons.shield_rounded,
      color: Color(0xFF38D6F5),
    );
  }
  return const ProtectionState(
    status: ProtectionStatus.protected,
    title: 'No threats detected',
    subtitle: 'Every scan so far came back clean. Static analysis is '
        'on-demand — nothing scans automatically.',
    icon: Icons.shield_rounded,
    color: Color(0xFF2FA84F),
  );
}

/// True when the last failure was the backend being unreachable.
ProtectionState offlineState() => const ProtectionState(
      status: ProtectionStatus.offline,
      title: 'Security service unavailable',
      subtitle: offlineMessage,
      icon: Icons.cloud_off_rounded,
      color: Color(0xFFE8A33D),
    );