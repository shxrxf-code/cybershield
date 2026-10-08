/// Honest platform capability model.
///
/// Operating systems impose sandbox and privacy restrictions. CyberShield
/// never claims capabilities it does not have: each platform reports what it
/// can and cannot do, and the UI reflects those reports. When a capability is
/// unavailable the app says so instead of pretending to protect.
library;

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show kIsWeb;

/// The platform this build is running on (desktop builds resolve at runtime).
enum AppPlatform {
  android,
  ios,
  linux,
  macos,
  windows,
  unknown;

  String get label => switch (this) {
        AppPlatform.android => 'Android',
        AppPlatform.ios => 'iOS',
        AppPlatform.linux => 'Linux',
        AppPlatform.macos => 'macOS',
        AppPlatform.windows => 'Windows',
        AppPlatform.unknown => 'This platform',
      };
}

AppPlatform currentPlatform() {
  if (kIsWeb) return AppPlatform.unknown;
  if (Platform.isAndroid) return AppPlatform.android;
  if (Platform.isIOS) return AppPlatform.ios;
  if (Platform.isLinux) return AppPlatform.linux;
  if (Platform.isMacOS) return AppPlatform.macos;
  if (Platform.isWindows) return AppPlatform.windows;
  return AppPlatform.unknown;
}

/// A capability with an honest, per-platform status.
///
/// `available` means the operating system allows this build to do it with the
/// permissions already granted; `enabled` additionally reflects whether
/// CyberShield has actually wired/activated it. Both must be true before a UI
/// may display it as active.
class Capability {
  const Capability({
    required this.id,
    required this.title,
    required this.purpose,
    this.available = false,
    this.enabled = false,
    this.note,
  });

  final String id;
  final String title;
  final String purpose;

  /// The OS exposes the mechanism this build would use.
  final bool available;

  /// CyberShield has actually implemented and activated it here.
  final bool enabled;

  /// Honest context shown to the user (platform limits, what is missing).
  final String? note;

  /// What the UI may truthfully claim.
  bool get isActive => available && enabled;
}

/// The strongest legitimate protection model supported by this build, per
/// platform. Everything here is derived from OS rules — nothing is invented.
///
/// Background/startup/network protection are real operating-system features
/// this build deliberately does *not* claim: they require platform services
/// (WorkManager / foreground service / background task / system extension)
/// that are not wired, so they report `available: true, enabled: false` where
/// the OS permits them — an honest "plausible one day, not active now".
class AppCapabilities {
  const AppCapabilities({
    required this.platform,
    required this.folderScan,
    required this.fileScan,
    required this.backgroundProtection,
    required this.startupProtection,
    required this.networkProtection,
    required this.notifications,
  });

  final AppPlatform platform;

  /// Scanning folders/paths the user grants (desktop directory pickers).
  final bool folderScan;

  /// Scanning individual user-picked files (all platforms have a picker).
  final bool fileScan;

  final bool backgroundProtection;
  final bool startupProtection;
  final bool networkProtection;

  /// On-device notifications (in-app alerts; OS notification wiring is a TODO).
  final bool notifications;

  bool get platformIsMobile => platform == AppPlatform.android || platform == AppPlatform.ios;

  List<Capability> permissionSummary() {
    bool desktop =
        platform == AppPlatform.linux ||
        platform == AppPlatform.macos ||
        platform == AppPlatform.windows;
    return [
      Capability(
        id: 'storage',
        title: 'Storage access',
        purpose: 'CyberShield reads only the folders and files you explicitly '
            'choose, and never background-scans private app data.',
        available: true,
        enabled: true,
        note: desktop
            ? 'Folder and file pickers are available; only granted content '
                'is read.'
            : 'On $platform, access is limited to what you pick through the '
                'system pickers (scoped storage / sandbox).',
      ),
      Capability(
        id: 'file_scan',
        title: 'File scanning',
        purpose: 'Static analysis of files you select, through the '
            'CyberShield detection API. Files are never executed.',
        available: true,
        enabled: true,
      ),
      Capability(
        id: 'background',
        title: 'Background protection',
        purpose: 'Monitoring new files without the UI being open.',
        available: platform == AppPlatform.android || desktop,
        enabled: false,
        note: platform == AppPlatform.android
            ? 'A background worker is not wired in this build. OS rules '
                'require WorkManager / a foreground service; nothing is '
                'predicted to run in the background.'
            : 'Allowed by the OS but not implemented in this build.',
      ),
      Capability(
        id: 'startup',
        title: 'Startup protection',
        purpose: 'Resuming protection states after the device boots.',
        available:
            platform == AppPlatform.android || platform == AppPlatform.windows,
        enabled: false,
        note: 'Boot-time launch is OS-gated and not wired in this build.',
      ),
      Capability(
        id: 'network',
        title: 'Network protection',
        purpose: 'Browsing-level protection of web traffic.',
        available:
            platform == AppPlatform.android || platform == AppPlatform.ios,
        enabled: false,
        note: 'Would require a VPN/network extension with legitimate user '
            'configuration. Not implemented — and never silently enabled.',
      ),
      Capability(
        id: 'notifications',
        title: 'Threat notifications',
        purpose: 'Alerting you when a scan flags a threat.',
        available: true,
        enabled: true,
        note: 'In-app alerts only in this build; OS push notifications are '
            'not wired.',
      ),
    ];
  }
}

AppCapabilities capabilitiesFor({AppPlatform? platform}) {
  final p = platform ?? currentPlatform();
  final desktop =
      p == AppPlatform.linux || p == AppPlatform.macos || p == AppPlatform.windows;
  return AppCapabilities(
    platform: p,
    folderScan: desktop,
    fileScan: true,
    backgroundProtection: p == AppPlatform.android || desktop,
    startupProtection: p == AppPlatform.android || p == AppPlatform.windows,
    networkProtection: p == AppPlatform.android || p == AppPlatform.ios,
    notifications: true,
  );
}