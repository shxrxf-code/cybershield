/// Domain enums mirroring `backend/app/schemas/common.py`.
///
/// Each enum keeps its API wire value (`api`) plus a display label; parsing is
/// defensive — an unknown wire value degrades to the `unknown` variant (or
/// `null` where the schema allows it).
library;

enum Verdict {
  safe('SAFE', 'Safe'),
  lowRisk('LOW_RISK', 'Low risk'),
  suspicious('SUSPICIOUS', 'Suspicious'),
  highRisk('HIGH_RISK', 'High risk'),
  malicious('MALICIOUS', 'Malicious'),
  unknown('UNKNOWN', 'Unknown');

  const Verdict(this.api, this.label);
  final String api;
  final String label;

  static Verdict? fromApi(Object? value) {
    if (value is! String) return null;
    for (final verdict in Verdict.values) {
      if (verdict.api == value) return verdict;
    }
    return null;
  }

  bool get isSafeEnough => this == safe || this == lowRisk;
}

enum ScanStatus {
  queued('QUEUED', 'Queued'),
  scanning('SCANNING', 'Scanning'),
  analyzing('ANALYZING', 'Analyzing'),
  completed('COMPLETED', 'Completed'),
  failed('FAILED', 'Failed'),
  unknown('UNKNOWN', 'Unknown');

  const ScanStatus(this.api, this.label);
  final String api;
  final String label;

  static ScanStatus fromApi(Object? value) {
    if (value is! String) return ScanStatus.unknown;
    for (final status in ScanStatus.values) {
      if (status.api == value) return status;
    }
    return ScanStatus.unknown;
  }

  bool get isTerminal => this == completed || this == failed;
}

enum ScanType {
  url('url', 'URL'),
  email('email', 'Email'),
  file('file', 'File'),
  apk('apk', 'APK'),
  quick('quick', 'Text'),
  unknown('unknown', 'Unknown');

  const ScanType(this.api, this.label);
  final String api;
  final String label;

  static ScanType fromApi(Object? value) {
    if (value is! String) return ScanType.unknown;
    for (final type in ScanType.values) {
      if (type.api == value) return type;
    }
    return ScanType.unknown;
  }
}

enum ObjectType {
  url('url', 'URL'),
  domain('domain', 'Domain'),
  email('email', 'Email'),
  file('file', 'File'),
  image('image', 'Image'),
  document('document', 'Document'),
  archive('archive', 'Archive'),
  apk('apk', 'APK'),
  text('text', 'Text'),
  unknown('unknown', 'Unknown');

  const ObjectType(this.api, this.label);
  final String api;
  final String label;

  static ObjectType fromApi(Object? value) {
    if (value is! String) return ObjectType.unknown;
    for (final type in ObjectType.values) {
      if (type.api == value) return type;
    }
    return ObjectType.unknown;
  }
}