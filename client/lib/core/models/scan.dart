/// Scan request options and scan/report models.
///
/// These mirror the schemas in `backend/app/schemas/scan.py`. One shared
/// `ScanReport` model covers every report shape (URL / email / text / file /
/// APK and the generic `ScanDetail` envelope) so a single report screen can
/// render any of them.
library;

import '../utils/json.dart';
import 'enums.dart';

/// Consent for outbound analysis behaviour. All flags default to `true` on the
/// backend; the client surfaces them as explicit, toggleable disclosures.
class ConsentOptions {
  ConsentOptions({
    this.thirdPartyLookup = true,
    this.dnsLookup = true,
    this.activeFetch = true,
  });

  /// Submit hashes/URLs to third-party reputation services.
  bool thirdPartyLookup;
  /// Resolve the hostname (a DNS query is observable by the resolver).
  bool dnsLookup;
  /// Fetch the URL's content over the network.
  bool activeFetch;

  Map<String, dynamic> toJson() => {
        'third_party_lookup': thirdPartyLookup,
        'dns_lookup': dnsLookup,
        'active_fetch': activeFetch,
      };
}

/// Options shared by every scan request (BaseScanRequest in the backend).
class BaseScanOptions {
  BaseScanOptions({ConsentOptions? consent, this.quick = false})
      : consent = consent ?? ConsentOptions();

  ConsentOptions consent;
  bool quick;

  Map<String, dynamic> toJson() => {
        'consent': consent.toJson(),
        'quick': quick,
      };
}

/// FileScanOptions (static analysis switches).
class FileScanOptions extends BaseScanOptions {
  FileScanOptions({
    super.consent,
    super.quick,
    this.quarantine = true,
    this.skipAntivirus = false,
    this.skipYara = false,
    this.inspectArchives = true,
    this.extractText = true,
  });

  bool quarantine;
  bool skipAntivirus;
  bool skipYara;
  bool inspectArchives;
  bool extractText;

  @override
  Map<String, dynamic> toJson() => {
        ...super.toJson(),
        'quarantine': quarantine,
        'skip_antivirus': skipAntivirus,
        'skip_yara': skipYara,
        'inspect_archives': inspectArchives,
        'extract_text': extractText,
      };
}

/// ApkScanOptions extends FileScanOptions with Android-specific toggles.
class ApkScanOptions extends FileScanOptions {
  ApkScanOptions({
    super.consent,
    super.quick,
    super.quarantine,
    super.skipAntivirus,
    super.skipYara,
    super.inspectArchives,
    super.extractText,
    this.inspectDex = true,
    this.inspectManifest = true,
    this.verifySignature = true,
  });

  bool inspectDex;
  bool inspectManifest;
  bool verifySignature;

  @override
  Map<String, dynamic> toJson() => {
        ...super.toJson(),
        'inspect_dex': inspectDex,
        'inspect_manifest': inspectManifest,
        'verify_signature': verifySignature,
      };
}

/// Body of a `202 Accepted` async scan submission.
class ScanAccepted {
  const ScanAccepted({
    required this.scanId,
    this.status = 'QUEUED',
    this.objectType,
    required this.pollUrl,
  });

  final String scanId;
  final String status;
  final String? objectType;
  final String pollUrl;

  factory ScanAccepted.fromJson(Map<String, dynamic> json) => ScanAccepted(
        scanId: asStringOr(json['scan_id'], ''),
        status: asStringOr(json['status'], 'QUEUED'),
        objectType: asString(json['object_type']),
        pollUrl: asStringOr(json['poll_url'], '/api/v1/scans/'),
      );
}

/// Compact row for history / list views (`ScanSummary`).
class ScanSummary {
  const ScanSummary({
    required this.scanId,
    required this.scanType,
    required this.objectType,
    required this.status,
    required this.target,
    this.score,
    this.verdict,
    this.createdAt,
  });

  final String scanId;
  final ScanType scanType;
  final ObjectType objectType;
  final ScanStatus status;
  final String target;
  final double? score;
  final Verdict? verdict;
  final DateTime? createdAt;

  factory ScanSummary.fromJson(Map<String, dynamic> json) => ScanSummary(
        scanId: asStringOr(json['scan_id'], ''),
        scanType: ScanType.fromApi(json['scan_type']),
        objectType: ObjectType.fromApi(json['object_type']),
        status: ScanStatus.fromApi(json['status']),
        target: asStringOr(json['target'], ''),
        score: asDoubleOrNull(json['score']),
        verdict: Verdict.fromApi(json['verdict']),
        createdAt: asDate(json['created_at']),
      );
}

/// Paginated history response (`PaginatedResponse`).
class ScansPage {
  const ScansPage({
    this.items = const [],
    this.total = 0,
    this.page = 1,
    this.pageSize = 20,
    this.pages = 0,
  });

  final List<ScanSummary> items;
  final int total;
  final int page;
  final int pageSize;
  final int pages;

  factory ScansPage.fromJson(Map<String, dynamic> json) => ScansPage(
        items: asList(json['items'])
            .map((e) => ScanSummary.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
        total: asInt(json['total']),
        page: asInt(json['page'], 1),
        pageSize: asInt(json['page_size'], 20),
        pages: asInt(json['pages']),
      );
}

/// An observable indicator extracted during analysis.
class SignalIndicator {
  const SignalIndicator({
    required this.type,
    required this.value,
    this.context,
  });

  final String type;
  final String value;
  final String? context;

  factory SignalIndicator.fromJson(Map<String, dynamic> json) =>
      SignalIndicator(
        type: asStringOr(json['type'], 'indicator'),
        value: asStringOr(json['value'], ''),
        context: asString(json['context']),
      );
}

/// One piece of explainable evidence (`DetectionSignal`).
class DetectionSignal {
  const DetectionSignal({
    required this.code,
    required this.title,
    required this.description,
    required this.severity,
    required this.category,
    required this.source,
    this.weight,
    this.confidence = 0,
    this.evidence = const {},
    this.indicators = const [],
  });

  final String code;
  final String title;
  final String description;
  final String severity;
  final String category;
  final String source;
  final double? weight;
  final double confidence;
  final Map<String, dynamic> evidence;
  final List<SignalIndicator> indicators;

  factory DetectionSignal.fromJson(Map<String, dynamic> json) =>
      DetectionSignal(
        code: asStringOr(json['code'], ''),
        title: asStringOr(json['title'], ''),
        description: asStringOr(json['description'], ''),
        severity: asStringOr(json['severity'], 'INFO'),
        category: asStringOr(json['category'], 'uncategorised'),
        source: asStringOr(json['source'], 'heuristic'),
        weight: asDoubleOrNull(json['weight']),
        confidence: asDouble(json['confidence']),
        evidence: asMapOrEmpty(json['evidence']),
        indicators: asList(json['indicators'])
            .map((e) => SignalIndicator.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
      );

  static List<DetectionSignal> listFrom(Object? raw) => asList(raw)
      .map((e) => DetectionSignal.fromJson(asMapOrEmpty(e)))
      .toList(growable: false);
}

/// Shared report model — see class docs at the top of this file. All fields
/// are optional because each scan type only populates the ones it has.
class ScanReport {
  const ScanReport({
    required this.scanId,
    required this.scanType,
    required this.objectType,
    required this.status,
    required this.target,
    this.score,
    this.verdict,
    this.confidence,
    this.recommendation,
    this.recommendationText,
    this.reasons = const [],
    this.signals = const [],
    this.indicators = const [],
    this.scoreBreakdown,
    this.metadataJson,
    this.targetUrl,
    this.normalisedUrl,
    this.targetHost,
    this.resolvedIps = const [],
    this.fetchBlockedReason,
    this.pageTitle,
    this.httpStatus,
    this.emailSubject,
    this.targetEmail,
    this.senderDomain,
    this.replyTo,
    this.returnPath,
    this.authentication = const {},
    this.headersOfInterest = const {},
    this.attachmentCount = 0,
    this.originalFilename,
    this.detectedType,
    this.sizeBytes,
    this.sha256,
    this.sha1,
    this.md5,
    this.entropy,
    this.isQuarantined = false,
    this.packageName,
    this.versionName,
    this.versionCode,
    this.permissionsRequested = const [],
    this.dangerousPermissions = const [],
    this.signature = const {},
    this.dynamicallyAnalysed = false,
    this.characterCount,
    this.extractedUrls = const [],
    this.extractedEmails = const [],
    this.durationMs,
    this.analyzersRun,
    this.errorMessage,
    this.createdAt,
    this.expiresAt,
  });

  final String scanId;
  final ScanType scanType;
  final ObjectType objectType;
  final ScanStatus status;
  final String target;

  final double? score;
  final Verdict? verdict;
  /// 0..1 reliability of the verdict.
  final double? confidence;
  final String? recommendation;
  final String? recommendationText;
  final List<String> reasons;
  final List<DetectionSignal> signals;
  final List<SignalIndicator> indicators;
  final Map<String, dynamic>? scoreBreakdown;
  final Map<String, dynamic>? metadataJson;

  // URL specifics.
  final String? targetUrl;
  final String? normalisedUrl;
  final String? targetHost;
  final List<String> resolvedIps;
  final String? fetchBlockedReason;
  final String? pageTitle;
  final int? httpStatus;

  // Email specifics.
  final String? emailSubject;
  final String? targetEmail;
  final String? senderDomain;
  final String? replyTo;
  final String? returnPath;
  final Map<String, dynamic> authentication;
  final Map<String, dynamic> headersOfInterest;
  final int attachmentCount;

  // File / APK specifics.
  final String? originalFilename;
  final String? detectedType;
  final int? sizeBytes;
  final String? sha256;
  final String? sha1;
  final String? md5;
  final double? entropy;
  final bool isQuarantined;
  final String? packageName;
  final String? versionName;
  final String? versionCode;
  final List<String> permissionsRequested;
  final List<String> dangerousPermissions;
  final Map<String, dynamic> signature;
  /// Always false for APK analysis (static only).
  final bool dynamicallyAnalysed;

  // Text specifics.
  final int? characterCount;
  final List<String> extractedUrls;
  final List<String> extractedEmails;

  final int? durationMs;
  final String? analyzersRun;
  final String? errorMessage;
  final DateTime? createdAt;
  final DateTime? expiresAt;

  bool get hasReport =>
      status == ScanStatus.completed && score != null && verdict != null;

  String get primaryLabel {
    switch (scanType) {
      case ScanType.url:
        return targetUrl ?? targetHost ?? target;
      case ScanType.email:
        return emailSubject ?? targetEmail ?? target;
      case ScanType.file:
      case ScanType.apk:
        return originalFilename ?? target;
      case ScanType.quick:
        return target;
      case ScanType.unknown:
        return target;
    }
  }

  /// Analyzer identifiers that ran, when reported (comma separated).
  List<String> get analyzers => (analyzersRun ?? '')
      .split(',')
      .map((s) => s.trim())
      .where((s) => s.isNotEmpty)
      .toList(growable: false);

  List<String> get extractedIndicatorValues =>
      indicators.map((i) => i.value).toList(growable: false);

  factory ScanReport.fromScanDetail(Map<String, dynamic> json) {
    final signals = DetectionSignal.listFrom(json['signals']);
    final flattened = signals
        .expand((s) => s.indicators)
        .toList(growable: false);
    return ScanReport(
      scanId: asStringOr(json['scan_id'], ''),
      scanType: ScanType.fromApi(json['scan_type']),
      objectType: ObjectType.fromApi(json['object_type']),
      status: ScanStatus.fromApi(json['status']),
      target: asStringOr(json['target'], ''),
      score: asDoubleOrNull(json['score']),
      verdict: Verdict.fromApi(json['verdict']),
      confidence: asDoubleOrNull(json['confidence']),
      recommendation: asString(json['recommendation']),
      recommendationText: asString(json['recommendation_text']),
      reasons: asStringList(json['reasons']),
      signals: signals,
      indicators: flattened,
      scoreBreakdown: asMap(json['score_breakdown']),
      metadataJson: asMap(json['metadata_json']),
      targetUrl: asString(json['target_url']),
      targetHost: asString(json['target_host']),
      targetEmail: asString(json['target_email']),
      emailSubject: asString(json['email_subject']),
      originalFilename: asString(json['original_filename']),
      sha256: asString(json['sha256']),
      sizeBytes: asIntOrNull(json['size_bytes']),
      isQuarantined: asBool(json['is_quarantined']),
      durationMs: asIntOrNull(json['duration_ms']),
      analyzersRun: asString(json['analyzers_run']),
      errorMessage: asString(json['error_message']),
      createdAt: asDate(json['created_at']),
      expiresAt: asDate(json['expires_at']),
    );
  }

  factory ScanReport.fromUrlResponse(Map<String, dynamic> json) => ScanReport(
        scanId: asStringOr(json['scan_id'], ''),
        scanType: ScanType.url,
        objectType: ObjectType.url,
        status: ScanStatus.fromApi(json['status'] ?? 'COMPLETED'),
        target: asStringOr(json['url'], asStringOr(json['host'], 'URL scan')),
        score: asDoubleOrNull(json['score']),
        verdict: Verdict.fromApi(json['verdict']),
        confidence: asDoubleOrNull(json['confidence']),
        recommendation: asString(json['recommendation']),
        recommendationText: asString(json['recommendation_text']),
        reasons: asStringList(json['reasons']),
        signals: DetectionSignal.listFrom(json['signals']),
        indicators: asList(json['indicators'])
            .map((e) => SignalIndicator.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
        scoreBreakdown: asMap(json['score_breakdown']),
        metadataJson: asMap(json['metadata_json']) ?? asMap(json['reputation']),
        targetUrl: asString(json['url']),
        normalisedUrl: asString(json['normalised_url']),
        targetHost: asString(json['host']),
        resolvedIps: asStringList(json['resolved_ips']),
        fetchBlockedReason: asString(json['fetch_blocked_reason']),
        pageTitle: asString(json['page_title']),
        httpStatus: asIntOrNull(json['http_status']),
        durationMs: asIntOrNull(json['duration_ms']),
        createdAt: asDate(json['created_at']),
      );

  factory ScanReport.fromEmailResponse(Map<String, dynamic> json) =>
      ScanReport(
        scanId: asStringOr(json['scan_id'], ''),
        scanType: ScanType.email,
        objectType: ObjectType.email,
        status: ScanStatus.fromApi(json['status'] ?? 'COMPLETED'),
        target: asStringOr(json['subject'], 'Email scan'),
        score: asDoubleOrNull(json['score']),
        verdict: Verdict.fromApi(json['verdict']),
        confidence: asDoubleOrNull(json['confidence']),
        recommendation: asString(json['recommendation']),
        recommendationText: asString(json['recommendation_text']),
        reasons: asStringList(json['reasons']),
        signals: DetectionSignal.listFrom(json['signals']),
        indicators: asList(json['indicators'])
            .map((e) => SignalIndicator.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
        scoreBreakdown: asMap(json['score_breakdown']),
        metadataJson: asMap(json['metadata_json']),
        emailSubject: asString(json['subject']),
        targetEmail: asString(json['sender']),
        senderDomain: asString(json['sender_domain']),
        replyTo: asString(json['reply_to']),
        returnPath: asString(json['return_path']),
        authentication: asMapOrEmpty(json['authentication']),
        headersOfInterest: asMapOrEmpty(json['headers_of_interest']),
        attachmentCount: asInt(json['attachment_count']),
        durationMs: asIntOrNull(json['duration_ms']),
        createdAt: asDate(json['created_at']),
      );

  factory ScanReport.fromTextResponse(Map<String, dynamic> json) => ScanReport(
        scanId: asStringOr(json['scan_id'], ''),
        scanType: ScanType.quick,
        objectType: ObjectType.text,
        status: ScanStatus.fromApi(json['status'] ?? 'COMPLETED'),
        target: 'Text scan',
        score: asDoubleOrNull(json['score']),
        verdict: Verdict.fromApi(json['verdict']),
        confidence: asDoubleOrNull(json['confidence']),
        recommendation: asString(json['recommendation']),
        recommendationText: asString(json['recommendation_text']),
        reasons: asStringList(json['reasons']),
        signals: DetectionSignal.listFrom(json['signals']),
        indicators: asList(json['indicators'])
            .map((e) => SignalIndicator.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
        scoreBreakdown: asMap(json['score_breakdown']),
        metadataJson: asMap(json['metadata_json']),
        characterCount: asIntOrNull(json['character_count']),
        extractedUrls: asStringList(json['extracted_urls']),
        extractedEmails: asStringList(json['extracted_emails']),
        durationMs: asIntOrNull(json['duration_ms']),
        createdAt: asDate(json['created_at']),
      );

  /// Covers both `FileScanResponse` and `ApkScanResponse` (the latter adds
  /// Android fields and `scan_type == 'apk'`).
  factory ScanReport.fromFileResponse(Map<String, dynamic> json) {
    final isApk = ScanType.fromApi(json['scan_type']) == ScanType.apk ||
        json.containsKey('package_name');
    final base = ScanReport(
      scanId: asStringOr(json['scan_id'], ''),
      scanType: isApk ? ScanType.apk : ScanType.file,
      objectType: json.containsKey('object_type')
          ? ObjectType.fromApi(json['object_type'])
          : (isApk ? ObjectType.apk : ObjectType.file),
      status: ScanStatus.fromApi(json['status'] ?? 'COMPLETED'),
      target: asStringOr(json['filename'], 'File scan'),
      score: asDoubleOrNull(json['score']),
      verdict: Verdict.fromApi(json['verdict']),
      confidence: asDoubleOrNull(json['confidence']),
      recommendation: asString(json['recommendation']),
      recommendationText: asString(json['recommendation_text']),
      reasons: asStringList(json['reasons']),
      signals: DetectionSignal.listFrom(json['signals']),
      indicators: asList(json['indicators'])
          .map((e) => SignalIndicator.fromJson(asMapOrEmpty(e)))
          .toList(growable: false),
      scoreBreakdown: asMap(json['score_breakdown']),
      metadataJson: asMap(json['metadata_json']),
      originalFilename: asString(json['filename']),
      detectedType: asString(json['detected_type']),
      sizeBytes: asIntOrNull(json['size_bytes']),
      sha256: asString(json['sha256']),
      sha1: asString(json['sha1']),
      md5: asString(json['md5']),
      entropy: asDoubleOrNull(json['entropy']),
      isQuarantined: asBool(json['quarantined']),
      packageName: asString(json['package_name']),
      versionName: asString(json['version_name']),
      versionCode: asString(json['version_code']),
      permissionsRequested: asStringList(json['permissions_requested']),
      dangerousPermissions: asStringList(json['dangerous_permissions']),
      signature: asMapOrEmpty(json['signature']),
      dynamicallyAnalysed: asBool(json['dynamically_analysed']),
      durationMs: asIntOrNull(json['duration_ms']),
      createdAt: asDate(json['created_at']),
    );
    return base;
  }
}