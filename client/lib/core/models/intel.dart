/// Response of `GET /api/v1/intel/search`.
library;

import '../utils/json.dart';

class IntelAnswer {
  const IntelAnswer({
    required this.provider,
    this.indicatorType,
    this.isMalicious = false,
    this.confidence = 0,
    this.detectionRatio,
    this.categories = const [],
    this.threatType,
    this.sourceName,
    this.reference,
    this.hitCount = 0,
    this.cachedUntil,
    this.metadata = const {},
  });

  final String provider;
  final String? indicatorType;
  final bool isMalicious;
  final double confidence;
  final double? detectionRatio;
  final List<String> categories;
  final String? threatType;
  final String? sourceName;
  final String? reference;
  final int hitCount;
  final DateTime? cachedUntil;
  final Map<String, dynamic> metadata;

  factory IntelAnswer.fromJson(Map<String, dynamic> json) => IntelAnswer(
        provider: asStringOr(json['provider'], 'unknown'),
        indicatorType: asString(json['indicator_type']),
        isMalicious: asBool(json['is_malicious']),
        confidence: asDouble(json['confidence']),
        detectionRatio: asDoubleOrNull(json['detection_ratio']),
        categories: asStringList(json['categories']),
        threatType: asString(json['threat_type']),
        sourceName: asString(json['source_name']),
        reference: asString(json['reference']),
        hitCount: asInt(json['hit_count']),
        cachedUntil: asDate(json['cached_until']),
        metadata: asMapOrEmpty(json['metadata']),
      );
}

class IntelResult {
  const IntelResult({
    required this.indicator,
    required this.answers,
    required this.consensus,
    this.note,
  });

  final String indicator;
  final List<IntelAnswer> answers;
  final String consensus;

  /// Always: "Cached data only; nothing was sent to a third party by this
  /// request."
  final String? note;

  bool get allMalicious => consensus == 'malicious';
  bool get mixed => consensus == 'mixed';

  factory IntelResult.fromJson(Map<String, dynamic> json) => IntelResult(
        indicator: asStringOr(json['indicator'], ''),
        answers: asList(json['answers'])
            .map((e) => IntelAnswer.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
        consensus: asStringOr(json['consensus'], 'unknown'),
        note: asString(json['note']),
      );
}