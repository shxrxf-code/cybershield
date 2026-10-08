/// `QuarantineItemSummary` from `/api/v1/quarantine`.
library;

import '../utils/json.dart';
import 'enums.dart';

class QuarantineItem {
  const QuarantineItem({
    required this.id,
    this.scanId,
    required this.originalFilename,
    this.sizeBytes = 0,
    required this.sha256,
    this.detectedType,
    this.verdict,
    this.score,
    this.isEncrypted = false,
    this.isReleased = false,
    this.createdAt,
    this.expiresAt,
    this.metadataJson = const {},
  });

  final String id;
  final String? scanId;
  final String originalFilename;
  final int sizeBytes;
  final String sha256;
  final String? detectedType;
  final Verdict? verdict;
  final double? score;
  final bool isEncrypted;
  final bool isReleased;
  final DateTime? createdAt;
  final DateTime? expiresAt;
  final Map<String, dynamic> metadataJson;

  String get sha256Short =>
      sha256.length > 12 ? sha256.substring(0, 12) : sha256;

  factory QuarantineItem.fromJson(Map<String, dynamic> json) =>
      QuarantineItem(
        id: asStringOr(json['id'], ''),
        scanId: asString(json['scan_id']),
        originalFilename: asStringOr(json['original_filename'], 'untitled'),
        sizeBytes: asInt(json['size_bytes']),
        sha256: asStringOr(json['sha256'], ''),
        detectedType: asString(json['detected_type']),
        verdict: Verdict.fromApi(json['verdict']),
        score: asDoubleOrNull(json['score']),
        isEncrypted: asBool(json['is_encrypted']),
        isReleased: asBool(json['is_released']),
        createdAt: asDate(json['created_at']),
        expiresAt: asDate(json['expires_at']),
        metadataJson: asMapOrEmpty(json['metadata_json']),
      );
}