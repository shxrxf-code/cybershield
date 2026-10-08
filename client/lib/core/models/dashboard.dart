/// `DashboardStats` from `GET /api/v1/dashboard`.
library;

import '../utils/json.dart';

class StatsBucket {
  const StatsBucket({
    this.date,
    this.total = 0,
    this.safe = 0,
    this.suspicious = 0,
    this.malicious = 0,
  });

  final DateTime? date;
  final int total;
  final int safe;
  final int suspicious;
  final int malicious;

  factory StatsBucket.fromJson(Map<String, dynamic> json) => StatsBucket(
        date: asDate(json['date']),
        total: asInt(json['total']),
        safe: asInt(json['safe']),
        suspicious: asInt(json['suspicious']),
        malicious: asInt(json['malicious']),
      );
}

class TopThreatType {
  const TopThreatType({this.category = '', this.count = 0});
  final String category;
  final int count;

  factory TopThreatType.fromJson(Map<String, dynamic> json) => TopThreatType(
        category: asStringOr(json['category'], ''),
        count: asInt(json['count']),
      );
}

class DashboardStats {
  const DashboardStats({
    this.totalScans = 0,
    this.safeCount = 0,
    this.lowRiskCount = 0,
    this.suspiciousCount = 0,
    this.highRiskCount = 0,
    this.maliciousCount = 0,
    this.unknownCount = 0,
    this.averageScore = 0,
    this.averageConfidence = 0,
    this.quarantinedFiles = 0,
    this.timeline = const [],
    this.topThreatTypes = const [],
    this.generatedAt,
  });

  final int totalScans;
  final int safeCount;
  final int lowRiskCount;
  final int suspiciousCount;
  final int highRiskCount;
  final int maliciousCount;
  final int unknownCount;
  final double averageScore;
  final double averageConfidence;
  final int quarantinedFiles;
  final List<StatsBucket> timeline;
  final List<TopThreatType> topThreatTypes;
  final DateTime? generatedAt;

  int get verdictTotal =>
      safeCount + lowRiskCount + suspiciousCount + highRiskCount +
      maliciousCount + unknownCount;

  factory DashboardStats.fromJson(Map<String, dynamic> json) => DashboardStats(
        totalScans: asInt(json['total_scans']),
        safeCount: asInt(json['safe_count']),
        lowRiskCount: asInt(json['low_risk_count']),
        suspiciousCount: asInt(json['suspicious_count']),
        highRiskCount: asInt(json['high_risk_count']),
        maliciousCount: asInt(json['malicious_count']),
        unknownCount: asInt(json['unknown_count']),
        averageScore: asDouble(json['average_score']),
        averageConfidence: asDouble(json['average_confidence']),
        quarantinedFiles: asInt(json['quarantined_files']),
        timeline: asList(json['timeline'])
            .map((e) => StatsBucket.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
        topThreatTypes: asList(json['top_threat_types'])
            .map((e) => TopThreatType.fromJson(asMapOrEmpty(e)))
            .toList(growable: false),
        generatedAt: asDate(json['generated_at']),
      );
}