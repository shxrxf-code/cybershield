/// `PasswordStrengthResponse` from `POST /api/v1/auth/password-strength`.
library;

import '../utils/json.dart';

class PasswordStrength {
  const PasswordStrength({
    this.score = 0,
    this.length = 0,
    this.characterClasses = 0,
    this.problems = const [],
  });

  final double score;
  final int length;
  final int characterClasses;
  final List<String> problems;

  factory PasswordStrength.fromJson(Map<String, dynamic> json) =>
      PasswordStrength(
        score: asDouble(json['score']),
        length: asInt(json['length']),
        characterClasses: asInt(json['character_classes']),
        problems: asStringList(json['problems']),
      );
}