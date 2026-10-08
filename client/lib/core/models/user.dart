/// `UserResponse` from `/api/v1/users/me` and `/api/v1/users/*`.
library;

import '../utils/json.dart';

class User {
  const User({
    required this.id,
    required this.email,
    this.fullName,
    this.isActive = false,
    this.isAdmin = false,
    this.isVerified = false,
    this.createdAt,
    this.lastLoginAt,
  });

  final String id;
  final String email;
  final String? fullName;
  final bool isActive;
  final bool isAdmin;
  final bool isVerified;
  final DateTime? createdAt;
  final DateTime? lastLoginAt;

  String get displayName => (fullName?.isNotEmpty ?? false) ? fullName! : email;

  factory User.fromJson(Map<String, dynamic> json) => User(
        id: asStringOr(json['id'], ''),
        email: asStringOr(json['email'], ''),
        fullName: asString(json['full_name']),
        isActive: asBool(json['is_active']),
        isAdmin: asBool(json['is_admin']),
        isVerified: asBool(json['is_verified']),
        createdAt: asDate(json['created_at']),
        lastLoginAt: asDate(json['last_login_at']),
      );

  Map<String, dynamic> updateJson({String? fullName}) =>
      {'full_name': fullName};
}