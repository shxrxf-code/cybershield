/// `ApiKeyResponse` from `/api/v1/api-keys`.
library;

import '../utils/json.dart';

class ApiKeyItem {
  const ApiKeyItem({
    required this.id,
    required this.name,
    required this.prefix,
    required this.scopes,
    this.isActive = false,
    this.createdAt,
    this.expiresAt,
    this.lastUsedAt,
    this.plaintext,
  });

  final String id;
  final String name;
  final String prefix;
  final List<String> scopes;
  final bool isActive;
  final DateTime? createdAt;
  final DateTime? expiresAt;
  final DateTime? lastUsedAt;

  /// Present exactly once, in the creation response — never recoverable later.
  final String? plaintext;

  String get masked => '$prefix••••••••';

  factory ApiKeyItem.fromJson(Map<String, dynamic> json) => ApiKeyItem(
        id: asStringOr(json['id'], ''),
        name: asStringOr(json['name'], ''),
        prefix: asStringOr(json['prefix'], ''),
        scopes: asStringList(json['scopes']),
        isActive: asBool(json['is_active']),
        createdAt: asDate(json['created_at']),
        expiresAt: asDate(json['expires_at']),
        lastUsedAt: asDate(json['last_used_at']),
        plaintext: asString(json['plaintext']),
      );
}