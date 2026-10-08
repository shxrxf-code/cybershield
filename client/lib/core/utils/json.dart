/// Defensive JSON helpers.
///
/// Every model in this app decodes through these so a single unexpected field
/// type degrades to a sensible default instead of throwing.
library;

Map<String, dynamic>? asMap(Object? value) {
  if (value == null) return null;
  if (value is Map<String, dynamic>) return value;
  if (value is Map) {
    return value.map((key, val) => MapEntry(key.toString(), val));
  }
  return null;
}

Map<String, dynamic> asMapOrEmpty(Object? value) => asMap(value) ?? const {};

List<dynamic> asList(Object? value) => value is List ? value : const [];

String? asString(Object? value) => value is String ? value : null;

String asStringOr(Object? value, String fallback) {
  if (value is String) return value;
  if (value == null) return fallback;
  return value.toString();
}

int asInt(Object? value, [int fallback = 0]) =>
    value is int ? value : (value is num ? value.toInt() : fallback);

int? asIntOrNull(Object? value) =>
    value is int ? value : (value is num ? value.toInt() : null);

double asDouble(Object? value, [double fallback = 0]) =>
    value is num ? value.toDouble() : fallback;

double? asDoubleOrNull(Object? value) => value is num ? value.toDouble() : null;

bool asBool(Object? value, [bool fallback = false]) =>
    value is bool ? value : fallback;

DateTime? asDate(Object? value) {
  final text = asString(value);
  if (text == null) return null;
  return DateTime.tryParse(text);
}

List<String> asStringList(Object? value) => asList(value)
    .map((e) => asString(e))
    .whereType<String>()
    .toList(growable: false);

double? asNumOrNull(Object? value) => value is num ? value.toDouble() : null;