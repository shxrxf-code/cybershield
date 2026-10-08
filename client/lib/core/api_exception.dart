/// The one error envelope the API can return:
///
/// ```json
/// {"error": {"code": string, "message": string, "status_code": int,
///            "correlation_id": string, "details": {...}?}}
/// ```
///
/// There is never a top-level `detail` key. `ApiException.fromResponse`
/// decodes the envelope (with a defensive fallback) and extracts the
/// `Retry-After` header / `details.retry_after_seconds` for 429s.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

import 'utils/json.dart';

class ApiException implements Exception {
  const ApiException({
    this.code = 'http_error',
    this.message = 'The request failed.',
    this.statusCode = 0,
    this.correlationId,
    this.details = const {},
    this.retryAfterSeconds,
    this.url,
  });

  final String code;
  final String message;
  final int statusCode;
  final String? correlationId;
  final Map<String, dynamic> details;
  final int? retryAfterSeconds;
  final String? url;

  bool get isUnauthorized =>
      statusCode == 401 || code == 'auth_invalid' || code == 'auth_expired' ||
      code == 'auth_required';

  bool get isRateLimited => statusCode == 429 || code == 'rate_limited';

  bool get isNotFound => statusCode == 404 || code == 'not_found';

  bool get isConflict => statusCode == 409 || code == 'conflict';

  @override
  String toString() =>
      'ApiException($statusCode $code): $message'
      '${correlationId == null ? '' : ' [correlation: $correlationId]'}';

  factory ApiException.fromResponse(http.Response response, {String? url}) {
    final retryAfter = _parseRetryAfter(response.headers['retry-after']);
    final envelope = _tryDecodeEnvelope(response.body);
    if (envelope != null) {
      final details = asMapOrEmpty(envelope['details']);
      final retryFromDetails = asIntOrNull(details['retry_after_seconds']);
      return ApiException(
        code: asStringOr(envelope['code'], 'http_error'),
        message: asStringOr(
            envelope['message'], response.reasonPhrase ?? 'Request failed.'),
        statusCode: asInt(envelope['status_code'], response.statusCode),
        correlationId: asString(envelope['correlation_id']),
        details: details,
        retryAfterSeconds: retryAfter ?? retryFromDetails,
        url: url,
      );
    }
    return ApiException(
      code: _fallbackCodeForStatus(response.statusCode),
      message: 'Unexpected response (HTTP ${response.statusCode}).',
      statusCode: response.statusCode,
      retryAfterSeconds: retryAfter,
      url: url,
    );
  }
}

/// Tries to decode `{"error": {...}}`; returns the inner `error` map or null.
Map<String, dynamic>? _tryDecodeEnvelope(String body) {
  try {
    final decoded = jsonDecode(body);
    final map = asMap(decoded);
    if (map != null && map['error'] != null) {
      return asMap(map['error']);
    }
  } catch (_) {
    // Not JSON — fall through to the generic branch.
  }
  return null;
}

int? _parseRetryAfter(String? value) {
  if (value == null) return null;
  final trimmed = value.trim();
  final seconds = int.tryParse(trimmed);
  if (seconds != null) return seconds < 0 ? null : seconds;
  final date = DateTime.tryParse(trimmed);
  if (date != null) {
    final delta = date.difference(DateTime.now()).inSeconds;
    return delta < 0 ? null : delta;
  }
  return null;
}

String _fallbackCodeForStatus(int status) => switch (status) {
      401 => 'auth_invalid',
      403 => 'forbidden',
      404 => 'not_found',
      409 => 'conflict',
      422 => 'validation_error',
      429 => 'rate_limited',
      413 => 'payload_too_large',
      _ => 'http_error',
    };