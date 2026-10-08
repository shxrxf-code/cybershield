/// Thin typed HTTP client for the CyberShield API.
///
/// Responsibilities:
/// - attach the active credential (`Authorization: Bearer …` or `X-API-Key`);
/// - on a `401` from an authenticated call, rotate the refresh token exactly
///   once and retry the original request (bearer sessions only);
/// - if the refresh fails, or the mode cannot be refreshed, clear the session;
/// - decode the shared `{"error": {...}}` envelope into `ApiException`,
///   surfacing `Retry-After` for rate-limited responses;
/// - expose JSON, multipart and raw-bytes endpoints.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'api_exception.dart';
import 'auth_store.dart';
import 'config.dart';
import 'models/token_pair.dart';

/// A named part of a multipart upload: either a field or a file.
class MultipartPart {
  const MultipartPart.text(this.name, this.value)
      : filename = null,
        bytes = null;

  const MultipartPart.file(this.name, this.filename, this.bytes)
      : value = null;

  final String name;
  final String? value;
  final String? filename;
  final Uint8List? bytes;
}

class ApiClient {
  final AuthStore auth;
  final String baseUrl;
  final http.Client _http;
  final Duration _timeout;

  ApiClient({
    required this.auth,
    String? baseUrl,
    http.Client? httpClient,
    this._timeout = const Duration(seconds: 90),
  })  : baseUrl = baseUrl ?? AppConfig.apiBaseUrl,
        _http = httpClient ?? http.Client();

  // ---------------------------------------------------------------------
  // Convenience verbs
  // ---------------------------------------------------------------------

  Future<dynamic> getJson(String path, {Map<String, dynamic>? query}) async {
    final res = await _send('GET', path, query: query);
    return _decode(res, path);
  }

  Future<dynamic> postJson(
    String path, {
    Object? body,
    Map<String, dynamic>? query,
  }) async {
    final res = await _send(
      'POST',
      path,
      body: body == null ? null : jsonEncode(body),
      headers: const {'content-type': 'application/json'},
      query: query,
    );
    return _decode(res, path);
  }

  Future<dynamic> patchJson(
    String path, {
    Object? body,
    Map<String, dynamic>? query,
  }) async {
    final res = await _send(
      'PATCH',
      path,
      body: body == null ? null : jsonEncode(body),
      headers: const {'content-type': 'application/json'},
      query: query,
    );
    return _decode(res, path);
  }

  Future<dynamic> postMultipart(
    String path, {
    required List<MultipartPart> parts,
    Map<String, dynamic>? query,
  }) async {
    final res = await _sendMultipart(path, parts: parts, query: query);
    return _decode(res, path);
  }

  /// Downloads raw bytes (quarantine download / release). Returns the decoded
  /// response; callers read `.bodyBytes` and `.headers`.
  Future<http.Response> getBytes(String path,
      {Map<String, dynamic>? query}) async {
    final res = await _send('GET', path, query: query);
    if (res.statusCode >= 200 && res.statusCode < 300) return res;
    throw _decodeError(res, path);
  }

  /// Issues a `DELETE` request (quarantine deletion and admin user
  /// deactivation return 204).
  Future<void> delete(String path, {Map<String, dynamic>? query}) async {
    final res = await _send('DELETE', path, query: query);
    if (res.statusCode >= 200 && res.statusCode < 300) return;
    throw _decodeError(res, path);
  }

  // ---------------------------------------------------------------------
  // Core send logic
  // ---------------------------------------------------------------------

  Future<http.Response> _send(
    String method,
    String path, {
    Object? body,
    Map<String, String>? headers,
    Map<String, dynamic>? query,
    bool allowAuth = true,
    bool alreadyRefreshed = false,
  }) async {
    final uri = _uri(path, query);
    final request = http.Request(method, uri);
    if (headers != null) request.headers.addAll(headers);
    if (method != 'GET' && body != null) {
      request.body = body as String;
    }
    var usedCredential = false;
    if (allowAuth) {
      usedCredential = _applyCredential(request);
    }
    final response = await _sendRaw(request);

    if (response.statusCode == 401 &&
        usedCredential &&
        allowAuth &&
        !alreadyRefreshed &&
        auth.mode == AuthMode.bearer) {
      final refreshed = await _rotateRefreshToken();
      if (refreshed) {
        return _send(
          method,
          path,
          body: body,
          headers: headers,
          query: query,
          allowAuth: allowAuth,
          alreadyRefreshed: true,
        );
      }
    }
    return response;
  }

  /// Sends a request and normalises transport-level failures into typed
  /// [ApiException]s so callers never see raw `SocketException`/`Timeout`
  /// objects (and the UI never renders them).
  Future<http.Response> _sendRaw(http.BaseRequest request) async {
    try {
      final streamed = await _http.send(request).timeout(_timeout);
      return await http.Response.fromStream(streamed);
    } on TimeoutException {
      throw ApiException(
        code: 'network_timeout',
        message: 'The request timed out.',
        statusCode: 0,
        url: request.url.toString(),
      );
    } on ApiException {
      rethrow;
    } catch (_) {
      throw ApiException(
        code: 'network_unreachable',
        message:
            'Could not reach the security service (${request.url.host}:'
            '${request.url.port}).',
        statusCode: 0,
        url: request.url.toString(),
      );
    }
  }

  Future<http.Response> _sendMultipart(
    String path, {
    required List<MultipartPart> parts,
    Map<String, dynamic>? query,
    bool alreadyRefreshed = false,
  }) async {
    final request = http.MultipartRequest('POST', _uri(path, query));
    var usedCredential = _applyCredential(request);
    for (final part in parts) {
      if (part.bytes != null && part.filename != null) {
        request.files.add(http.MultipartFile.fromBytes(
          part.name,
          part.bytes!,
          filename: part.filename,
        ));
      } else {
        request.fields[part.name] = part.value ?? '';
      }
    }
    final response = await _sendRaw(request);

    if (response.statusCode == 401 &&
        usedCredential &&
        !alreadyRefreshed &&
        auth.mode == AuthMode.bearer) {
      final refreshed = await _rotateRefreshToken();
      if (refreshed) {
        return _sendMultipart(path,
            parts: parts, query: query, alreadyRefreshed: true);
      }
    }
    return response;
  }

  /// Rotates the refresh token. Returns `true` on success.
  ///
  /// Session handling is deliberate:
  /// - Explicit `401`/rejection from the refresh endpoint → the stored
  ///   credential is invalid or revoked → clear it so the UI returns to the
  ///   signed-out state with the clean "session expired" message.
  /// - Transport failure/timeout reaching the refresh endpoint → this is not
  ///   an auth problem; the session is kept so a flaky network does not log
  ///   the user out. The original request's error still surfaces to the
  ///   caller, mapped to a friendly "service unavailable" message.
  Future<bool> _rotateRefreshToken() async {
    final session = auth.session;
    if (session == null ||
        session.mode != AuthMode.bearer ||
        session.refreshToken == null ||
        session.refreshToken!.isEmpty) {
      await auth.clear();
      return false;
    }
    http.Response response;
    try {
      response = await _http
          .post(
            _uri('/api/v1/auth/refresh'),
            headers: const {'content-type': 'application/json'},
            body: jsonEncode({'refresh_token': session.refreshToken}),
          )
          .timeout(_timeout);
    } catch (_) {
      // Network problem during refresh — not an auth problem. Keep session.
      return false;
    }
    if (response.statusCode == 200) {
      final pair =
          TokenPair.fromJson(_decodeJson(response.body).cast<String, dynamic>());
      await auth.updateTokens(pair, remember: session.remember);
      return true;
    }
    if (response.statusCode == 401) {
      // Refresh token invalid/expired/revoked — the only case that clears.
      await auth.clear();
    }
    return false;
  }

  /// Attaches the current credential. Returns whether one was attached.
  bool _applyCredential(http.BaseRequest request) {
    final session = auth.session;
    if (session == null) return false;
    if (session.mode == AuthMode.apiKey) {
      request.headers['X-API-Key'] = session.accessToken;
    } else {
      request.headers['authorization'] = 'Bearer ${session.accessToken}';
    }
    return true;
  }

  // ---------------------------------------------------------------------
  // Decoding
  // ---------------------------------------------------------------------

  dynamic _decode(http.Response response, String path) {
    if (response.statusCode >= 200 && response.statusCode < 300) {
      if (response.body.isEmpty) return null;
      try {
        return _decodeJson(response.body);
      } catch (_) {
        throw ApiException(
          code: 'invalid_response',
          message: 'The server returned an unreadable response (HTTP '
              '${response.statusCode}).',
          statusCode: response.statusCode,
          url: path,
        );
      }
    }
    throw _decodeError(response, path);
  }

  ApiException _decodeError(http.Response response, String path) =>
      ApiException.fromResponse(response, url: path);

  dynamic _decodeJson(String body) => jsonDecode(body);

  Uri _uri(String path, [Map<String, dynamic>? query]) {
    final base = baseUrl.replaceFirst(RegExp(r'/+$'), '');
    final cleaned = path.startsWith('/') ? path : '/$path';
    final uri = Uri.parse('$base$cleaned');
    if (query == null || query.isEmpty) return uri;
    return uri.replace(
      queryParameters: query.map((key, value) => MapEntry(key, '$value')),
    );
  }
}