/// App-wide session state: authentication lifecycle, current user, and access
/// to the shared [ApiClient] / [AuthStore].
///
/// Exposed to the widget tree through [AppScope] (an `InheritedNotifier`), so
/// any widget can read it with `AppScope.of(context)` and be rebuilt when the
/// session changes.
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'api_client.dart';
import 'api_exception.dart';
import 'app_errors.dart';
import 'auth_store.dart';
import 'models/token_pair.dart';
import 'models/user.dart';

enum SessionStatus { restoring, unauthenticated, authenticated }

class SessionController extends ChangeNotifier {
  SessionController({
    required this.auth,
    required this.api,
    SessionStatus initialStatus = SessionStatus.restoring,
  }) : status = initialStatus {
    auth.addListener(_onAuthChanged);
  }

  final AuthStore auth;
  final ApiClient api;

  SessionStatus status;
  User? user;
  String? bootError;

  bool get isAuthenticated => status == SessionStatus.authenticated;
  bool get isAdmin => user?.isAdmin ?? false;
  bool get usesApiKey => auth.mode == AuthMode.apiKey;

  @override
  void dispose() {
    auth.removeListener(_onAuthChanged);
    super.dispose();
  }

  /// Resumes a persisted "remember me" session at startup.
  Future<void> restore() async {
    status = SessionStatus.restoring;
    notifyListeners();
    await auth.restore();
    if (!auth.hasSession) {
      status = SessionStatus.unauthenticated;
      notifyListeners();
      return;
    }
    status = SessionStatus.authenticated;
    try {
      user = await _fetchMe();
    } on ApiException catch (e) {
      if (e.isUnauthorized) {
        // Stored tokens are stale or revoked; the AuthStore listener will
        // transition us to unauthenticated once cleared.
        await auth.clear();
        user = null;
      } else {
        // Server unreachable etc. — proceed logged-in; screens will surface
        // their own errors.
        bootError = friendlyAppError(e, signedIn: true);
      }
    } catch (_) {
      // Degrade gracefully; treat as an unusable network, not a logout.
      bootError ??= offlineMessage;
    }
    notifyListeners();
  }

  /// Password sign-in. Throws [ApiException] on failure.
  Future<void> signInWithPassword({
    required String email,
    required String password,
    required bool remember,
  }) async {
    final data = await api.postJson(
      '/api/v1/auth/login',
      body: {
        'email': email.trim().toLowerCase(),
        'password': password,
        'client': 'cybershield-flutter',
      },
    );
    final pair = TokenPair.fromJson(_toMap(data));
    await auth.storeBearerTokens(pair, remember: remember);
    try {
      user = await _fetchMe();
    } catch (_) {
      // Do not keep a half-authenticated session: if the account cannot be
      // read the sign-in did not complete, so roll the credential back.
      await auth.clear();
      user = null;
      rethrow;
    }
    status = SessionStatus.authenticated;
    notifyListeners();
  }

  /// API-key sign-in. The key is stored and used via `X-API-Key`.
  Future<void> signInWithApiKey(
    String apiKey, {
    required bool remember,
  }) async {
    await auth.storeApiKey(apiKey.trim(), remember: remember);
    try {
      user = await _fetchMe();
    } catch (_) {
      // Same contract as password sign-in: invalid keys roll back so a failed
      // sign-in leaves no false session behind.
      await auth.clear();
      user = null;
      rethrow;
    }
    status = SessionStatus.authenticated;
    notifyListeners();
  }

  Future<void> logout() async {
    if (auth.mode == AuthMode.bearer && auth.session != null) {
      try {
        await api.postJson('/api/v1/auth/logout');
      } on ApiException {
        // Best-effort server-side revocation; the local session clears anyway.
      } catch (_) {}
    }
    await auth.clear();
    user = null;
    status = SessionStatus.unauthenticated;
    notifyListeners();
  }

  Future<void> refreshUser() async {
    user = await _fetchMe();
    notifyListeners();
  }

  Future<User> _fetchMe() async {
    final data = await api.getJson('/api/v1/users/me');
    return User.fromJson(_toMap(data));
  }

  void _onAuthChanged() {
    if (!auth.hasSession && status == SessionStatus.authenticated) {
      user = null;
      status = SessionStatus.unauthenticated;
      notifyListeners();
    }
  }
}

Map<String, dynamic> _toMap(Object? data) {
  if (data is Map) return Map<String, dynamic>.from(data);
  if (data is String) {
    final decoded = jsonDecode(data);
    if (decoded is Map) return Map<String, dynamic>.from(decoded);
  }
  return <String, dynamic>{};
}