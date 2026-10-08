/// Persists the current credential (bearer token pair or API key) in
/// `flutter_secure_storage` and exposes it to the rest of the app.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'models/token_pair.dart';

enum AuthMode { bearer, apiKey }

/// An authenticated credential the client holds, in memory.
class AuthSession {
  const AuthSession({
    required this.mode,
    required this.accessToken,
    this.refreshToken,
    this.remember = true,
  });

  final AuthMode mode;

  /// Bearer access token, or the API key in `apiKey` mode.
  final String accessToken;
  final String? refreshToken;
  final bool remember;
}

class AuthStore extends ChangeNotifier {
  static const _keyMode = 'cs.mode';
  static const _keyAccess = 'cs.access';
  static const _keyRefresh = 'cs.refresh';
  static const _keyRemember = 'cs.remember';

  final FlutterSecureStorage _storage;

  AuthStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  AuthSession? _session;

  AuthSession? get session => _session;

  bool get hasSession => _session != null;

  AuthMode get mode => _session?.mode ?? AuthMode.bearer;

  /// Loads any stored credential so a previous "remember me" session can be
  /// resumed after an app restart.
  Future<void> restore() async {
    final modeRaw = await _read(_keyMode);
    final access = await _read(_keyAccess);
    if (access == null || access.isEmpty) {
      _session = null;
      return;
    }
    final mode = modeRaw == 'api_key' ? AuthMode.apiKey : AuthMode.bearer;
    final refresh = mode == AuthMode.bearer ? await _read(_keyRefresh) : null;
    final remember = (await _read(_keyRemember)) == '1';
    _session = AuthSession(
      mode: mode,
      accessToken: access,
      refreshToken: refresh,
      remember: remember,
    );
    // Notify listeners only when something actually changed.
    notifyListeners();
  }

  Future<void> storeBearerTokens(
    TokenPair pair, {
    required bool remember,
  }) async {
    _session = AuthSession(
      mode: AuthMode.bearer,
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      remember: remember,
    );
    await _persist(pair.accessToken, pair.refreshToken, remember: remember);
    notifyListeners();
  }

  Future<void> storeApiKey(
    String apiKey, {
    required bool remember,
  }) async {
    _session = AuthSession(
      mode: AuthMode.apiKey,
      accessToken: apiKey,
      remember: remember,
    );
    await _persist(apiKey, null, remember: remember);
    notifyListeners();
  }

  Future<void> updateTokens(
    TokenPair pair, {
    required bool remember,
  }) async {
    final current = _session;
    if (current == null || current.mode != AuthMode.bearer) return;
    _session = AuthSession(
      mode: AuthMode.bearer,
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      remember: remember,
    );
    await _persist(pair.accessToken, pair.refreshToken, remember: remember);
    notifyListeners();
  }

  Future<void> _persist(String access, String? refresh,
      {required bool remember}) async {
    await _storage.write(key: _keyMode, value: refresh == null ? 'api_key' : 'bearer');
    await _storage.write(key: _keyAccess, value: access);
    if (refresh != null) {
      await _storage.write(key: _keyRefresh, value: refresh);
    } else {
      await _storage.delete(key: _keyRefresh);
    }
    await _storage.write(key: _keyRemember, value: remember ? '1' : '0');
  }

  /// Clears the credential in memory and storage. Safe to call when nothing
  /// is stored.
  Future<void> clear() async {
    _session = null;
    await _storage.delete(key: _keyMode);
    await _storage.delete(key: _keyAccess);
    await _storage.delete(key: _keyRefresh);
    await _storage.delete(key: _keyRemember);
    notifyListeners();
  }

  Future<String?> _read(String key) async {
    try {
      return await _storage.read(key: key);
    } catch (_) {
      return null;
    }
  }
}