/// Central mapping from API/transport failures to user-safe messages.
///
/// This is the only place the app decides what text a user sees after a
/// failed request. Raw backend exception messages, stack traces, JWT errors,
/// database errors and internal API messages are never passed through to the
/// UI — every state maps to one of the friendly messages below.
library;

import 'api_exception.dart';

/// Shown when a stored session can no longer be refreshed.
const String sessionExpiredMessage =
    'Your security session has expired. Please sign in again.';

/// Shown when the backend cannot be reached at all (not an auth problem).
const String offlineMessage =
    'The security service is unavailable. Your device and local data are '
    'unaffected.';

/// A transport failure (host unreachable, connection refused, no network).
bool isOfflineError(ApiException e) =>
    e.statusCode == 0 && (e.code == 'network_unreachable' || e.code == 'http_error');

/// A timeout (client-side or HTTP 408).
bool isTimeoutError(ApiException e) =>
    e.code == 'network_timeout' || e.statusCode == 408;

/// A defect or unreachable backend — always something the user can retry.
bool isRetryable(ApiException e) =>
    isOfflineError(e) ||
    isTimeoutError(e) ||
    e.statusCode == 0 ||
    e.statusCode >= 500 ||
    e.isRateLimited;

/// Maps an [ApiException] (transport or HTTP) to a friendly, self-contained
/// message for the user. `signedIn` reflects the session state *at the time of
/// the request* so a 401 is framed as "expired" for signed-in users and as
/// "sign in first" for signed-out ones — never as backend JSON text.
String friendlyAppError(ApiException e, {required bool signedIn}) {
  if (isOfflineError(e)) return offlineMessage;
  if (isTimeoutError(e)) {
    return 'The security service is taking too long to respond. '
        'Please try again.';
  }
  if (e.isUnauthorized) {
    return signedIn
        ? sessionExpiredMessage
        : 'Sign in to use this feature. Scans are stored per account.';
  }
  switch (e.statusCode) {
    case 403:
      return 'You do not have permission to do that on this account.';
    case 404:
      return 'That item is no longer available.';
    case 413:
    case 415:
      return 'That file is too large (or its type is not accepted) for '
          'scanning here.';
    case 429:
      final wait = e.retryAfterSeconds;
      return wait != null && wait > 0
          ? 'Too many requests right now — try again in about $wait seconds.'
          : 'Too many requests right now. Wait a moment and try again.';
    case 422:
      return 'The request could not be validated. Check the input and try '
          'again.';
    case 503:
      return 'A scan engine is temporarily unavailable. Please try again '
          'shortly.';
    case >= 500:
      return 'A security service is temporarily unavailable. Please try '
          'again shortly.';
  }
  if (e.code == 'invalid_response') {
    return 'The security service returned an unreadable response. '
        'Try refreshing.';
  }
  return 'Something went wrong. Please try again.';
}