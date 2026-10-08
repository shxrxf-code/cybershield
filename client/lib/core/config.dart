/// Static application configuration.
///
/// The API base URL is configurable at build time via
/// `--dart-define=API_BASE_URL=...` and defaults to the local development
/// backend.
class AppConfig {
  AppConfig._();

  static const String appName = 'CyberShield';

  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://localhost:8000',
  );

  /// Hard ceiling enforced by the backend (settings.max_upload_bytes).
  static const int maxUploadBytes = 100 * 1024 * 1024;

  static const int maxUploadMib = maxUploadBytes ~/ (1024 * 1024);

  /// Default page size for list endpoints.
  static const int pageSize = 20;

  /// Backend-reported minimum password length (settings.password_min_length).
  static const int passwordMinLength = 12;
}