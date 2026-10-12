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

  // -----------------------------------------------------------------------
  // Demo login (development convenience)
  // -----------------------------------------------------------------------
  //
  // When [demoLogin] is true the sign-in sheet pre-fills the credentials below
  // so a reviewer can start a session with a single tap. These match the
  // accounts created by `backend/scripts/seed_dev.py`; they are development
  // credentials and grant nothing in a real deployment.
  //
  // Real builds must pass `--dart-define=DEMO_LOGIN=false` (or build in release
  // mode, which disables the pre-fill unless DEMO_LOGIN is set explicitly).
  static const bool demoLogin = bool.fromEnvironment(
    'DEMO_LOGIN',
    defaultValue: true,
  );

  static const String demoEmail = String.fromEnvironment(
    'DEMO_EMAIL',
    defaultValue: 'analyst@cybershield.dev',
  );

  static const String demoPassword = String.fromEnvironment(
    'DEMO_PASSWORD',
    defaultValue: 'CyberShield!dev2026-Analyst',
  );
}