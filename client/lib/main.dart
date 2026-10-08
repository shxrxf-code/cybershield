/// CyberShield client entry point.
///
/// Boot sequence:
/// 1. Build the secure token store ([AuthStore]) and the API client on top of it.
/// 2. Create the app-wide [SessionController], which drives the root gate.
/// 3. Ask it to [SessionController.restore] any persisted "remember me"
///    session, then run the app.
library;

import 'package:flutter/material.dart';

import 'app.dart';
import 'core/api_client.dart';
import 'core/auth_store.dart';
import 'core/session_controller.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final auth = AuthStore();
  final api = ApiClient(auth: auth);
  final session = SessionController(auth: auth, api: api);

  // Restores a persisted session before the first frame settles so the
  // splash screen never flashes for fresh logins.
  await session.restore();

  runApp(CybershieldApp(session: session));
}