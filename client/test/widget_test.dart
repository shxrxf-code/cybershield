import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import 'package:cybershield_client/app.dart';
import 'package:cybershield_client/core/api_client.dart';
import 'package:cybershield_client/core/api_exception.dart';
import 'package:cybershield_client/core/app_errors.dart';
import 'package:cybershield_client/core/auth_store.dart';
import 'package:cybershield_client/core/models/dashboard.dart';
import 'package:cybershield_client/core/models/enums.dart';
import 'package:cybershield_client/core/models/user.dart';
import 'package:cybershield_client/core/protection_status.dart';
import 'package:cybershield_client/core/scan_state.dart';
import 'package:cybershield_client/core/session_controller.dart';
import 'package:cybershield_client/features/auth/sign_in_sheet.dart';
import 'package:cybershield_client/features/dashboard/dashboard_screen.dart';
import 'package:cybershield_client/features/security/security_screen.dart';
import 'package:cybershield_client/features/shell/app_shell.dart';
import 'package:cybershield_client/widgets/verdict_style.dart';

void main() {
  group('verdict styling', () {
    test('verdict colours map to the fixed brand palette', () {
      expect(verdictColorFor(Verdict.safe), const Color(0xFF2FA84F));
      expect(verdictColorFor(Verdict.lowRisk), const Color(0xFF98C93C));
      expect(verdictColorFor(Verdict.suspicious), const Color(0xFFE8A33D));
      expect(verdictColorFor(Verdict.highRisk), const Color(0xFFE07B2D));
      expect(verdictColorFor(Verdict.malicious), const Color(0xFFD64545));
      expect(verdictColorFor(Verdict.unknown), const Color(0xFF8A93A6));
    });

    test('score bands label risk levels', () {
      expect(scoreBandLabel(0), 'SAFE');
      expect(scoreBandLabel(19), 'SAFE');
      expect(scoreBandLabel(20), 'LOW RISK');
      expect(scoreBandLabel(39), 'LOW RISK');
      expect(scoreBandLabel(40), 'SUSPICIOUS');
      expect(scoreBandLabel(59), 'SUSPICIOUS');
      expect(scoreBandLabel(60), 'HIGH RISK');
      expect(scoreBandLabel(79), 'HIGH RISK');
      expect(scoreBandLabel(80), 'MALICIOUS');
      expect(scoreBandLabel(100), 'MALICIOUS');
    });
  });

  group('API error envelope', () {
    http.Response envelope(
      Map<String, dynamic> error, {
      int status = 400,
      Map<String, String> headers = const {},
    }) =>
        http.Response(
          jsonEncode({'error': error}),
          status,
          headers: {'content-type': 'application/json', ...headers},
        );

    test('decodes the {"error": {...}} envelope', () {
      final e = ApiException.fromResponse(
        envelope({
          'code': 'validation_error',
          'message': 'URL must start with http',
          'status_code': 422,
          'correlation_id': 'corr-42',
          'details': {'field': 'url'},
        }, status: 422),
        url: '/api/v1/scans',
      );
      expect(e.code, 'validation_error');
      expect(e.message, 'URL must start with http');
      expect(e.statusCode, 422);
      expect(e.correlationId, 'corr-42');
      expect(e.details['field'], 'url');
      expect(e.url, '/api/v1/scans');
    });

    test('reads Retry-After header on 429 and never raw detail', () {
      final e = ApiException.fromResponse(
        envelope({
          'code': 'rate_limited',
          'message': 'Too many requests',
          'status_code': 429,
        }, status: 429, headers: {'retry-after': '37'}),
      );
      expect(e.isRateLimited, isTrue);
      expect(e.retryAfterSeconds, 37);
      expect(e.message, 'Too many requests');
    });

    test('falls back to retry_after_seconds in details', () {
      final e = ApiException.fromResponse(
        envelope({
          'code': 'rate_limited',
          'message': 'slow down',
          'status_code': 429,
          'details': {'retry_after_seconds': 5},
        }, status: 429),
      );
      expect(e.retryAfterSeconds, 5);
    });

    test('degrades when the body is not the envelope', () {
      final plain = ApiException.fromResponse(
        http.Response(jsonEncode({'detail': 'nope'}), 500),
      );
      expect(plain.code, 'http_error');
      expect(plain.statusCode, 500);
      expect(plain.message, contains('Unexpected response'));

      final forbidden = ApiException.fromResponse(http.Response('denied', 403));
      expect(forbidden.code, 'forbidden');
      expect(forbidden.isUnauthorized, isFalse);
    });
  });

  group('friendly error mapping', () {
    test('maps transport/HTTP failures to user-safe copy, never raw text', () {
      // Offline.
      expect(
        friendlyAppError(
            const ApiException(code: 'network_unreachable', statusCode: 0),
            signedIn: true),
        offlineMessage,
      );
      // Timeout (client-side and HTTP 408).
      expect(
        friendlyAppError(
            const ApiException(code: 'network_timeout', statusCode: 0),
            signedIn: true),
        contains('taking too long'),
      );
      expect(
        friendlyAppError(const ApiException(statusCode: 408), signedIn: true),
        contains('taking too long'),
      );
      // 401 framed by session state, never as backend text.
      expect(
        friendlyAppError(const ApiException(statusCode: 401), signedIn: true),
        sessionExpiredMessage,
      );
      expect(
        friendlyAppError(const ApiException(statusCode: 401), signedIn: false),
        contains('Sign in to use this feature'),
      );
      // Fixed status codes.
      expect(
        friendlyAppError(const ApiException(statusCode: 403), signedIn: true),
        contains('permission'),
      );
      expect(
        friendlyAppError(const ApiException(statusCode: 404), signedIn: true),
        'That item is no longer available.',
      );
      expect(
        friendlyAppError(const ApiException(statusCode: 413), signedIn: true),
        contains('too large'),
      );
      expect(
        friendlyAppError(const ApiException(statusCode: 429),
            signedIn: true),
        contains('Wait a moment'),
      );
      expect(
        friendlyAppError(
            const ApiException(
                statusCode: 429, retryAfterSeconds: 12),
            signedIn: true),
        contains('about 12 seconds'),
      );
      expect(
        friendlyAppError(const ApiException(statusCode: 503), signedIn: true),
        contains('scan engine'),
      );
      expect(
        friendlyAppError(const ApiException(statusCode: 500), signedIn: true),
        contains('temporarily unavailable'),
      );
      expect(
        friendlyAppError(const ApiException(code: 'invalid_response'),
            signedIn: true),
        contains('unreadable response'),
      );
      expect(
        friendlyAppError(const ApiException(), signedIn: true),
        'Something went wrong. Please try again.',
      );
    });

    test('retryability classification', () {
      expect(isOfflineError(const ApiException(code: 'network_unreachable')),
          isTrue);
      expect(isRetryable(const ApiException(statusCode: 500)), isTrue);
      expect(isRetryable(const ApiException(statusCode: 429)), isTrue);
      expect(isRetryable(const ApiException(statusCode: 408)), isTrue);
      expect(isRetryable(const ApiException(statusCode: 404)), isFalse);
      expect(isRetryable(const ApiException(statusCode: 401)), isFalse);
    });
  });

  group('scan state machine', () {
    test('runs the full phase lifecycle and reports honest progress', () {
      final scan = SecurityScan();
      addTearDown(scan.dispose);
      var notifications = 0;
      scan.addListener(() => notifications++);

      expect(scan.phase, ScanPhase.idle);
      expect(scan.phase.isRunning, isFalse);

      scan.start();
      expect(scan.phase, ScanPhase.initializing);
      expect(scan.isRunning, isTrue);
      expect(scan.progress.filesQueued, isNull);

      scan.beginScanning(queuedTotal: 10);
      expect(scan.phase, ScanPhase.scanning);
      expect(scan.progress.filesQueued, 10);
      expect(scan.progress.fraction, 0.0);

      scan.recordFileScanned();
      scan.recordFileScanned(threat: true);
      expect(scan.progress.filesProcessed, 2);
      expect(scan.progress.threatsDetected, 1);
      expect(scan.progress.fraction, 0.2);

      scan.pause();
      expect(scan.paused, isTrue);
      expect(scan.elapsed.isRunning, isFalse);
      scan.resume();
      expect(scan.paused, isFalse);
      expect(scan.elapsed.isRunning, isTrue);

      scan.complete();
      expect(scan.phase, ScanPhase.completed);
      expect(scan.phase.isTerminal, isTrue);
      expect(scan.isRunning, isFalse);
      expect(notifications, greaterThan(4));
    });

    test('fail(), cancel() and reset() reach the right states', () {
      final scan = SecurityScan();
      addTearDown(scan.dispose);

      scan.start();
      scan.setAnalyzing();
      scan.fail('A friendly message');
      expect(scan.phase, ScanPhase.failed);
      expect(scan.failureMessage, 'A friendly message');
      expect(scan.phase.isTerminal, isTrue);

      scan.reset();
      expect(scan.phase, ScanPhase.idle);
      expect(scan.failureMessage, isNull);

      scan.start();
      scan.completeWithThreat(threatsDetected: 3, objectsAnalyzed: 7);
      expect(scan.phase, ScanPhase.threatFound);
      expect(scan.progress.threatsDetected, 3);
      expect(scan.phase.isTerminal, isTrue);
      expect(scan.phase.isRunning, isFalse);

      scan.start();
      scan.cancel();
      expect(scan.phase, ScanPhase.cancelled);
    });
  });

  group('protection status engine', () {
    test('states are derived from real inputs only', () {
      ProtectionState s;
      s = protectionState(
          booting: true,
          signedIn: false,
          offline: false,
          engineReady: false,
          scanning: false);
      expect(s.status, ProtectionStatus.initializing);

      s = protectionState(
          booting: false,
          signedIn: true,
          offline: true,
          engineReady: false,
          scanning: false);
      expect(s.status, ProtectionStatus.offline);

      // Signed-out takes precedence over offline: an anonymous user is asked
      // to sign in, not told the service is down.
      s = protectionState(
          booting: false,
          signedIn: false,
          offline: true,
          engineReady: false,
          scanning: false);
      expect(s.status, ProtectionStatus.actionRequired);
      expect(s.title, 'Sign in to start scanning');

      s = protectionState(
          booting: false,
          signedIn: true,
          offline: false,
          engineReady: false,
          scanning: false);
      expect(s.status, ProtectionStatus.actionRequired);
      expect(s.title, 'Engine status unavailable');

      s = protectionState(
          booting: false,
          signedIn: true,
          offline: false,
          engineReady: true,
          scanning: true);
      expect(s.status, ProtectionStatus.scanning);
    });

    test('verdict counts drive warning / at-risk / protected states', () {
      ProtectionState s;
      s = protectionState(
          booting: false,
          signedIn: true,
          offline: false,
          engineReady: true,
          scanning: false,
          stats: const DashboardStats(
              maliciousCount: 1, highRiskCount: 1, totalScans: 9));
      expect(s.status, ProtectionStatus.atRisk);
      expect(s.isProblem, isTrue);

      s = protectionState(
          booting: false,
          signedIn: true,
          offline: false,
          engineReady: true,
          scanning: false,
          stats: const DashboardStats(suspiciousCount: 3, totalScans: 9));
      expect(s.status, ProtectionStatus.warning);

      s = protectionState(
          booting: false,
          signedIn: true,
          offline: false,
          engineReady: true,
          scanning: false,
          stats: const DashboardStats());
      expect(s.status, ProtectionStatus.protected);
      expect(s.title, 'Engine ready — nothing scanned yet');

      s = protectionState(
          booting: false,
          signedIn: true,
          offline: false,
          engineReady: true,
          scanning: false,
          stats: const DashboardStats(totalScans: 5, safeCount: 5));
      expect(s.status, ProtectionStatus.protected);
      expect(s.title, 'No threats detected');
      expect(s.isProtected, isTrue);
    });

    test('offline state is explicit', () {
      final s = offlineState();
      expect(s.status, ProtectionStatus.offline);
      expect(s.title, 'Security service unavailable');
      expect(s.subtitle, offlineMessage);
    });
  });

  group('sign-in sheet', () {
    testWidgets('switches between credentials and API-key modes',
        (tester) async {
      final auth = AuthStore();
      final session = SessionController(
        auth: auth,
        api: ApiClient(auth: auth),
        initialStatus: SessionStatus.unauthenticated,
      );
      addTearDown(session.dispose);

      await tester.pumpWidget(AppScope(
        session: session,
        child: MaterialApp(
          home: Scaffold(
            body: Builder(
              builder: (context) => Center(
                child: FilledButton(
                  onPressed: () => showSignInSheet(context),
                  child: const Text('open'),
                ),
              ),
            ),
          ),
        ),
      ));
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      // Credentials mode first: email + password fields.
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.byType(TextField), findsNWidgets(2));

      // Switch to API-key mode.
      await tester.tap(find.text('API key'));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsOneWidget);

      // And back to credentials.
      await tester.tap(find.text('Credentials'));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsNWidgets(2));
    });
  });

  group('root gate', () {
    SessionController makeSession({required SessionStatus initialStatus,
        bool signedIn = false}) {
      final auth = AuthStore();
      final session = SessionController(
        auth: auth,
        api: ApiClient(auth: auth),
        initialStatus: initialStatus,
      );
      if (signedIn || initialStatus == SessionStatus.authenticated) {
        session.user = const User(
          id: 'u-tester',
          email: 'tester@example.com',
          fullName: 'Test Runner',
          isActive: true,
          isVerified: true,
        );
      }
      addTearDown(session.dispose);
      return session;
    }

    void setLargeScreen(WidgetTester tester) {
      tester.view.physicalSize = const Size(1300, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
    }

    testWidgets('boots straight to the mobile shell when unauthenticated',
        (tester) async {
      final session =
          makeSession(initialStatus: SessionStatus.unauthenticated);

      await tester.pumpWidget(CybershieldApp(session: session));
      await tester.pumpAndSettle();

      expect(find.byType(AppShell), findsOneWidget);
      // The narrow layout uses the 5-destination bottom bar.
      final bar = tester.widget<NavigationBar>(find.byType(NavigationBar));
      expect(bar.selectedIndex, 0);
      expect(find.byType(NavigationRail), findsNothing);

      // Nav destinations.
      for (final label in ['Home', 'Scan', 'History', 'Security', 'Settings']) {
        expect(find.text(label), findsAtLeastNWidgets(1));
      }

      // First-run sign-in prompt is the front door of this build.
      expect(find.text('Sign in to store scans'), findsWidgets);
      // The hero primary action is always present (opens sign-in when out).
      expect(find.text('Scan now'), findsOneWidget);

      // Scroll the dashboard's own scrollable to the lower sections.
      final dashboardScrollable = find
          .descendant(
            of: find.byType(DashboardScreen),
            matching: find.byType(Scrollable),
          )
          .first;
      await tester.scrollUntilVisible(
        find.text('Protection modules'),
        200,
        scrollable: dashboardScrollable,
      );
      expect(find.text('File protection'), findsWidgets);
      // "Scan activity" lives below the fold of the lazy dashboard list, so
      // scroll it into view before asserting on it.
      await tester.scrollUntilVisible(
        find.text('Scan activity'),
        200,
        scrollable: dashboardScrollable,
      );
      expect(find.text('Scan activity'), findsWidgets);
      await tester.scrollUntilVisible(
        find.textContaining('Static analysis only'),
        200,
        scrollable: dashboardScrollable,
      );
      expect(find.textContaining('Static analysis only'), findsWidgets);
    });

    testWidgets('navigates the mobile bar and renders each section',
        (tester) async {
      final session = makeSession(initialStatus: SessionStatus.unauthenticated);

      await tester.pumpWidget(CybershieldApp(session: session));
      await tester.pumpAndSettle();

      Finder nav(String label) => find.descendant(
          of: find.byType(NavigationBar), matching: find.text(label));

      // History.
      await tester.tap(nav('History'));
      await tester.pumpAndSettle();
      expect(
          tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex,
          2);
      expect(find.text('Sign in to view scan history'), findsWidgets);

      // Security (Protection & Permissions centre).
      await tester.tap(nav('Security'));
      await tester.pumpAndSettle();
      expect(
          tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex,
          3);
      expect(find.text('Protection status'), findsWidgets);
      expect(find.text('Sign in to activate'), findsWidgets);

      // The capability and battery sections sit below the fold of the lazy
      // security list — scroll them into view before asserting.
      final securityScrollable = find
          .descendant(
            of: find.byType(SecurityScreen),
            matching: find.byType(Scrollable),
          )
          .first;
      await tester.scrollUntilVisible(
        find.text('Permissions & capabilities'),
        200,
        scrollable: securityScrollable,
      );
      expect(find.text('Permissions & capabilities'), findsWidgets);
      await tester.scrollUntilVisible(
        find.text('Battery & background'),
        200,
        scrollable: securityScrollable,
      );
      expect(find.text('Battery & background'), findsWidgets);

      // Settings.
      await tester.tap(nav('Settings'));
      await tester.pumpAndSettle();
      expect(
          tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex,
          4);
      expect(find.text('Sign in'), findsWidgets);

      // Back to Home.
      await tester.tap(nav('Home'));
      await tester.pumpAndSettle();
      expect(
          tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex,
          0);
    });

    testWidgets('authenticated dashboards reach the full-scan screen',
        (tester) async {
      final session =
          makeSession(initialStatus: SessionStatus.authenticated);

      await tester.pumpWidget(CybershieldApp(session: session));
      await tester.pumpAndSettle();

      expect(find.byType(AppShell), findsOneWidget);
      expect(find.text('Sign out'), findsNothing);

      // Open the full-device scan from the Home hero.
      await tester.tap(find.text('Scan now'));
      await tester.pumpAndSettle();
      expect(find.text('Full device scan'), findsWidgets);
      expect(find.text('What a full scan covers'), findsWidgets);
      expect(find.text('My home folder'), findsWidgets);
    });

    testWidgets('desktop rail lists every section including secondary tools',
        (tester) async {
      setLargeScreen(tester);
      final session = makeSession(initialStatus: SessionStatus.unauthenticated);

      await tester.pumpWidget(CybershieldApp(session: session));
      await tester.pumpAndSettle();

      final rail = tester.widget<NavigationRail>(find.byType(NavigationRail));
      expect(rail.selectedIndex, 0);
      expect(find.byType(NavigationBar), findsNothing);

      for (final label in [
        'Home',
        'Scan',
        'History',
        'Quarantine',
        'Threat Intel',
        'Apps',
        'Security',
        'Settings',
      ]) {
        expect(find.text(label), findsAtLeastNWidgets(1));
      }

      Finder railLabel(String label) => find.descendant(
          of: find.byType(NavigationRail), matching: find.text(label));

      await tester.tap(railLabel('Threat Intel'));
      await tester.pumpAndSettle();
      expect(
          tester.widget<NavigationRail>(find.byType(NavigationRail))
              .selectedIndex,
          4);
      // The Intel page is reachable from the desktop rail. With no session it
      // shows its honest signed-out state (the reputation search card is
      // account-gated), which still proves the rail navigated there.
      expect(find.text('Sign in to search threat intelligence'), findsWidgets);
    });
  });
}