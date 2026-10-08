import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import 'package:cybershield_client/app.dart';
import 'package:cybershield_client/core/api_client.dart';
import 'package:cybershield_client/core/api_exception.dart';
import 'package:cybershield_client/core/auth_store.dart';
import 'package:cybershield_client/core/models/enums.dart';
import 'package:cybershield_client/core/models/user.dart';
import 'package:cybershield_client/core/session_controller.dart';
import 'package:cybershield_client/features/auth/sign_in_sheet.dart';
import 'package:cybershield_client/features/dashboard/dashboard_screen.dart';
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
    testWidgets('boots straight to the shell when unauthenticated',
        (tester) async {
      final auth = AuthStore();
      final session = SessionController(
        auth: auth,
        api: ApiClient(auth: auth),
        initialStatus: SessionStatus.unauthenticated,
      );
      addTearDown(session.dispose);

      await tester.pumpWidget(CybershieldApp(session: session));
      await tester.pumpAndSettle();

      expect(find.byType(AppShell), findsOneWidget);
      expect(find.text('Status'), findsAtLeastNWidgets(1));

      // AV-style security centre renders even without a session: the hero,
      // scan shortcuts and the honesty note are always visible.
      expect(find.text('Security Center'), findsWidgets);
      expect(find.text('Analysis engine ready'), findsOneWidget);
      expect(find.text('Device folder scan'), findsOneWidget);
      // First-run sign-in prompt is the front door of this build.
      expect(find.text('Sign in to store scans'), findsOneWidget);

      // The prompt, hero and section headers push the tiles below the fold of
      // the 600px test viewport, so scroll the dashboard's own scrollable.
      final dashboardScrollable = find
          .descendant(
            of: find.byType(DashboardScreen),
            matching: find.byType(Scrollable),
          )
          .first;
      await tester.scrollUntilVisible(
        find.text('Folder scan'),
        200,
        scrollable: dashboardScrollable,
      );
      expect(find.text('Folder scan'), findsOneWidget);
      await tester.scrollUntilVisible(
        find.text('APK scan'),
        200,
        scrollable: dashboardScrollable,
      );
      expect(find.text('APK scan'), findsOneWidget);

      // The honesty note sits below the fold in the test viewport; scroll the
      // dashboard's own scrollable to it.
      await tester.scrollUntilVisible(
        find.textContaining('Static analysis only'),
        200,
        scrollable: dashboardScrollable,
      );
      expect(
        find.textContaining('Static analysis only'),
        findsOneWidget,
      );
    });

    testWidgets('boots to the shell and renders navigation when authenticated',
        (tester) async {
      final auth = AuthStore();
      final session = SessionController(
        auth: auth,
        api: ApiClient(auth: auth),
        initialStatus: SessionStatus.authenticated,
      );
      session.user = const User(
        id: 'u-tester',
        email: 'tester@example.com',
        fullName: 'Test Runner',
        isActive: true,
        isVerified: true,
      );
      addTearDown(session.dispose);

      await tester.pumpWidget(CybershieldApp(session: session));
      // Network calls in tests hit the mocked 400 client and are handled
      // gracefully by each screen, so the tree settles to the shell.
      await tester.pumpAndSettle();

      expect(find.byType(AppShell), findsOneWidget);
      expect(find.text('Status'), findsAtLeastNWidgets(1));
      expect(find.text('Quarantine'), findsAtLeastNWidgets(1));

      // On mobile widths the secondary sections live behind the More sheet.
      await tester.tap(find.text('More'));
      await tester.pumpAndSettle();
      expect(find.text('Profile'), findsWidgets);
      expect(find.text('Threat Intel'), findsWidgets);
    });
  });
}