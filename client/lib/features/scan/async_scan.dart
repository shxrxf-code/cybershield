import 'package:flutter/material.dart';

import '../../core/api_exception.dart';
import '../../core/models/enums.dart';
import '../../core/models/scan.dart';
import '../report/report_screen.dart';

/// Kicks off an async scan submission and opens a report screen that polls the
/// job until it reaches a terminal state. Shared by every scan form.
Future<void> submitAsyncAndOpenReport(
  BuildContext context, {
  required Future<dynamic> Function() submit,
}) async {
  final data = await submit();
  final accepted = ScanAccepted.fromJson(
      Map<String, dynamic>.from(data as Map));
  if (!context.mounted) return;
  await Navigator.of(context).push(
    MaterialPageRoute<void>(
      builder: (_) => ReportScreen.polling(accepted.pollUrl),
    ),
  );
}

/// Polls `GET {pollUrl}` with growing backoff until the report is terminal.
Future<ScanReport> pollScanReport(
  dynamic Function(String path, {Map<String, dynamic>? query}) get,
  String pollUrl, {
  void Function(String status)? onProgress,
  bool isNotFoundRetryable = true,
}) async {
  var delay = const Duration(milliseconds: 700);
  final deadline = DateTime.now().add(const Duration(minutes: 6));
  var notFoundTries = 0;

  while (DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(delay);
    try {
      final data = await get(pollUrl);
      final report = ScanReport.fromScanDetail(
          Map<String, dynamic>.from(data as Map));
      onProgress?.call(report.status.api);
      if (report.status == ScanStatus.completed) {
        return report;
      }
      if (report.status == ScanStatus.failed) {
        throw ApiException(
          code: 'scan_failed',
          statusCode: 502,
          message: report.errorMessage ?? 'The scan failed on the server.',
        );
      }
    } on ApiException catch (e) {
      if (e.isNotFound && isNotFoundRetryable && notFoundTries < 3) {
        notFoundTries += 1;
        // Row not visible yet — keep waiting.
      } else {
        rethrow;
      }
    }
    delay = delay < const Duration(seconds: 6)
        ? delay * 2
        : const Duration(seconds: 6);
  }
  throw ApiException(
    code: 'scan_timeout',
    statusCode: 504,
    message: 'The scan did not finish in time. It may still be running — '
        'check your History later.',
  );
}