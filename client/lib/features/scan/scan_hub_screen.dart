import 'package:flutter/material.dart';

import 'device_scan_form.dart';
import 'email_scan_form.dart';
import 'file_scan_form.dart';
import 'text_scan_form.dart';
import 'url_scan_form.dart';

/// Stable tab indices for each scan type. Other screens (e.g. the dashboard
/// quick tiles) reference these so the hub can be reordered without breaking
/// navigation.
abstract final class ScanTab {
  static const int device = 0;
  static const int url = 1;
  static const int email = 2;
  static const int text = 3;
  static const int file = 4;
  static const int apk = 5;
}

/// Landing point for every scan type, organised as tabs. The device scan is
/// the default tab because it is the most common on-device workflow.
class ScanHubScreen extends StatefulWidget {
  const ScanHubScreen({super.key, this.tabIndex = ScanTab.device});

  final int tabIndex;

  @override
  State<ScanHubScreen> createState() => _ScanHubScreenState();
}

class _ScanHubScreenState extends State<ScanHubScreen>
    with TickerProviderStateMixin {
  static const int _tabCount = 6;

  late final TabController _controller;

  @override
  void initState() {
    super.initState();
    _controller = TabController(
      length: _tabCount,
      vsync: this,
      initialIndex: widget.tabIndex.clamp(0, _tabCount - 1),
    );
  }

  @override
  void didUpdateWidget(covariant ScanHubScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.tabIndex != oldWidget.tabIndex &&
        widget.tabIndex >= 0 &&
        widget.tabIndex < _tabCount) {
      _controller.animateTo(widget.tabIndex);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan'),
        bottom: TabBar(
          controller: _controller,
          isScrollable: true,
          tabAlignment: TabAlignment.start,
          tabs: const [
            Tab(text: 'Device'),
            Tab(text: 'URL'),
            Tab(text: 'Email'),
            Tab(text: 'Text'),
            Tab(text: 'File'),
            Tab(text: 'APK'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _controller,
        children: const [
          DeviceScanForm(),
          UrlScanForm(),
          EmailScanForm(),
          TextScanForm(),
          FileScanForm(kind: FileScanKind.file),
          FileScanForm(kind: FileScanKind.apk),
        ],
      ),
    );
  }
}