import 'package:flutter/material.dart';

import '../apps/apps_screen.dart';
import '../dashboard/dashboard_screen.dart';
import '../history/history_screen.dart';
import '../intel/intel_screen.dart';
import '../profile/profile_screen.dart';
import '../quarantine/quarantine_screen.dart';
import '../scan/scan_hub_screen.dart';
import '../security/security_screen.dart';

/// Root shell for the whole app (this build has no login screen, so the shell
/// is the app's front door).
///
/// Mobile-first layout, per product spec:
/// - Narrow (< 600dp): a 5-item Material 3 `NavigationBar` with the primary
///   destinations — Home, Scan, History, Security, Settings. Secondary tools
///   (Quarantine, Threat Intel, Apps) live on the Security screen and are
///   pushed as routes, so the bar never crowds a phone display.
/// - Tablet (600–1024dp): the same five entries; content renders in two
///   columns (see the Home / Scan screens' own breakpoints).
/// - Desktop (>= 1024dp): a `NavigationRail` lists every section including
///   the secondary tools.
class AppShell extends StatefulWidget {
  const AppShell({super.key});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  /// Pages indexed for the rail; the rail lists every section as destinations.
  static const int home = 0;
  static const int scan = 1;
  static const int history = 2;
  static const int security = 6;
  static const int settings = 7;

  /// Bottom-bar order on narrow layouts (the five primary destinations).
  static const List<int> narrowPages = [home, scan, history, security, settings];

  int _index = 0;
  int _scanTab = 0;

  void _openScanTab(int tab) {
    setState(() {
      _scanTab = tab;
      _index = scan;
    });
  }

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    final desktop = width >= 1024;
    final pages = <Widget>[
      DashboardScreen(onOpenScan: _openScanTab),
      ScanHubScreen(tabIndex: _scanTab),
      const HistoryScreen(),
      const QuarantineScreen(),
      const IntelScreen(),
      const AppsScreen(),
      const SecurityScreen(),
      const ProfileScreen(),
    ];

    const railDestinations = [
      NavigationRailDestination(
        icon: Icon(Icons.shield_outlined),
        selectedIcon: Icon(Icons.shield_rounded),
        label: Text('Home'),
      ),
      NavigationRailDestination(
        icon: Icon(Icons.radar_rounded),
        selectedIcon: Icon(Icons.radar_rounded),
        label: Text('Scan'),
      ),
      NavigationRailDestination(
        icon: Icon(Icons.history_outlined),
        selectedIcon: Icon(Icons.history_rounded),
        label: Text('History'),
      ),
      NavigationRailDestination(
        icon: Icon(Icons.health_and_safety_outlined),
        selectedIcon: Icon(Icons.health_and_safety_rounded),
        label: Text('Quarantine'),
      ),
      NavigationRailDestination(
        icon: Icon(Icons.travel_explore_outlined),
        selectedIcon: Icon(Icons.travel_explore_rounded),
        label: Text('Threat Intel'),
      ),
      NavigationRailDestination(
        icon: Icon(Icons.apps_outlined),
        selectedIcon: Icon(Icons.apps_rounded),
        label: Text('Apps'),
      ),
      NavigationRailDestination(
        icon: Icon(Icons.security_rounded),
        selectedIcon: Icon(Icons.security_rounded),
        label: Text('Security'),
      ),
      NavigationRailDestination(
        icon: Icon(Icons.settings_outlined),
        selectedIcon: Icon(Icons.settings_rounded),
        label: Text('Settings'),
      ),
    ];

    const narrowDestinations = [
      NavigationDestination(
        icon: Icon(Icons.shield_outlined),
        selectedIcon: Icon(Icons.shield_rounded),
        label: 'Home',
      ),
      NavigationDestination(
        icon: Icon(Icons.radar_rounded),
        selectedIcon: Icon(Icons.radar_rounded),
        label: 'Scan',
      ),
      NavigationDestination(
        icon: Icon(Icons.history_outlined),
        selectedIcon: Icon(Icons.history_rounded),
        label: 'History',
      ),
      NavigationDestination(
        icon: Icon(Icons.security_rounded),
        selectedIcon: Icon(Icons.security_rounded),
        label: 'Security',
      ),
      NavigationDestination(
        icon: Icon(Icons.settings_outlined),
        selectedIcon: Icon(Icons.settings_rounded),
        label: 'Settings',
      ),
    ];

    final body = IndexedStack(index: _index, children: pages);

    if (desktop) {
      final scheme = Theme.of(context).colorScheme;
      return Scaffold(
        body: Row(
          children: [
            NavigationRail(
              selectedIndex: _index,
              onDestinationSelected: (i) => setState(() => _index = i),
              leading: Padding(
                padding: const EdgeInsets.fromLTRB(8, 16, 8, 20),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 46,
                      height: 46,
                      decoration: BoxDecoration(
                        color: scheme.primary,
                        borderRadius: BorderRadius.circular(14),
                        boxShadow: [
                          BoxShadow(
                            color: scheme.primary.withValues(alpha: 0.4),
                            blurRadius: 14,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                      child: Icon(Icons.shield_rounded,
                          color: scheme.onPrimary, size: 28),
                    ),
                    const SizedBox(height: 10),
                    Text(
                      'CyberShield',
                      style: Theme.of(context)
                          .textTheme
                          .labelLarge
                          ?.copyWith(fontWeight: FontWeight.w800),
                    ),
                    Text(
                      'static analyzer',
                      style: Theme.of(context)
                          .textTheme
                          .labelSmall
                          ?.copyWith(
                              color: scheme.onSurfaceVariant,
                              letterSpacing: 0.4),
                    ),
                  ],
                ),
              ),
              labelType: NavigationRailLabelType.all,
              groupAlignment: -0.9,
              destinations: railDestinations,
            ),
            const VerticalDivider(width: 1),
            Expanded(child: body),
          ],
        ),
      );
    }

    final barSlot = narrowPages.indexOf(_index);
    return Scaffold(
      body: body,
      bottomNavigationBar: NavigationBar(
        selectedIndex: barSlot < 0 ? 0 : barSlot,
        onDestinationSelected: (i) => setState(() => _index = narrowPages[i]),
        destinations: narrowDestinations,
      ),
    );
  }
}