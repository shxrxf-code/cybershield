import 'package:flutter/material.dart';

import '../apps/apps_screen.dart';
import '../dashboard/dashboard_screen.dart';
import '../history/history_screen.dart';
import '../intel/intel_screen.dart';
import '../profile/profile_screen.dart';
import '../quarantine/quarantine_screen.dart';
import '../scan/scan_hub_screen.dart';

/// Root shell for the whole app (this build has no login screen, so the shell
/// is the app's front door).
///
/// - Wide layouts (>= 860dp): an antivirus-style `NavigationRail` with a brand
///   header and every section listed.
/// - Narrow/mobile layouts: a 5-destination Material 3 `NavigationBar` with
///   the secondary sections (Threat Intel, Apps, Profile) tucked behind a
///   "More" bottom sheet, so the bar never crowds a phone display.
class AppShell extends StatefulWidget {
  const AppShell({super.key});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  int _index = 0;
  int _scanTab = 0;

  /// Index of the "More" slot on the narrow bottom bar.
  static const int _moreSlot = 4;

  void _openScanTab(int tab) {
    setState(() {
      _scanTab = tab;
      _index = 1;
    });
  }

  Future<void> _openMoreSheet() async {
    final selected = await showModalBottomSheet<int>(
      context: context,
      showDragHandle: true,
      useSafeArea: true,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.travel_explore_outlined),
              title: const Text('Threat Intel'),
              onTap: () => Navigator.of(context).pop(4),
            ),
            ListTile(
              leading: const Icon(Icons.apps_outlined),
              title: const Text('Apps'),
              onTap: () => Navigator.of(context).pop(5),
            ),
            ListTile(
              leading: const Icon(Icons.person_outline_rounded),
              title: const Text('Profile'),
              onTap: () => Navigator.of(context).pop(6),
            ),
          ],
        ),
      ),
    );
    if (selected != null && mounted) {
      setState(() => _index = selected);
    }
  }

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 860;
    final pages = <Widget>[
      DashboardScreen(onOpenScan: _openScanTab),
      ScanHubScreen(tabIndex: _scanTab),
      const HistoryScreen(),
      const QuarantineScreen(),
      const IntelScreen(),
      const AppsScreen(),
      const ProfileScreen(),
    ];

    const railDestinations = [
      NavigationDestination(
        icon: Icon(Icons.shield_outlined),
        selectedIcon: Icon(Icons.shield_rounded),
        label: 'Status',
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
        icon: Icon(Icons.health_and_safety_outlined),
        selectedIcon: Icon(Icons.health_and_safety_rounded),
        label: 'Quarantine',
      ),
      NavigationDestination(
        icon: Icon(Icons.travel_explore_outlined),
        selectedIcon: Icon(Icons.travel_explore_rounded),
        label: 'Threat Intel',
      ),
      NavigationDestination(
        icon: Icon(Icons.apps_outlined),
        selectedIcon: Icon(Icons.apps_rounded),
        label: 'Apps',
      ),
      NavigationDestination(
        icon: Icon(Icons.person_outline_rounded),
        selectedIcon: Icon(Icons.person_rounded),
        label: 'Profile',
      ),
    ];

    const narrowDestinations = [
      NavigationDestination(
        icon: Icon(Icons.shield_outlined),
        selectedIcon: Icon(Icons.shield_rounded),
        label: 'Status',
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
        icon: Icon(Icons.health_and_safety_outlined),
        selectedIcon: Icon(Icons.health_and_safety_rounded),
        label: 'Quarantine',
      ),
      NavigationDestination(
        icon: Icon(Icons.more_horiz_rounded),
        selectedIcon: Icon(Icons.more_horiz_rounded),
        label: 'More',
      ),
    ];

    final body = IndexedStack(index: _index, children: pages);

    if (wide) {
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
              destinations: railDestinations
                  .map((d) => NavigationRailDestination(
                        icon: d.icon,
                        selectedIcon: d.selectedIcon,
                        label: Text(d.label),
                      ))
                  .toList(),
            ),
            const VerticalDivider(width: 1),
            Expanded(child: body),
          ],
        ),
      );
    }

    return Scaffold(
      body: body,
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index > 3 ? _moreSlot : _index,
        onDestinationSelected: (i) {
          if (i == _moreSlot) {
            _openMoreSheet();
          } else {
            setState(() => _index = i);
          }
        },
        destinations: narrowDestinations,
      ),
    );
  }
}