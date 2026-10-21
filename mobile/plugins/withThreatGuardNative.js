/**
 * withThreatGuardNative — Expo config plugin for Mobile ThreatGuard.
 *
 * The app is a *bare* Expo project: the checked-in `android/` directory is the
 * source of truth and is edited by hand, so this plugin is normally dormant.
 * It exists so that every hand-made native customization would be re-applied
 * if the native project were ever regenerated with `npx expo prebuild` (for
 * example by an EAS cloud build that does not commit `android/`).
 *
 * The customizations it preserves are exactly the deviations of `android/`
 * from the upstream Expo/RN template, documented in
 * docs/migration/expo-migration-report.md:
 *
 *   1. MainApplication.kt registers ThreatGuard's three hand-written native
 *      packages (FileScanner, NotificationMonitor, AppInspection).
 *   2. AndroidManifest.xml declares POST_NOTIFICATIONS, the Android 11+
 *      <queries> package-visibility block used by App Inspection, and the two
 *      notification services (foreground monitor + NotificationListenerService).
 *   3. android/build.gradle contains the op-sqlite `debug` build type patch
 *      (the library ships a `release` build type only).
 *   4. res/values styles/colors provide the dark splash screen theme
 *      (Theme.App.SplashScreen, background #070C16).
 *
 * Every step is idempotent: running prebuild twice, or running the plugin
 * against a tree that already contains the changes, is a no-op.
 */

const fs = require('fs');
const path = require('path');

const {
  withAndroidManifest,
  withDangerousMod,
  createRunOncePlugin,
} = require('@expo/config-plugins');

const PKG = 'com.threatguard.mobile';

// ---------------------------------------------------------------------------
// 1. MainApplication.kt — native package registration
// ---------------------------------------------------------------------------

const MAIN_APPLICATION_IMPORTS = [
  'import com.threatguard.mobile.appinspection.AppInspectionPackage',
  'import com.threatguard.mobile.notification.NotificationMonitorPackage',
  'import com.threatguard.mobile.scanner.FileScannerPackage',
].join('\n');

const MAIN_APPLICATION_REGISTRATIONS = [
  'add(FileScannerPackage())',
  'add(NotificationMonitorPackage())',
  'add(AppInspectionPackage())',
].join('\n          ');

const withThreatGuardPackages = (config) =>
  withDangerousMod(config, [
    'android',
    (cfg) => {
      const file = path.join(
        cfg.modRequest.platformProjectRoot,
        'app/src/main/java/com/threatguard/mobile/MainApplication.kt'
      );
      let src = fs.readFileSync(file, 'utf8');

      // Imports: anchor on the Expo host import, which every Expo template
      // MainApplication.kt contains.
      if (!src.includes('FileScannerPackage')) {
        const importAnchor = 'import expo.modules.ExpoReactHostFactory';
        if (!src.includes(importAnchor)) {
          throw new Error(
            '[withThreatGuardNative] MainApplication.kt does not contain the expected ' +
              `'${importAnchor}' anchor; the Expo template layout changed. Update ` +
              'plugins/withThreatGuardNative.js to match the new template.'
          );
        }
        src = src.replace(importAnchor, `${importAnchor}\n\n${MAIN_APPLICATION_IMPORTS}`);
      }

      // Registrations: anchor on the template's placeholder comment inside
      // `PackageList(this).packages.apply { ... }`.
      if (!src.includes('add(FileScannerPackage())')) {
        const addAnchor = '// add(MyReactNativePackage())';
        if (!src.includes(addAnchor)) {
          throw new Error(
            '[withThreatGuardNative] MainApplication.kt does not contain the expected ' +
              `'${addAnchor}' anchor inside packages.apply { }; cannot insert native ` +
              'package registrations safely. Update plugins/withThreatGuardNative.js.'
          );
        }
        src = src.replace(
          addAnchor,
          `// add(MyReactNativePackage())\n          //\n          // ThreatGuard's own native modules are plain React Native packages (not npm\n          // packages, so autolinking cannot see them) and are registered here by hand.\n          ${MAIN_APPLICATION_REGISTRATIONS}`
        );
      }

      fs.writeFileSync(file, src);
      return cfg;
    },
  ]);

// ---------------------------------------------------------------------------
// 2. AndroidManifest.xml — permissions, <queries>, notification services
// ---------------------------------------------------------------------------

// The notification-monitoring service is itself the NotificationListenerService:
// the intent-filter below is what system settings matches when the user grants
// notification access to ThreatGuard. The BIND_ permission keeps it private.
const NOTIFICATION_MONITOR_SERVICE = {
  $: {
    'android:name': '.notification.NotificationMonitorService',
    'android:label': '@string/app_name',
    'android:exported': 'false',
    'android:permission': 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
  },
  'intent-filter': [
    {
      action: [
        { $: { 'android:name': 'android.service.notification.NotificationListenerService' } },
      ],
    },
  ],
};

// Package visibility for the App Inspection module (Android 11+): mirrors the
// hand-written <queries> block in android/app/src/main/AndroidManifest.xml.
const QUERIES_BLOCK = [
  {
    intent: [
      {
        action: [{ $: { 'android:name': 'android.intent.action.MAIN' } }],
        category: [{ $: { 'android:name': 'android.intent.category.LAUNCHER' } }],
      },
    ],
  },
  {
    intent: [
      {
        action: [{ $: { 'android:name': 'android.intent.action.VIEW' } }],
        category: [{ $: { 'android:name': 'android.intent.category.DEFAULT' } }],
        data: [{ $: { 'android:scheme': 'https' } }],
      },
    ],
  },
  {
    intent: [
      {
        action: [{ $: { 'android:name': 'android.intent.action.SEND' } }],
        data: [{ $: { 'android:mimeType': 'text/plain' } }],
      },
    ],
  },
  {
    intent: [
      {
        action: [{ $: { 'android:name': 'android.intent.action.SENDTO' } }],
        data: [{ $: { 'android:scheme': 'mailto' } }],
      },
    ],
  },
  {
    intent: [{ action: [{ $: { 'android:name': 'android.intent.action.DIAL' } }] }],
  },
];

const withThreatGuardManifest = (config) =>
  withAndroidManifest(config, (cfg) => {
    const manifest = cfg.modResults.manifest;

    // 2a. Permissions: the plugin is idempotent, so re-declaring the two the
    // app needs is safe — withAndroidManifest runs on the prebuild-generated
    // manifest, which lacks POST_NOTIFICATIONS unless app.json adds it.
    manifest['uses-permission'] = manifest['uses-permission'] ?? [];
    const declared = new Set(
      manifest['uses-permission'].map((p) => p.$ && p.$['android:name']).filter(Boolean)
    );
    for (const permission of [
      'android.permission.INTERNET',
      'android.permission.POST_NOTIFICATIONS',
    ]) {
      if (!declared.has(permission)) {
        manifest['uses-permission'].push({ $: { 'android:name': permission } });
      }
    }

    // 2b. <queries> package visibility — required by the App Inspection module
    // on Android 11+, and by the notification listener intent resolution.
    if (!manifest.queries) {
      manifest.queries = QUERIES_BLOCK;
    }

    // 2c. Notification-monitoring / listener service.
    const application = manifest.application?.[0];
    if (!application) {
      throw new Error('[withThreatGuardNative] Generated AndroidManifest has no <application>.');
    }
    application.service = application.service ?? [];
    const serviceNames = new Set(
      application.service.map((s) => s.$ && s.$['android:name']).filter(Boolean)
    );
    if (!serviceNames.has('.notification.NotificationMonitorService')) {
      application.service.push(NOTIFICATION_MONITOR_SERVICE);
    }

    return cfg;
  });

// ---------------------------------------------------------------------------
// 3. android/build.gradle — op-sqlite debug build type patch
// ---------------------------------------------------------------------------

const OP_SQLITE_PATCH = `

/**
 * @op-engineering/op-sqlite publishes its Android library with a \`release\`
 * build type only, but the app's \`debug\` variant needs a matching \`debug\` build
 * type (and the prefab it produces). Adding it here keeps the fix in versioned
 * source instead of patching node_modules, which \`npm install\` would discard.
 *
 * This is idempotent: if a future release of the library already declares a
 * \`debug\` build type, this block simply reconfigures it.
 *
 * NOTE: this is one of the custom native modifications that
 * \`plugins/withThreatGuardNative.js\` re-applies during \`expo prebuild\`.
 */
subprojects { subproject ->
    if (subproject.name == 'op-engineering_op-sqlite') {
        subproject.plugins.withId('com.android.library') {
            subproject.android {
                buildTypes {
                    debug {
                        minifyEnabled false
                        debuggable true
                    }
                }
            }
        }
    }
}
`;

const withOpSqliteDebugBuildType = (config) =>
  withDangerousMod(config, [
    'android',
    (cfg) => {
      const file = path.join(cfg.modRequest.platformProjectRoot, 'build.gradle');
      let src = fs.readFileSync(file, 'utf8');
      if (!src.includes('op-engineering_op-sqlite')) {
        src = `${src.replace(/\s*$/, '')}\n${OP_SQLITE_PATCH}`;
        fs.writeFileSync(file, src);
      }
      return cfg;
    },
  ]);

// ---------------------------------------------------------------------------
// 4. Splash screen resources — dark background matching the app theme
// ---------------------------------------------------------------------------

const SPLASH_STYLE = `  <style name="Theme.App.SplashScreen" parent="AppTheme">
    <item name="android:windowBackground">@color/splashscreen_background</item>
  </style>
`;

const SPLASH_COLOR = `  <!-- Matches ThemeColors.background (slate-950) in src/theme/tokens.ts, so the
       native splash screen flows straight into the app's dark background with no
       colour flash on launch. -->
  <color name="splashscreen_background">#070C16</color>
`;

const withThreatGuardSplash = (config) =>
  withDangerousMod(config, [
    'android',
    (cfg) => {
      const resDir = path.join(cfg.modRequest.platformProjectRoot, 'app/src/main/res/values');

      const stylesFile = path.join(resDir, 'styles.xml');
      let styles = fs.readFileSync(stylesFile, 'utf8');
      if (!styles.includes('Theme.App.SplashScreen')) {
        styles = styles.replace('</resources>', `${SPLASH_STYLE}</resources>`);
        fs.writeFileSync(stylesFile, styles);
      }

      const colorsFile = path.join(resDir, 'colors.xml');
      const colors = fs.existsSync(colorsFile) ? fs.readFileSync(colorsFile, 'utf8') : '<resources>\n</resources>\n';
      if (!colors.includes('splashscreen_background')) {
        fs.writeFileSync(colorsFile, colors.replace('</resources>', `${SPLASH_COLOR}</resources>`));
      }

      return cfg;
    },
  ]);

// ---------------------------------------------------------------------------

const pkg = require('../package.json');

module.exports = createRunOncePlugin(
  withThreatGuardNative,
  pkg.name,
  pkg.version
);

function withThreatGuardNative(config) {
  config = withThreatGuardPackages(config);
  config = withThreatGuardManifest(config);
  config = withOpSqliteDebugBuildType(config);
  config = withThreatGuardSplash(config);
  return config;
}
