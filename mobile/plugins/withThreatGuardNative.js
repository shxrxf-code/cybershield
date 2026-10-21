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
 *   5. ios/Info.plist declares CFBundleURLSchemes=threatguard, the iOS half of
 *      the expo-dev-client deep-link scheme (the Android half is in item 2).
 *
 * Every step is idempotent: running prebuild twice, or running the plugin
 * against a tree that already contains the changes, is a no-op.
 */

const fs = require('fs');
const path = require('path');

const {
  withAndroidManifest,
  withDangerousMod,
  withInfoPlist,
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
// Only `<intent>` entries are listed here; `<package>` entries, if ever needed,
// go in QUERIES_BLOCK_PACKAGES.
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

const QUERIES_BLOCK_PACKAGES = [];

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
    // on Android 11+. Expo's prebuild already emits a <queries> block containing
    // only a VIEW/https intent, so the threats below are merged into whatever is
    // there instead of being skipped: losing the DIAL/MAIN/SEND entries would
    // silently break package enumeration at runtime.
    manifest.queries = manifest.queries ?? [];
    const queryBlock = manifest.queries[0] ?? {};
    queryBlock.intent = queryBlock.intent ?? [];
    const queryKeys = new Set(
      queryBlock.intent.map((i) => JSON.stringify(i.action?.[0]?.$?.['android:name'] ?? ''))
    );
    for (const intent of QUERIES_BLOCK) {
      const key = JSON.stringify(intent.intent?.[0]?.action?.[0]?.$?.['android:name'] ?? '');
      if (!queryKeys.has(key)) {
        queryBlock.intent.push(intent.intent[0]);
        queryKeys.add(key);
      }
    }
    if (queryBlock.package === undefined && QUERIES_BLOCK_PACKAGES.length > 0) {
      queryBlock.package = QUERIES_BLOCK_PACKAGES;
    }
    manifest.queries[0] = queryBlock;

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

    // 2d. Deep-link scheme for expo-dev-client (threatguard://). Expo generates
    // this from app.json's `scheme`, but the project is bare-first, so it is
    // asserted here as well to keep the checked-in and regenerated projects in
    // step.
    const mainActivity = (application.activity ?? []).find(
      (a) => a.$ && a.$['android:name'] === '.MainActivity'
    );
    if (mainActivity) {
      mainActivity['intent-filter'] = mainActivity['intent-filter'] ?? [];
      const hasScheme = mainActivity['intent-filter'].some((f) =>
        (f.data ?? []).some((d) => d.$ && d.$['android:scheme'] === 'threatguard')
      );
      if (!hasScheme) {
        mainActivity['intent-filter'].push({
          action: [{ $: { 'android:name': 'android.intent.action.VIEW' } }],
          category: [
            { $: { 'android:name': 'android.intent.category.DEFAULT' } },
            { $: { 'android:name': 'android.intent.category.BROWSABLE' } },
          ],
          data: [{ $: { 'android:scheme': 'threatguard' } }],
        });
      }
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
    <item name="android:windowBackground">@drawable/splashscreen_logo</item>
  </style>
`;

// Expo's own splash generation hard-codes a white splashscreen_background and a
// splashscreen_logo drawable (SDK 58 ships splash handling inside `expo`; there
// is no expo-splash-screen config plugin in this project). ThreatGuard's palette
// is dark, so the colour is overridden here to ThemeColors.background
// (slate-950, src/theme/tokens.ts) — the theme keeps the logo drawable, so the
// result is the app mark on a dark field instead of a white flash.
const SPLASH_COLOR = `  <color name="splashscreen_background">#070C16</color>
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
      let colors = fs.existsSync(colorsFile)
        ? fs.readFileSync(colorsFile, 'utf8')
        : '<resources>\n</resources>\n';
      if (/<color name="splashscreen_background">[^<]*<\/color>/.test(colors)) {
        // Override the value generated by Expo, which defaults to white.
        colors = colors.replace(
          /<color name="splashscreen_background">[^<]*<\/color>/,
          SPLASH_COLOR.trim()
        );
      } else {
        colors = colors.replace('</resources>', `${SPLASH_COLOR}</resources>`);
      }
      fs.writeFileSync(colorsFile, colors);

      // Fail loudly rather than shipping a wrong-coloured splash.
      const finalColors = fs.readFileSync(colorsFile, 'utf8');
      if (!finalColors.includes('#070C16')) {
        throw new Error(
          '[withThreatGuardNative] splashscreen_background was not set to #070C16; ' +
            'the Expo splash template changed. Update plugins/withThreatGuardNative.js.'
        );
      }

      return cfg;
    },
  ]);

// ---------------------------------------------------------------------------
// 5. ios/Info.plist — CFBundleURLSchemes for expo-dev-client
// ---------------------------------------------------------------------------
//
// `expo start --dev-client` only advertises the dev-client launcher URI when the
// scheme is present in *both* native projects. The Android intent filter is
// asserted above; this keeps the iOS half in step so the checked-in ios/ tree
// does not warn at start-up. app.json's `scheme` produces this on prebuild too.
const withThreatGuardIosScheme = (config) =>
  withInfoPlist(config, (cfg) => {
    const SCHEME = 'threatguard';
    const urlTypes = cfg.modResults.CFBundleURLTypes ?? [];
    const declared = urlTypes.some((t) =>
      (t.CFBundleURLSchemes ?? []).includes(SCHEME)
    );
    if (!declared) {
      urlTypes.push({ CFBundleURLSchemes: [SCHEME] });
    }
    cfg.modResults.CFBundleURLTypes = urlTypes;
    return cfg;
  });

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
  config = withThreatGuardIosScheme(config);
  return config;
}
