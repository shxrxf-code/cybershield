/**
 * Jest configuration.
 *
 * The React Native preset handles the RN core and assets. Two additions are
 * required by the app's dependencies:
 *
 * 1. `transformIgnorePatterns` allow-lists React Navigation (v7),
 *    react-native-screens, the safe-area library, lucide and zustand — they all
 *    ship untranspiled ESM.
 * 2. The `transform` is re-declared to include `.mjs`, because some of those
 *    packages (notably lucide-react-native) resolve their ESM entry point in
 *    the React Native Jest environment. The preset's asset transformer is kept
 *    so images and SVGs still resolve to stubs.
 * 3. `moduleNameMapper` maps the `src/` alias to the actual source directory.
 */
module.exports = {
  preset: '@react-native/jest-preset',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  moduleNameMapper: {
    '^src/(.*)$': '<rootDir>/src/$1',
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  transform: {
    '^.+\\.(js|jsx|ts|tsx|mjs|cjs)$': 'babel-jest',
    '^.+\\.(bmp|gif|jpg|jpeg|mp4|png|psd|svg|webp)$': require.resolve(
      '@react-native/jest-preset/jest/assetFileTransformer.js',
    ),
  },
  transformIgnorePatterns: [
    'node_modules/(?!((jest-)?react-native|@react-native(-community)?|@react-navigation|react-native-screens|react-native-safe-area-context|react-native-svg|lucide-react-native|zustand)/)',
  ],
};