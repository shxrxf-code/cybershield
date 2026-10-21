/**
 * @format
 *
 * Expo entry point.
 *
 * `registerRootComponent` registers the app with the React Native runtime
 * (component name "main") and sets up the environment Expo expects, which is
 * what `expo-dev-client` and the dev launcher load. This replaces the previous
 * `AppRegistry.registerComponent(name from app.json)` call, which cannot be
 * kept because the app name now lives inside the Expo config block.
 */

import { registerRootComponent } from 'expo';

import App from './App';

registerRootComponent(App);
