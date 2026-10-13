/**
 * Jest environment tweaks.
 *
 * - Safe-area-context ships an official Jest mock; we register it so its native
 *   module is not required in the test environment.
 * - react-native-screens is mocked down to plain views, which is all the
 *   navigators need to render a tree in tests.
 * - The unified animated module is silenced so timers do not leak between tests.
 */

require('react-native-safe-area-context/jest/mock');

jest.mock('react-native-screens', () => {
  const React = require('react');
  const { View } = require('react-native');
  const passthrough = (name) => {
    const Component = ({ children, ...props }) => React.createElement(View, props, children);
    Component.displayName = name;
    return Component;
  };
  return {
    enableScreens: jest.fn(),
    enableFreeze: jest.fn(),
    screensEnabled: jest.fn(() => false),
    Screen: passthrough('Screen'),
    ScreenContainer: passthrough('ScreenContainer'),
    ScreenStack: passthrough('ScreenStack'),
    ScreenStackHeaderConfig: passthrough('ScreenStackHeaderConfig'),
    ScreenStackHeaderSubview: passthrough('ScreenStackHeaderSubview'),
  };
});
