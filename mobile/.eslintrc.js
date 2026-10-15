module.exports = {
  root: true,
  extends: '@react-native',
  env: {
    jest: true,
  },
  rules: {
    // `void promise` is the deliberate idiom used throughout this codebase for
    // fire-and-forget work whose errors are already handled internally. The
    // rule still reports `void` used in expression position; only the
    // statement form (the idiom) is allowed.
    'no-void': ['error', { allowAsStatement: true }],
  },
};
