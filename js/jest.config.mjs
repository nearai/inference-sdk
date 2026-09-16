export default {
  testTimeout: 60 * 1000,
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: 'tsconfig.test.json' }],
    '^.+\\.js$': [
      'ts-jest',
      { tsconfig: { allowJs: true, module: 'CommonJS' } },
    ],
  },
  // jose is ESM-only; run its real cryptographic implementation in these CJS tests.
  transformIgnorePatterns: ['/node_modules/(?!.*jose/)'],
};
