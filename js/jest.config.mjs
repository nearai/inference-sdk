export default {
  testTimeout: 60 * 1000,
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: 'tsconfig.test.json' }],
    '^.+\\.js$': [
      'ts-jest',
      { tsconfig: { allowJs: true, module: 'CommonJS' } },
    ],
  },
  // These browser-compatible dependencies publish ESM only.
  transformIgnorePatterns: ['/node_modules/(?!.*(?:@freedomofpress|@noble|jose)/)'],
};
