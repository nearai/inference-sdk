export default {
  testMatch: ['<rootDir>/test/**/*.spec.ts'],
  testTimeout: 60 * 1000,
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: 'tsconfig.test.json' }],
    '^.+\\.m?js$': [
      'ts-jest',
      { tsconfig: { allowJs: true, module: 'CommonJS' } },
    ],
  },
  // These browser-compatible dependencies publish ESM only.
  transformIgnorePatterns: [
    '/node_modules/(?!.*(?:@freedomofpress|@noble|jose|hpke|ohttp-ts|bhttp-ts|quicvarint)/)',
  ],
};
