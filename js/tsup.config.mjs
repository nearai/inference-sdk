import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/node.ts'],
  format: ['esm'],
  platform: 'neutral',
  target: 'es2022',
  external: ['node:crypto', 'node:https', 'node:stream'],
  // Keep Sigstore's tested dependency graph inside the build. Its crypto
  // package's outdated peer range otherwise breaks strict consumer installs.
  noExternal: [
    /^@freedomofpress\/(sigstore-browser|tuf-browser|crypto-browser)(\/|$)/,
    /^@noble\/(curves|hashes)(\/|$)/,
  ],
  splitting: false,
  dts: true,
  sourcemap: true,
});
