import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/node.ts'],
  format: ['esm'],
  platform: 'neutral',
  target: 'es2022',
  external: ['node:crypto', 'node:https', 'node:stream'],
  splitting: false,
  dts: true,
  sourcemap: true,
});
