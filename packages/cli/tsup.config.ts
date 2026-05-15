import { defineConfig } from 'tsup';
import pkg from './package.json';

export default defineConfig([
  {
    // ── CLI entry (shebang + commander) ──────────────────────────────────
    entry: ['src/index.ts'],
    format: ['cjs'],
    target: 'node18',
    platform: 'node',
    clean: true,
    sourcemap: false,
    dts: false,
    minify: false,
    splitting: false,
    bundle: true,
    banner: {
      js: '#!/usr/bin/env node',
    },
    define: {
      __VIBESCAN_VERSION__: JSON.stringify(pkg.version),
    },
    esbuildOptions(options) {
      options.conditions = ['node'];
    },
  },
  {
    // ── Library entry (no shebang — used by VSCode extension) ────────────
    entry: { lib: 'src/lib.ts' },
    format: ['cjs'],
    target: 'node18',
    platform: 'node',
    clean: false, // do not wipe the CLI output built above
    sourcemap: false,
    dts: false,
    minify: false,
    splitting: false,
    bundle: true,
    define: {
      __VIBESCAN_VERSION__: JSON.stringify(pkg.version),
    },
    esbuildOptions(options) {
      options.conditions = ['node'];
    },
  },
]);
