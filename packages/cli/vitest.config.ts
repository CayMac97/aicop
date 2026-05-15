import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30_000,
    include: ['tests/**/*.test.ts'],
  },
  resolve: {
    // Allow '.js' extension imports (used in TypeScript source) to resolve to '.ts'
    extensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  },
});
