import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    testTimeout: 60_000,
    hookTimeout: 120_000,
    fileParallelism: false,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/index.ts', 'src/context/**', 'src/fixtures.ts'],
      reporter: ['text', 'json-summary'],
      // M0-AC17: the security kernel is fully covered.
      thresholds: { lines: 100, functions: 100, branches: 100, statements: 100 },
    },
  },
});
