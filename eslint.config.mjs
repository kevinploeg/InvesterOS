import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['.dependency-cruiser.cjs', '**/node_modules/**', '**/.next/**', '**/coverage/**', 'playwright-report/**', 'test-results/**', '**/next-env.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
  {
    // The web app never talks to Postgres except through the kernel, and never uses test fixtures.
    files: ['apps/web/**/*.{ts,tsx}'],
    ignores: ['apps/web/src/server/runtime.ts'],
    rules: {
      'no-restricted-imports': ['error', {
        paths: [
          { name: 'pg', message: 'Use @investoros/kernel/db (withTenantTx) — never raw pg in the app.' },
          { name: '@investoros/kernel/fixtures', message: 'Fixtures bypass RLS: tests and seed only.' },
          { name: '@investoros/testing', message: 'Test-only package.' },
          { name: '@investoros/mock-oidc', message: 'Dev/test-only IdP.' },
        ],
      }],
    },
  },
);
