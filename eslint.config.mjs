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
          { name: 'next/cache', importNames: ['unstable_cache', 'cacheLife', 'cacheTag'], message: 'Tenant data must never enter a shared cache (C3). Fetch per request inside withTenantTx.' },
        ],
      }],
      // C3: no shared caching of tenant data. The "use cache" directive is banned in the app.
      'no-restricted-syntax': ['error',
        { selector: "ExpressionStatement[directive='use cache']", message: "'use cache' is not allowed: tenant data must not be cached across requests (C3)." },
        { selector: "ExpressionStatement[directive='use cache: remote']", message: "'use cache' is not allowed (C3)." },
        { selector: "ExpressionStatement[directive='use cache: private']", message: "'use cache' is not allowed (C3)." },
      ],
    },
  },
);
