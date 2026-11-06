/** Module-boundary rules (M0-AC1). Violations fail CI. */
module.exports = {
  forbidden: [
    { name: 'no-circular', severity: 'error', from: {}, to: { circular: true } },
    {
      name: 'fixtures-are-test-only',
      comment: 'Fixtures use an admin connection that bypasses RLS.',
      severity: 'error',
      from: { path: '^(apps|packages/kernel/src/(?!fixtures))', pathNot: '\\.(test|spec)\\.ts$' },
      to: { path: 'packages/kernel/src/fixtures\\.ts$' },
    },
    {
      name: 'test-tooling-not-in-runtime',
      severity: 'error',
      from: { path: '^(apps/web|packages/kernel/src|packages/db/src)' },
      to: { path: '^(packages/testing|tooling/mock-oidc)' },
    },
    {
      name: 'kernel-does-not-know-apps',
      severity: 'error',
      from: { path: '^packages/' },
      to: { path: '^apps/' },
    },
    {
      name: 'raw-pg-only-in-kernel-db',
      comment: 'All runtime DB access goes through kernel/db transaction helpers.',
      severity: 'error',
      from: { path: '^(apps/web|packages/kernel/src)', pathNot: '^(packages/kernel/src/(db|fixtures)|apps/web/src/server/runtime)' },
      to: { path: 'node_modules/(\\.pnpm/)?pg(@|/)', dependencyTypesNot: ['type-only'] },
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    exclude: { path: '(\\.next|coverage|node_modules/\\.pnpm/(?!pg@))' },
    tsPreCompilationDeps: true,
    tsConfig: { fileName: 'tsconfig.base.json' },
    enhancedResolveOptions: { exportsFields: ['exports'], conditionNames: ['import', 'require', 'node', 'default', 'types'] },
  },
};
