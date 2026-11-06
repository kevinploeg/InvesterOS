import { defineConfig } from '@playwright/test';

/**
 * E2E against a production build, a freshly seeded synthetic database (investoros_e2e) and the
 * local mock IdP. Requires DATABASE_ADMIN_URL (local/CI Postgres). Never points at shared environments.
 */
const env = {
  DATABASE_URL: 'postgres://ios_app:dev_app_password@127.0.0.1:5432/investoros_e2e',
  DATABASE_AUTH_URL: 'postgres://ios_auth:dev_auth_password@127.0.0.1:5432/investoros_e2e',
  OIDC_ISSUER: 'http://127.0.0.1:4010',
  OIDC_CLIENT_ID: 'investoros-web',
  OIDC_CLIENT_SECRET: 'e2e-client-secret',
  APP_BASE_URL: 'http://127.0.0.1:3000',
  AUTH_STATE_SECRET: 'ZTJlLW9ubHktc3RhdGUtc2VjcmV0LW5vdC1mb3ItcHJvZHVjdGlvbg==',
  NEXT_TELEMETRY_DISABLED: '1',
};
Object.assign(process.env, env);

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { baseURL: env.APP_BASE_URL, trace: 'off' },
  webServer: [
    {
      command: 'pnpm --filter @investoros/mock-oidc start',
      url: `${env.OIDC_ISSUER}/.well-known/openid-configuration`,
      env: { ...env, MOCK_OIDC_PORT: '4010' },
      reuseExistingServer: false,
    },
    {
      command: 'pnpm --filter @investoros/web start',
      url: `${env.APP_BASE_URL}/api/health`,
      env,
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
});
