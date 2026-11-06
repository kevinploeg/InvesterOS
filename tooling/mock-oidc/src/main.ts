import { startMockOidc } from './server';

const base = process.env.APP_BASE_URL ?? 'http://127.0.0.1:3000';
const port = Number(process.env.MOCK_OIDC_PORT ?? 4010);
const oidc = await startMockOidc({
  port,
  clients: [{ id: process.env.OIDC_CLIENT_ID ?? 'investoros-web', secret: process.env.OIDC_CLIENT_SECRET ?? 'dev-client-secret', redirectUris: [`${base}/auth/callback`] }],
});
console.log(`mock OIDC issuer listening at ${oidc.issuer} (DEV/TEST ONLY)`);
