import { z } from 'zod';

const schema = z.object({
  OIDC_ISSUER: z.string().url(),
  OIDC_CLIENT_ID: z.string().min(1),
  OIDC_CLIENT_SECRET: z.string().min(1),
  APP_BASE_URL: z.string().url(),
  AUTH_STATE_SECRET: z.string().min(32),
});

/** Session lifetimes are database policy (meta.auth_policy), not app configuration. */
export interface AuthConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  baseUrl: string;
  redirectUri: string;
  stateSecret: string;
  /** Secure cookies (and the __Host- prefix) whenever the app is served over https. */
  secureCookies: boolean;
}

export function loadAuthConfig(env: NodeJS.ProcessEnv = process.env): AuthConfig {
  const e = schema.parse(env);
  return {
    issuer: e.OIDC_ISSUER,
    clientId: e.OIDC_CLIENT_ID,
    clientSecret: e.OIDC_CLIENT_SECRET,
    baseUrl: e.APP_BASE_URL,
    redirectUri: new URL('/auth/callback', e.APP_BASE_URL).toString(),
    stateSecret: e.AUTH_STATE_SECRET,
    secureCookies: e.APP_BASE_URL.startsWith('https://'),
  };
}

export const sessionCookieName = (cfg: Pick<AuthConfig, 'secureCookies'>): string =>
  cfg.secureCookies ? '__Host-ios_session' : 'ios_session';
export const stateCookieName = (cfg: Pick<AuthConfig, 'secureCookies'>): string =>
  cfg.secureCookies ? '__Host-ios_oidc' : 'ios_oidc';
