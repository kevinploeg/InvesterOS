import { z } from 'zod';

const schema = z.object({
  OIDC_ISSUER: z.string().url(),
  OIDC_CLIENT_ID: z.string().min(1),
  OIDC_CLIENT_SECRET: z.string().min(1),
  APP_BASE_URL: z.string().url(),
  AUTH_STATE_SECRET: z.string().min(32),
  SESSION_ABSOLUTE_HOURS: z.coerce.number().int().positive().default(12),
  SESSION_IDLE_MINUTES: z.coerce.number().int().positive().default(30),
});

export interface AuthConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  baseUrl: string;
  redirectUri: string;
  stateSecret: string;
  absoluteTtlMs: number;
  idleSeconds: number;
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
    absoluteTtlMs: e.SESSION_ABSOLUTE_HOURS * 3_600_000,
    idleSeconds: e.SESSION_IDLE_MINUTES * 60,
    secureCookies: e.APP_BASE_URL.startsWith('https://'),
  };
}

export const sessionCookieName = (cfg: Pick<AuthConfig, 'secureCookies'>): string =>
  cfg.secureCookies ? '__Host-ios_session' : 'ios_session';
export const stateCookieName = (cfg: Pick<AuthConfig, 'secureCookies'>): string =>
  cfg.secureCookies ? '__Host-ios_oidc' : 'ios_oidc';
