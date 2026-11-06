import 'server-only';
import type pg from 'pg';
import { createPool, assertSyntheticDatabase } from '@investoros/kernel/db';
import { loadAuthConfig, type AuthConfig } from '@investoros/kernel/auth';

let pool: pg.Pool | undefined;
let authPool: pg.Pool | undefined;
let auth: AuthConfig | undefined;
let guard: Promise<void> | undefined;

function poolFor(envName: string, role: string): pg.Pool {
  const url = process.env[envName];
  if (!url) throw new Error(`${envName} missing`);
  if (!new RegExp(`^postgres(ql)?://${role}[:@]`).test(url)) throw new Error(`${envName} must use the ${role} role`);
  return createPool(url);
}

/** ios_app pool: every request. Never a privileged role. */
export function appPool(): pg.Pool {
  pool ??= poolFor('DATABASE_URL', 'ios_app');
  return pool;
}

/** ios_auth pool: ONLY the OIDC callback uses it, to create a session for a validated identity. */
export function sessionAuthPool(): pg.Pool {
  authPool ??= poolFor('DATABASE_AUTH_URL', 'ios_auth');
  return authPool;
}

export function authConfig(): AuthConfig {
  auth ??= loadAuthConfig();
  return auth;
}

export function ensureSynthetic(): Promise<void> {
  guard ??= assertSyntheticDatabase(appPool()).catch((e) => {
    guard = undefined;
    throw e;
  });
  return guard;
}
