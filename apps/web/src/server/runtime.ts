import 'server-only';
import type pg from 'pg';
import { createPool, assertSyntheticDatabase } from '@investoros/kernel/db';
import { loadAuthConfig, type AuthConfig } from '@investoros/kernel/auth';

let pool: pg.Pool | undefined;
let auth: AuthConfig | undefined;
let guard: Promise<void> | undefined;

/** ios_app pool. Never a privileged role. */
export function appPool(): pg.Pool {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL missing');
  if (/\/\/(postgres|ios_owner|ios_migrator)[:@]/.test(url)) throw new Error('DATABASE_URL must use the ios_app role');
  pool ??= createPool(url);
  return pool;
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
