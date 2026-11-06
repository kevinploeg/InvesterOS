/** Connection settings. Defaults are for local/CI synthetic databases only. */
export interface DbEnv {
  adminUrl: string;
  host: string;
  port: number;
  passwords: { app: string; migrator: string; worker: string };
}

export function dbEnv(env: NodeJS.ProcessEnv = process.env): DbEnv {
  const adminUrl = env.DATABASE_ADMIN_URL ?? 'postgres://postgres@127.0.0.1:5432/postgres';
  const u = new URL(adminUrl);
  return {
    adminUrl,
    host: u.hostname,
    port: Number(u.port || 5432),
    passwords: {
      app: env.IOS_APP_PASSWORD ?? 'dev_app_password',
      migrator: env.IOS_MIGRATOR_PASSWORD ?? 'dev_migrator_password',
      worker: env.IOS_WORKER_PASSWORD ?? 'dev_worker_password',
    },
  };
}

export function roleUrl(env: DbEnv, role: 'ios_app' | 'ios_worker' | 'ios_migrator', database: string): string {
  const pw = role === 'ios_app' ? env.passwords.app : role === 'ios_worker' ? env.passwords.worker : env.passwords.migrator;
  return `postgres://${role}:${encodeURIComponent(pw)}@${env.host}:${env.port}/${database}`;
}

export function adminUrlFor(env: DbEnv, database: string): string {
  const u = new URL(env.adminUrl);
  u.pathname = `/${database}`;
  return u.toString();
}
