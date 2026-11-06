import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { adminUrlFor, bootstrap, dbEnv, migrate, roleUrl } from '@investoros/db';
import { seed } from '@investoros/testing';

const SEED_FILE = join(import.meta.dirname, '.seed.json');

/** Prepares the synthetic E2E database. Runs BEFORE Playwright starts the web servers. */
async function prepare(): Promise<void> {
  const env = dbEnv();
  const name = 'investoros_e2e';
  const admin = new pg.Client({ connectionString: env.adminUrl });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.end();
  await bootstrap(env.adminUrl, name, env.passwords);
  await migrate(roleUrl(env, 'ios_migrator', name));
  const summary = await seed(adminUrlFor(env, name), process.env.OIDC_ISSUER ?? 'http://127.0.0.1:4010');
  writeFileSync(SEED_FILE, JSON.stringify(summary, null, 2));
}

await prepare();
console.log('e2e database prepared (synthetic)');
