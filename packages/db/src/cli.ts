import pg from 'pg';
import { adminUrlFor, dbEnv, roleUrl } from './config';
import { bootstrap, migrate } from './migrate';
import { lintSchema } from './schema-lint';

const cmd = process.argv[2];
const env = dbEnv();
const database = process.env.DATABASE_NAME ?? 'investoros_dev';

async function main(): Promise<void> {
  switch (cmd) {
    case 'bootstrap':
      await bootstrap(env.adminUrl, database, env.passwords);
      console.log(`bootstrapped ${database}`);
      return;
    case 'migrate': {
      const applied = await migrate(process.env.DATABASE_MIGRATOR_URL ?? roleUrl(env, 'ios_migrator', database));
      console.log(applied.length ? `applied: ${applied.join(', ')}` : 'up to date');
      return;
    }
    case 'lint': {
      const c = new pg.Client({ connectionString: adminUrlFor(env, database) });
      await c.connect();
      const v = await lintSchema(c);
      await c.end();
      if (v.length) {
        console.error(JSON.stringify(v, null, 2));
        process.exit(1);
      }
      console.log('schema-lint: 0 violations');
      return;
    }
    default:
      console.error('usage: cli.ts bootstrap|migrate|lint');
      process.exit(2);
  }
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
