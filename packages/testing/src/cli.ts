import { writeFileSync } from 'node:fs';
import { adminUrlFor, dbEnv } from '@investoros/db';
import { seed } from './seed';

const database = process.env.DATABASE_NAME ?? 'investoros_dev';
const issuer = process.env.OIDC_ISSUER ?? 'http://127.0.0.1:4010';
const summary = await seed(adminUrlFor(dbEnv(), database), issuer);
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(summary, null, 2));
console.log(`seeded ${summary.tenants.length} tenants, ${summary.users.length} users (synthetic) into ${database}`);
