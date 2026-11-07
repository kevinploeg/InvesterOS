/**
 * D8 benchmark (indicative; local hardware). Synthetic data only.
 *   pnpm --filter @investoros/kernel bench
 * Measures the per-transaction cost of the DB-verified context (auth.begin + ON COMMIT DELETE ROWS)
 * and RLS query cost on 10k securables / 1M child rows.
 */
import pg from 'pg';
import { createTestDatabase } from '@investoros/db';
import * as fx from '../src/fixtures';

const N = Number(process.env.BENCH_ITER ?? 2000);
const pct = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor((p / 100) * xs.length))]!;
const fmt = (xs: number[]) => `p50 ${pct(xs, 50).toFixed(3)} ms · p95 ${pct(xs, 95).toFixed(3)} ms · p99 ${pct(xs, 99).toFixed(3)} ms`;

async function time(c: pg.Client, n: number, body: () => Promise<unknown>): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    await body();
    out.push(performance.now() - t);
  }
  return out;
}

const db = await createTestDatabase({ probe: true });
const admin = new pg.Client({ connectionString: db.adminUrl });
await admin.connect();
try {
  const T = await fx.createTenant(admin, 'bench');
  const uid = await fx.createUser(admin, { email: 'bench@synthetic.test', displayName: 'Bench', issuer: 'https://idp.synthetic.test', subject: 'bench' });
  const mid = await fx.addMembership(admin, T.id, uid);
  await fx.assignRole(admin, T.id, T.roles.investment_professional, { membershipId: mid });
  const cred = await fx.login(admin, uid, { expiresInSeconds: 86400 });
  // 10k securables (10% restricted), grants on 100 restricted ones, 1M child rows.
  await admin.query(`INSERT INTO securables (tenant_id, id, kind, classification)
    SELECT $1, gen_random_uuid(), 'project', CASE WHEN g % 10 = 0 THEN 'restricted' ELSE 'standard' END FROM generate_series(1, 10000) g`, [T.id]);
  await admin.query(`INSERT INTO securable_grants (tenant_id, id, securable_id, membership_id, access, granted_by)
    SELECT $1, gen_random_uuid(), id, $2, 'read', $2 FROM securables WHERE tenant_id = $1 AND classification = 'restricted' LIMIT 100`, [T.id, mid]);
  await admin.query(`INSERT INTO probe_notes (tenant_id, id, securable_id, body)
    SELECT $1, gen_random_uuid(), s.id, 'n' FROM securables s, generate_series(1, 100) g WHERE s.tenant_id = $1`, [T.id]);
  await admin.query('ANALYZE');

  const c = new pg.Client({ connectionString: db.appUrl });
  await c.connect();
  const tok = cred.reveal();
  const tx = (mode: string, sql?: string) => async () => {
    await c.query('BEGIN');
    await c.query('SELECT auth.begin($1, $2, $3)', [tok, 'bench', mode]);
    if (sql) await c.query(sql);
    await c.query('COMMIT');
  };
  await time(c, 200, tx('read')); // warm-up
  const baseline = await time(c, N, async () => { await c.query('BEGIN'); await c.query('SELECT 1'); await c.query('COMMIT'); });
  const read = await time(c, N, tx('read'));
  const write = await time(c, N, tx('write'));
  const iam = await time(c, N, tx('iam'));
  const pointQuery = await time(c, N, tx('read', `SELECT id FROM teams LIMIT 1`));
  const one = (await admin.query(`SELECT id FROM securables WHERE tenant_id = $1 AND classification = 'standard' LIMIT 1`, [T.id])).rows[0].id;
  const childBySecurable = await time(c, 500, tx('read', `SELECT count(*) FROM probe_notes WHERE securable_id = '${one}'`));
  const fullCount = await time(c, 5, tx('read', `SELECT count(*) FROM probe_notes`));
  await c.query('BEGIN');
  await c.query('SELECT auth.begin($1, $2, $3)', [tok, 'bench', 'read']);
  const visible = (await c.query('SELECT count(*)::int AS n FROM probe_notes')).rows[0].n;
  await c.query('COMMIT');
  await c.end();

  console.log(`Postgres ${(await admin.query('SHOW server_version')).rows[0].server_version}; iterations ${N}`);
  console.log(`baseline BEGIN/SELECT 1/COMMIT        ${fmt(baseline)}`);
  console.log(`auth.begin read  + COMMIT             ${fmt(read)}`);
  console.log(`auth.begin write + COMMIT             ${fmt(write)}`);
  console.log(`auth.begin iam   + COMMIT             ${fmt(iam)}`);
  console.log(`read + point query under RLS          ${fmt(pointQuery)}`);
  console.log(`read + child rows of 1 securable (100)${fmt(childBySecurable)}`);
  console.log(`read + count(*) over 1M child rows    ${fmt(fullCount)}  (visible: ${visible} of 1000000)`);
} finally {
  await admin.end();
  await db.drop();
}
