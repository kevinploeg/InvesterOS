import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { redact, writeAudit } from '../src/audit';
import { assertSyntheticDatabase, withAnonymousTx, withTenantTx, withUserTx } from '../src/db';
import { isUuid, newId } from '../src/ids';
import { AuthenticationError, NotFoundError } from '../src/errors';
import * as fx from '../src/fixtures';
import { asApp, harness, ISSUER, staffSettings, type Harness } from './helpers';

let h: Harness;
let T: fx.TenantFixture;
let userId: string;
let membershipId: string;

beforeAll(async () => {
  h = await harness();
  T = await fx.createTenant(h.admin, 'audit-co');
  userId = await fx.createUser(h.admin, { email: 'aud@synthetic.test', displayName: 'Aud', issuer: ISSUER, subject: 'aud' });
  membershipId = await fx.addMembership(h.admin, T.id, userId);
  await fx.assignRole(h.admin, T.id, T.roles.admin, { membershipId });
});
afterAll(async () => h?.close());

describe('ids and errors', () => {
  it('UUIDv7 ids are valid and time-ordered', () => {
    const a = newId();
    const b = newId();
    expect(isUuid(a)).toBe(true);
    expect(a[14]).toBe('7');
    expect(a < b).toBe(true);
    expect(isUuid('nope')).toBe(false);
    expect(isUuid(42)).toBe(false);
  });
  it('error types carry HTTP semantics', () => {
    expect(new AuthenticationError().status).toBe(401);
    expect(new NotFoundError().status).toBe(404);
    expect(new NotFoundError().message).toBe('Not found');
  });
});

describe('transaction helpers', () => {
  it('reject malformed identifiers before touching the database', () => {
    const ctx = fx.staffContext(T, userId, membershipId);
    expect(() => withTenantTx(h.app, { ...ctx, tenantId: 'x' }, async () => 1)).toThrow(/invalid tenantId/);
    expect(() => withTenantTx(h.app, { ...ctx, membershipId: 'x' }, async () => 1)).toThrow(/invalid principal/);
    expect(() => withUserTx(h.app, 'x', async () => 1)).toThrow(/invalid userId/);
  });

  it('system context sets principal_type=system and no user', async () => {
    const r = await withTenantTx(h.app, { tenantId: T.id, principalType: 'system', jobName: 'test', requestId: 'r' }, (tx) =>
      tx.query(`SELECT app.principal_type() AS p, app.current_user_id() AS u, app.current_tenant() AS t`));
    expect(r.rows[0]).toEqual({ p: 'system', u: null, t: T.id });
  });

  it('anonymous transactions carry no context', async () => {
    const r = await withAnonymousTx(h.app, (tx) => tx.query(`SELECT app.current_tenant() AS t`));
    expect(r.rows[0].t).toBeNull();
  });
});

describe('synthetic-data guard (M0-AC16)', () => {
  it('passes on a marked database and refuses an unmarked one', async () => {
    await expect(assertSyntheticDatabase(h.app)).resolves.toBeUndefined();
    await h.admin.query('DELETE FROM meta.synthetic_marker');
    await expect(assertSyntheticDatabase(h.app)).rejects.toThrow(/Refusing to start/);
    await h.admin.query(`INSERT INTO meta.synthetic_marker (environment) VALUES ('synthetic')`);
  });
});

describe('audit (M0-AC7)', () => {
  it('writes user and system events in the same transaction, redacting PII keys', async () => {
    const ctx = fx.staffContext(T, userId, membershipId);
    const id = await withTenantTx(h.app, ctx, (tx) =>
      writeAudit(tx, ctx, { action: 'iam.member.invited', targetType: 'membership', targetId: membershipId, changes: { email: 'p@synthetic.test', role: 'admin' } }));
    const sys = await withTenantTx(h.app, { tenantId: T.id, principalType: 'system', jobName: 'nightly', requestId: 'job-1' }, (tx) =>
      writeAudit(tx, { tenantId: T.id, principalType: 'system', jobName: 'nightly', requestId: 'job-1' }, { action: 'system.check.ran' }));
    const r = await h.admin.query('SELECT id, actor_type, actor_label, changes FROM audit_events WHERE id = ANY($1) ORDER BY seq', [[id, sys]]);
    expect(r.rows[0]).toMatchObject({ actor_type: 'user', changes: { email: '[redacted]', role: 'admin' } });
    expect(r.rows[1]).toMatchObject({ actor_type: 'system', actor_label: 'system:nightly' });
  });

  it('a rolled-back change leaves no audit record (atomic with the change)', async () => {
    const ctx = fx.staffContext(T, userId, membershipId);
    let id = '';
    await expect(withTenantTx(h.app, ctx, async (tx) => {
      id = await writeAudit(tx, ctx, { action: 'test.rolled_back' });
      throw new Error('change failed');
    })).rejects.toThrow('change failed');
    expect((await h.admin.query('SELECT 1 FROM audit_events WHERE id = $1', [id])).rowCount).toBe(0);
  });

  it('is append-only: UPDATE/DELETE fail for the app and even for the owner role', async () => {
    const s = staffSettings(T.id, userId, membershipId);
    expect((await asApp(h.app, s, `UPDATE audit_events SET action = 'x.y'`)).code).toBe('42501');
    expect((await asApp(h.app, s, `DELETE FROM audit_events`)).code).toBe('42501');
    await expect(h.admin.query(`UPDATE audit_events SET action = 'x.y'`)).rejects.toThrow(/append-only/);
    await expect(h.admin.query(`DELETE FROM audit_events`)).rejects.toThrow(/append-only/);
    await expect(h.admin.query(`TRUNCATE audit_events`)).rejects.toThrow(/append-only/);
  });

  it('users cannot forge system events or events attributed to someone else', async () => {
    const s = staffSettings(T.id, userId, membershipId);
    const other = await fx.addMembership(h.admin, T.id, await fx.createUser(h.admin, { email: 'o@synthetic.test', displayName: 'O', issuer: ISSUER, subject: 'o' }));
    expect((await asApp(h.app, s, `INSERT INTO audit_events (tenant_id, id, actor_type, actor_label, action) VALUES ($1, gen_random_uuid(), 'system', 'system:x', 'a.b')`, [T.id])).code).toBe('42501');
    expect((await asApp(h.app, s, `INSERT INTO audit_events (tenant_id, id, actor_type, actor_membership_id, action) VALUES ($1, gen_random_uuid(), 'user', $2, 'a.b')`, [T.id, other])).code).toBe('42501');
  });

  it('redact handles nesting, arrays and depth limits', () => {
    expect(redact({ a: [{ phone: '1', ok: 2 }], nested: { iban: 'x' } })).toEqual({ a: [{ phone: '[redacted]', ok: 2 }], nested: { iban: '[redacted]' } });
    let deep: Record<string, unknown> = { v: 1 };
    for (let i = 0; i < 10; i++) deep = { d: deep };
    expect(JSON.stringify(redact(deep))).toContain('[depth]');
  });
});
