/**
 * Database-enforced information barrier (A7). Every assertion runs as ios_app against RLS directly,
 * WITHOUT the application authorization layer, proving the barrier holds even if app code is wrong.
 * A final block checks that the app-layer authorize() agrees with the database.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { withTenantTx } from '../src/db';
import { authorize, loadPrincipalAccess } from '../src/authz';
import { writeAudit } from '../src/audit';
import * as fx from '../src/fixtures';
import { asApp, harness, ISSUER, staffSettings, type Harness } from './helpers';

let h: Harness;
let T: fx.TenantFixture;
const U: Record<string, { userId: string; membershipId: string }> = {};
let R: string; // restricted securable
let S: string; // standard securable
let R2: string; // second restricted securable (nobody granted)
let teamId: string;

async function user(name: string, role: keyof fx.TenantFixture['roles']) {
  const userId = await fx.createUser(h.admin, { email: `${name}@synthetic.test`, displayName: name, issuer: ISSUER, subject: name });
  const membershipId = await fx.addMembership(h.admin, T.id, userId);
  await fx.assignRole(h.admin, T.id, T.roles[role], { membershipId });
  U[name] = { userId, membershipId };
}
const as = (name: string) => staffSettings(T.id, U[name]!.userId, U[name]!.membershipId);
const note = (securableId: string) => h.admin.query('INSERT INTO probe_notes (tenant_id, id, securable_id, body) VALUES ($1, gen_random_uuid(), $2, $3)', [T.id, securableId, 'synthetic note']);

beforeAll(async () => {
  h = await harness({ probe: true });
  T = await fx.createTenant(h.admin, 'barrier');
  await user('owner', 'owner');
  await user('admin', 'admin');
  await user('reader', 'investment_professional');
  await user('writer', 'investment_professional');
  await user('teamwriter', 'investment_professional');
  await user('outsider', 'investment_professional');
  await user('expired', 'investment_professional');
  await user('compliance', 'compliance');
  R = await fx.createSecurable(h.admin, T.id, 'restricted');
  R2 = await fx.createSecurable(h.admin, T.id, 'restricted');
  S = await fx.createSecurable(h.admin, T.id, 'standard');
  const by = U.owner!.membershipId;
  await fx.grantSecurable(h.admin, T.id, R, { membershipId: U.reader!.membershipId, access: 'read', grantedBy: by });
  await fx.grantSecurable(h.admin, T.id, R, { membershipId: U.writer!.membershipId, access: 'write', grantedBy: by });
  teamId = await fx.createTeam(h.admin, T.id, 'Deal team R');
  await fx.addTeamMember(h.admin, T.id, teamId, U.teamwriter!.membershipId);
  await fx.grantSecurable(h.admin, T.id, R, { teamId, access: 'write', grantedBy: by });
  await fx.grantSecurable(h.admin, T.id, R, { membershipId: U.expired!.membershipId, access: 'write', grantedBy: by, expiresAt: new Date(Date.now() - 1000) });
  await note(R);
  await note(R);
  await note(S);
  await note(R2);
});
afterAll(async () => h?.close());

const visibleSecurables = async (name: string) =>
  (await asApp(h.app, as(name), 'SELECT id FROM securables ORDER BY id')).rows.map((r) => r.id as string);
const notesOn = async (name: string, sid: string) =>
  Number((await asApp(h.app, as(name), 'SELECT count(*)::int AS n FROM probe_notes WHERE securable_id = $1', [sid])).rows[0]?.n ?? -1);
const insertNote = (name: string, sid: string) =>
  asApp(h.app, as(name), `INSERT INTO probe_notes (tenant_id, id, securable_id, body) VALUES ($1, gen_random_uuid(), $2, 'x')`, [T.id, sid]);
const updateNotes = (name: string, sid: string) =>
  asApp(h.app, as(name), `UPDATE probe_notes SET body = 'changed' WHERE securable_id = $1`, [sid]);
const deleteNotes = (name: string, sid: string) =>
  asApp(h.app, as(name), `DELETE FROM probe_notes WHERE securable_id = $1`, [sid]);

describe('read barrier', () => {
  it.each(['outsider', 'owner', 'admin', 'expired'])('%s (no live grant) cannot see restricted R or its children', async (who) => {
    expect(await visibleSecurables(who)).not.toContain(R);
    expect(await visibleSecurables(who)).toContain(S);
    expect(await notesOn(who, R)).toBe(0);
    expect(await notesOn(who, S)).toBe(1);
  });

  it.each(['reader', 'writer', 'teamwriter'])('%s (live grant) sees R and its children, but not ungranted R2', async (who) => {
    expect(await visibleSecurables(who)).toContain(R);
    expect(await visibleSecurables(who)).not.toContain(R2);
    expect(await notesOn(who, R)).toBe(2);
    expect(await notesOn(who, R2)).toBe(0);
  });

  it('compliance oversight sees all restricted securables read-only', async () => {
    expect(await visibleSecurables('compliance')).toEqual(expect.arrayContaining([R, R2, S]));
    expect(await notesOn('compliance', R)).toBe(2);
    expect((await insertNote('compliance', R)).code).toBe('42501');
    expect((await updateNotes('compliance', R)).rowCount).toBe(0);
  });

  it('aggregates do not leak restricted rows', async () => {
    const r = await asApp(h.app, as('outsider'), 'SELECT count(*)::int AS n FROM probe_notes');
    expect(r.rows[0]?.n).toBe(1);
  });
});

describe('write barrier', () => {
  it('read grant does not allow writes', async () => {
    expect((await insertNote('reader', R)).code).toBe('42501');
    expect((await updateNotes('reader', R)).rowCount).toBe(0);
    expect((await deleteNotes('reader', R)).rowCount).toBe(0);
  });

  it.each(['writer', 'teamwriter'])('%s (write grant) can write children of R', async (who) => {
    expect((await insertNote(who, R)).code).toBeUndefined();
    expect((await updateNotes(who, R)).rowCount).toBe(2);
    expect((await deleteNotes(who, R)).rowCount).toBe(2);
  });

  it('outsider cannot write children of R, and gets the same error as for a non-existent securable (no existence oracle)', async () => {
    const real = await insertNote('outsider', R);
    const fake = await insertNote('outsider', crypto.randomUUID());
    expect(real.code).toBe('42501');
    expect(fake.code).toBe(real.code);
  });

  it('an admin with securables.manage but no grant cannot de-classify or delete R', async () => {
    expect((await asApp(h.app, as('admin'), `UPDATE securables SET classification = 'standard' WHERE id = $1`, [R])).rowCount).toBe(0);
    expect((await asApp(h.app, as('admin'), `DELETE FROM securables WHERE id = $1`, [R])).rowCount).toBe(0);
  });

  it('a user without access.manage cannot grant themselves access', async () => {
    const r = await asApp(h.app, as('outsider'),
      `INSERT INTO securable_grants (tenant_id, id, securable_id, membership_id, access, granted_by) VALUES ($1, gen_random_uuid(), $2, $3, 'write', $3)`,
      [T.id, R, U.outsider!.membershipId]);
    expect(r.code).toBe('42501');
  });

  it('a grant must be recorded as granted by the acting membership (no forging granted_by)', async () => {
    const r = await asApp(h.app, as('admin'),
      `INSERT INTO securable_grants (tenant_id, id, securable_id, membership_id, access, granted_by) VALUES ($1, gen_random_uuid(), $2, $3, 'read', $4)`,
      [T.id, R, U.outsider!.membershipId, U.owner!.membershipId]);
    expect(r.code).toBe('42501');
  });

  it('KNOWN GAP (closed in M2): an access manager can grant themselves access; it is attributable via granted_by', async () => {
    const r = await asApp(h.app, as('admin'),
      `INSERT INTO securable_grants (tenant_id, id, securable_id, membership_id, access, granted_by) VALUES ($1, gen_random_uuid(), $2, $3, 'read', $3) RETURNING granted_by`,
      [T.id, R, U.admin!.membershipId]);
    expect(r.rows[0]?.granted_by).toBe(U.admin!.membershipId);
  });
});

describe('classification changes apply immediately to all children', () => {
  it('restricting S hides its children from the outsider at once', async () => {
    await h.admin.query(`UPDATE securables SET classification = 'restricted' WHERE id = $1`, [S]);
    try {
      expect(await notesOn('outsider', S)).toBe(0);
    } finally {
      await h.admin.query(`UPDATE securables SET classification = 'standard' WHERE id = $1`, [S]);
    }
    expect(await notesOn('outsider', S)).toBe(1);
  });
});

describe('membership state', () => {
  it('a suspended member with a write grant loses access immediately', async () => {
    await h.admin.query(`UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [U.writer!.membershipId]);
    try {
      expect(await notesOn('writer', R)).toBe(0);
      expect((await insertNote('writer', R)).code).toBe('42501');
    } finally {
      await h.admin.query(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, [U.writer!.membershipId]);
    }
  });
});

describe('audit log respects the barrier', () => {
  it('admin with audit.read cannot read audit events about R without a grant; compliance can', async () => {
    const ctx = fx.staffContext(T, U.writer!.userId, U.writer!.membershipId);
    await withTenantTx(h.app, ctx, (tx) => writeAudit(tx, ctx, { action: 'probe.updated', securableId: R }));
    const count = async (who: string) =>
      Number((await asApp(h.app, as(who), `SELECT count(*)::int AS n FROM audit_events WHERE securable_id = $1`, [R])).rows[0]?.n);
    expect(await count('admin')).toBe(0);
    expect(await count('compliance')).toBe(1);
    expect(await count('reader')).toBe(0); // reader can see R, but lacks audit.read
  });
});

describe('app-layer authorize() agrees with the database', () => {
  it.each(['owner', 'admin', 'reader', 'writer', 'teamwriter', 'outsider', 'expired', 'compliance'])('%s', async (who) => {
    const ctx = fx.staffContext(T, U[who]!.userId, U[who]!.membershipId);
    const access = await withTenantTx(h.app, ctx, (tx) => loadPrincipalAccess(tx));
    const dbSees = (await visibleSecurables(who)).includes(R);
    const appAllows = authorize(access, 'projects.read', { securableId: R, classification: 'restricted' }).allowed;
    // projects.read is held by every role here, so the decision is driven purely by the barrier.
    expect(appAllows).toBe(dbSees);
    const dbWrites = (await insertNote(who, R)).code === undefined;
    const appWrites = authorize(access, 'projects.write', { securableId: R, classification: 'restricted' }).allowed;
    if (appWrites) expect(dbWrites).toBe(true);
    if (!dbWrites) expect(appWrites).toBe(false);
  });
});
