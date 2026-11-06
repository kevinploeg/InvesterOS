/**
 * Deterministic SYNTHETIC dataset for development and E2E. Fictional organisations and people only.
 * Uses an admin connection (fixtures bypass RLS) and refuses to touch anything that does not look
 * like a dev/test database.
 */
import { Faker, en, nl, de } from '@faker-js/faker';
import pg from 'pg';
import * as fx from '@investoros/kernel/fixtures';
import type { SystemRoleKey } from '@investoros/kernel/authz';

export interface SeedSummary {
  issuer: string;
  tenants: { slug: string; name: string; restrictedSecurableId: string }[];
  users: { subject: string; email: string; displayName: string; tenants: { slug: string; role: SystemRoleKey }[] }[];
}

const TENANTS = [
  { slug: 'noordzee-capital', name: 'Noordzee Capital (synthetic)', locale: 'nl' },
  { slug: 'alpen-infrastructure', name: 'Alpen Infrastructure Partners (synthetic)', locale: 'de' },
  { slug: 'rijn-credit', name: 'Rijn Credit Partners (synthetic)', locale: 'en' },
] as const;

const ROLE_CYCLE: SystemRoleKey[] = ['owner', 'admin', 'investment_professional', 'investment_professional', 'investor_relations', 'investor_relations', 'compliance', 'read_only', 'investment_professional', 'read_only'];

export async function seed(adminUrl: string, issuer: string): Promise<SeedSummary> {
  const dbName = new URL(adminUrl).pathname.slice(1);
  if (!/^(investoros_(dev|e2e)|ios_test_[0-9a-f]+)$/.test(dbName)) {
    throw new Error(`Refusing to seed "${dbName}": synthetic seed only runs against dev/e2e/test databases`);
  }
  const faker = new Faker({ locale: [nl, de, en] });
  faker.seed(20261106);
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const summary: SeedSummary = { issuer, tenants: [], users: [] };
  try {
    await admin.query('BEGIN');
    const existing = await admin.query('SELECT count(*)::int AS n FROM tenants');
    if (existing.rows[0].n > 0) throw new Error('Database already seeded');
    await admin.query(`INSERT INTO meta.synthetic_marker (environment) VALUES ('synthetic') ON CONFLICT DO NOTHING`);

    let n = 0;
    for (const t of TENANTS) {
      const tenant = await fx.createTenant(admin, t.slug, t.name, t.locale);
      const owner = { membershipId: '' };
      const dealTeam = await fx.createTeam(admin, tenant.id, 'Deal team Project Atlas');
      const restricted = await fx.createSecurable(admin, tenant.id, 'restricted', 'project');
      await fx.createSecurable(admin, tenant.id, 'standard', 'project');
      for (let i = 0; i < 10; i++) {
        n++;
        const first = faker.person.firstName();
        const last = faker.person.lastName();
        const subject = `synthetic-user-${String(n).padStart(2, '0')}`;
        const email = `${subject}@${t.slug}.synthetic.invalid`;
        const userId = await fx.createUser(admin, { email, displayName: `${first} ${last}`, issuer, subject });
        const membershipId = await fx.addMembership(admin, tenant.id, userId);
        const role = ROLE_CYCLE[i]!;
        await fx.assignRole(admin, tenant.id, tenant.roles[role], { membershipId });
        if (role === 'owner') owner.membershipId = membershipId;
        if (i === 2 || i === 3) await fx.addTeamMember(admin, tenant.id, dealTeam, membershipId);
        summary.users.push({ subject, email, displayName: `${first} ${last}`, tenants: [{ slug: t.slug, role }] });
      }
      await fx.grantSecurable(admin, tenant.id, restricted, { teamId: dealTeam, access: 'write', grantedBy: owner.membershipId });
      summary.tenants.push({ slug: t.slug, name: t.name, restrictedSecurableId: restricted });
    }
    // A8: one person (e.g. an external fund administrator) is a member of two tenants.
    const multi = summary.users[0]!;
    const uid = (await admin.query('SELECT user_id FROM user_identities WHERE subject = $1', [multi.subject])).rows[0].user_id;
    const second = (await admin.query('SELECT id, slug FROM tenants WHERE slug = $1', [TENANTS[2].slug])).rows[0];
    const mid = await fx.addMembership(admin, second.id, uid);
    const ro = (await admin.query(`SELECT id FROM roles WHERE tenant_id = $1 AND key = 'read_only'`, [second.id])).rows[0].id;
    await fx.assignRole(admin, second.id, ro, { membershipId: mid });
    multi.tenants.push({ slug: second.slug, role: 'read_only' });
    await admin.query('COMMIT');
  } catch (e) {
    await admin.query('ROLLBACK');
    throw e;
  } finally {
    await admin.end();
  }
  return summary;
}
