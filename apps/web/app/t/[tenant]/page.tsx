import { getTranslations } from 'next-intl/server';
import { notFound, redirect } from 'next/navigation';
import { loadPrincipalAccess } from '@investoros/kernel/authz';
import { withTenantTx } from '@investoros/kernel/db';
import { appPool } from '@/server/runtime';
import { requireCredential } from '@/server/session';

export const dynamic = 'force-dynamic';

export default async function TenantHome({ params }: { params: Promise<{ tenant: string }> }) {
  const { tenant } = await params;
  const { credential, session } = await requireCredential();
  const t = await getTranslations('workspace');
  // The database validates the session AND the membership for this slug (auth.begin).
  const data = await withTenantTx(appPool(), credential, tenant, 'read', async (tx, ctx) => {
    const access = await loadPrincipalAccess(tx);
    const me = await tx.query<{ display_name: string }>('SELECT display_name FROM users WHERE id = $1', [ctx.userId]);
    const tn = await tx.query<{ name: string }>('SELECT name FROM tenants WHERE id = $1', [ctx.tenantId]);
    const roles = await tx.query<{ name: string }>(
      `SELECT DISTINCT r.name FROM role_assignments ra JOIN roles r ON r.tenant_id = ra.tenant_id AND r.id = ra.role_id
       WHERE ra.membership_id = $1 OR ra.team_id = ANY (app.my_team_ids()) ORDER BY r.name`, [ctx.membershipId]);
    const teams = await tx.query<{ name: string }>(
      `SELECT t.name FROM teams t JOIN team_members tm ON tm.tenant_id = t.tenant_id AND tm.team_id = t.id
       WHERE tm.membership_id = $1 ORDER BY t.name`, [ctx.membershipId]);
    return { access, me: me.rows[0]?.display_name ?? '', tenantName: tn.rows[0]?.name ?? '', roles: roles.rows.map((r) => r.name), teams: teams.rows.map((r) => r.name) };
  }).catch((e: Error) => {
    if (e.name === 'NotFoundError') notFound();
    if (e.name === 'AuthenticationError') redirect('/login');
    throw e;
  });
  // Membership verified above by the database. Make this tenant the session's active tenant via rotation.
  if (session.activeTenantSlug !== tenant) redirect(`/auth/switch?to=${encodeURIComponent(tenant)}`);
  const memberships = session.memberships;

  return (
    <main>
      <div className="row">
        <h1 data-testid="tenant-name">{data.tenantName}</h1>
        <form method="post" action="/auth/logout"><button className="btn secondary" type="submit" data-testid="logout">{t('logout')}</button></form>
      </div>
      <div className="card">
        <p data-testid="signed-in-as">{t('signedInAs', { name: data.me })}</p>
        <h2>{t('roles')}</h2>
        <p data-testid="roles">{data.roles.join(', ')} · {t('permissions', { count: data.access.tenantPermissions.size })}</p>
        <h2>{t('teams')}</h2>
        <p>{data.teams.length ? data.teams.join(', ') : t('noTeams')}</p>
      </div>
      {memberships.length > 1 ? (
        <div className="card">
          <h2>{t('switch')}</h2>
          <ul className="plain" data-testid="tenant-switcher">
            {memberships.map((m) => (
              <li key={m.tenantId}>{m.tenantSlug === tenant ? <strong>{m.tenantName}</strong> : <a href={`/t/${m.tenantSlug}`}>{m.tenantName}</a>}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </main>
  );
}
