import type { Tx } from '../db';
import { AuthorizationError } from '../errors';
import { authorize, type Decision, type PrincipalAccess, type ResourceRef } from './authorize';
import { isPermission, type Permission } from './permissions';

/** Loads the caller's access inside a withTenantTx transaction (RLS limits it to the current tenant). */
export async function loadPrincipalAccess(tx: Tx): Promise<PrincipalAccess> {
  const active = await tx.query<{ ok: boolean }>('SELECT app.membership_active() AS ok');
  const perms = await tx.query<{ permission: string; scope_type: string; scope_id: string | null }>(`
    SELECT DISTINCT rp.permission, ra.scope_type, ra.scope_id
    FROM role_assignments ra
    JOIN role_permissions rp ON rp.tenant_id = ra.tenant_id AND rp.role_id = ra.role_id
    WHERE ra.membership_id = app.current_membership() OR ra.team_id = ANY (app.my_team_ids())`);
  const grants = await tx.query<{ securable_id: string; access: 'read' | 'write' }>(`
    SELECT securable_id, access FROM securable_grants
    WHERE (membership_id = app.current_membership() OR team_id = ANY (app.my_team_ids()))
      AND (expires_at IS NULL OR expires_at > now())`);

  const tenantPermissions = new Set<Permission>();
  const scopedPermissions: { securableId: string; permission: Permission }[] = [];
  for (const r of perms.rows) {
    if (!isPermission(r.permission)) continue;
    if (r.scope_type === 'tenant') tenantPermissions.add(r.permission);
    else if (r.scope_id) scopedPermissions.push({ securableId: r.scope_id, permission: r.permission });
  }
  const restrictedGrants = new Map<string, 'read' | 'write'>();
  for (const g of grants.rows) {
    if (restrictedGrants.get(g.securable_id) !== 'write') restrictedGrants.set(g.securable_id, g.access);
  }
  return { membershipActive: active.rows[0]?.ok === true, tenantPermissions, scopedPermissions, restrictedGrants };
}

/** Throws AuthorizationError unless allowed. Use at the top of every command/query. */
export function assertAllowed(access: PrincipalAccess, permission: Permission, resource?: ResourceRef): Decision & { allowed: true } {
  const d = authorize(access, permission, resource);
  if (!d.allowed) throw new AuthorizationError(permission, d.reason);
  return d;
}
