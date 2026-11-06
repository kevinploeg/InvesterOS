/**
 * Permission registry: the single source of truth for permission keys.
 * The DB catalog (meta.permissions, migration 0003) must equal this list; a test enforces it.
 *
 * `scopable` permissions may be granted on a single securable (project, fund, opportunity,
 * offering) instead of tenant-wide. Non-scopable permissions only exist at tenant scope.
 * `read` marks read-only permissions: these are the only ones `restricted.oversight` can satisfy
 * on restricted resources.
 */
export interface PermissionDef {
  readonly key: string;
  readonly description: string;
  readonly scopable: boolean;
  readonly read: boolean;
}

const p = (key: string, description: string, opts: { scopable?: boolean; read?: boolean } = {}): PermissionDef => ({
  key,
  description,
  scopable: opts.scopable ?? false,
  read: opts.read ?? key.endsWith('.read'),
});

export const PERMISSIONS = [
  // Tenant & identity administration (M0/M1)
  p('tenant.settings.manage', 'Manage tenant settings'),
  p('iam.members.read', 'View members, teams and role assignments', { read: true }),
  p('iam.members.manage', 'Invite, suspend and remove members'),
  p('iam.teams.manage', 'Create teams and manage team membership'),
  p('iam.roles.manage', 'Create custom roles and assign roles'),
  // Information barriers
  p('access.manage', 'Grant and revoke access to restricted resources'),
  p('securables.manage', 'Create securables and change their classification'),
  p('restricted.oversight', 'Read-only oversight of all restricted resources (compliance); every use is audited', { read: true }),
  p('audit.read', 'Read the audit log'),
  // Domain permissions, registered now so roles and the authorization matrix are stable (built M3+)
  p('investors.read', 'View investors, parties and contacts'),
  p('investors.write', 'Create and edit investors, parties and contacts'),
  p('projects.read', 'View projects', { scopable: true }),
  p('projects.write', 'Create and edit projects', { scopable: true }),
  p('opportunities.read', 'View deals/opportunities', { scopable: true }),
  p('opportunities.write', 'Create and edit deals/opportunities', { scopable: true }),
  p('offerings.read', 'View offerings and subscriptions', { scopable: true }),
  p('offerings.write', 'Create and edit offerings and subscriptions', { scopable: true }),
  p('subscriptions.approve', 'Approve subscriptions (four-eyes)', { scopable: true }),
  p('crm.read', 'View interactions', { scopable: true }),
  p('crm.write', 'Record interactions', { scopable: true }),
  p('tasks.read', 'View tasks', { scopable: true }),
  p('tasks.write', 'Create and edit tasks', { scopable: true }),
  p('ledger.read', 'View transactions and holdings', { scopable: true }),
  p('ledger.post', 'Draft and post ledger transactions (four-eyes)'),
] as const satisfies readonly PermissionDef[];

export type Permission = (typeof PERMISSIONS)[number]['key'];

export const PERMISSION_KEYS: readonly Permission[] = PERMISSIONS.map((d) => d.key);

const byKey = new Map<string, PermissionDef>(PERMISSIONS.map((d) => [d.key, d]));

export function isPermission(key: string): key is Permission {
  return byKey.has(key);
}

export function permissionDef(key: Permission): PermissionDef {
  const def = byKey.get(key);
  if (!def) throw new Error(`Unknown permission: ${key}`);
  return def;
}
