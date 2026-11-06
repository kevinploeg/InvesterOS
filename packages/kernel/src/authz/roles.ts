import { PERMISSION_KEYS, permissionDef, type Permission } from './permissions';

/** System roles seeded into every tenant. Tenants may add custom roles in M1 (never new permissions). */
export const SYSTEM_ROLE_KEYS = [
  'owner',
  'admin',
  'investment_professional',
  'investor_relations',
  'compliance',
  'read_only',
] as const;
export type SystemRoleKey = (typeof SYSTEM_ROLE_KEYS)[number];

const reads = PERMISSION_KEYS.filter((k) => permissionDef(k).read && k !== 'restricted.oversight');

const set = (keys: readonly Permission[]): ReadonlySet<Permission> => new Set(keys);

/**
 * Deliberate choices:
 * - Nobody gets restricted resources through a tenant-wide role. Owner/admin hold
 *   `access.manage` (can grant), but must hold an explicit grant to see restricted data.
 *   Self-grants are audited; from M2 they require four-eyes approval.
 * - Only `compliance` has `restricted.oversight` (read-only, audited).
 */
export const SYSTEM_ROLES: Readonly<Record<SystemRoleKey, { name: string; permissions: ReadonlySet<Permission> }>> = {
  owner: {
    name: 'Owner',
    permissions: set(PERMISSION_KEYS.filter((k) => k !== 'restricted.oversight')),
  },
  admin: {
    name: 'Administrator',
    permissions: set([
      ...reads,
      'audit.read',
      'tenant.settings.manage',
      'iam.members.manage',
      'iam.teams.manage',
      'iam.roles.manage',
      'access.manage',
      'securables.manage',
    ]),
  },
  investment_professional: {
    name: 'Investment Professional',
    permissions: set([
      'iam.members.read',
      'investors.read',
      'projects.read',
      'projects.write',
      'opportunities.read',
      'opportunities.write',
      'offerings.read',
      'crm.read',
      'crm.write',
      'tasks.read',
      'tasks.write',
      'ledger.read',
    ]),
  },
  investor_relations: {
    name: 'Investor Relations',
    permissions: set([
      'iam.members.read',
      'investors.read',
      'investors.write',
      'projects.read',
      'opportunities.read',
      'offerings.read',
      'offerings.write',
      'crm.read',
      'crm.write',
      'tasks.read',
      'tasks.write',
      'ledger.read',
    ]),
  },
  compliance: {
    name: 'Compliance',
    permissions: set([...reads, 'audit.read', 'restricted.oversight', 'subscriptions.approve']),
  },
  read_only: {
    name: 'Read-only',
    permissions: set(reads),
  },
};
