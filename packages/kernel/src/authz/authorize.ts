import { permissionDef, type Permission } from './permissions';

export interface ScopedPermission {
  readonly securableId: string;
  readonly permission: Permission;
}

/** Everything authorize() needs about the caller, loaded once per request (see load.ts). */
export interface PrincipalAccess {
  readonly membershipActive: boolean;
  readonly tenantPermissions: ReadonlySet<Permission>;
  readonly scopedPermissions: readonly ScopedPermission[];
  /** Live grants on restricted securables (direct or via team). */
  readonly restrictedGrants: ReadonlyMap<string, 'read' | 'write'>;
}

export interface ResourceRef {
  readonly securableId: string;
  readonly classification: 'standard' | 'restricted';
}

export type Decision =
  | { allowed: true; via: 'tenant-role' | 'scoped-role'; oversight: boolean }
  | { allowed: false; reason: 'inactive-membership' | 'missing-permission' | 'restricted-no-grant' | 'restricted-read-only' };

/**
 * Application-layer authorization. Mirrors (never replaces) the database policies:
 *  1. membership must be active;
 *  2. the permission must be held tenant-wide, or (if scopable) via a role scoped to this securable;
 *  3. restricted resources additionally need a live grant: read perms need read|write, others need write.
 *     `restricted.oversight` satisfies read-only permissions only, and is flagged for auditing.
 */
export function authorize(access: PrincipalAccess, permission: Permission, resource?: ResourceRef): Decision {
  if (!access.membershipActive) return { allowed: false, reason: 'inactive-membership' };
  const def = permissionDef(permission);

  let via: 'tenant-role' | 'scoped-role' | null = access.tenantPermissions.has(permission) ? 'tenant-role' : null;
  if (!via && resource && def.scopable) {
    if (access.scopedPermissions.some((s) => s.securableId === resource.securableId && s.permission === permission)) {
      via = 'scoped-role';
    }
  }
  if (!via) return { allowed: false, reason: 'missing-permission' };

  if (resource?.classification === 'restricted') {
    const grant = access.restrictedGrants.get(resource.securableId);
    if (def.read) {
      if (grant) return { allowed: true, via, oversight: false };
      if (access.tenantPermissions.has('restricted.oversight')) return { allowed: true, via, oversight: true };
      return { allowed: false, reason: 'restricted-no-grant' };
    }
    if (grant === 'write') return { allowed: true, via, oversight: false };
    return { allowed: false, reason: grant ? 'restricted-read-only' : 'restricted-no-grant' };
  }
  return { allowed: true, via, oversight: false };
}
