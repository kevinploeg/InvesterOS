/**
 * Request context as established BY THE DATABASE (auth.begin). Application code receives it from
 * withTenantTx and never constructs one itself; the database does not accept identities from the app.
 */
export interface RequestContext {
  readonly tenantId: string;
  readonly tenantSlug: string;
  readonly userId: string;
  readonly membershipId: string;
  readonly sessionId: string;
  readonly principalType: 'staff';
  readonly requestId: string;
}

/** Named background job acting as the system principal in one tenant (ios_worker only). */
export interface SystemContext {
  readonly tenantId: string;
  readonly principalType: 'system';
  readonly jobName: string;
  readonly requestId: string;
}

export type TenantContext = RequestContext | SystemContext;
