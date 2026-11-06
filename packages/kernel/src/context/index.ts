/**
 * The only way tenant identity enters the data layer. Built by the auth layer from the
 * server-side session (never from URL/body alone) and passed explicitly to every command/query.
 */
export interface RequestContext {
  readonly tenantId: string;
  readonly tenantSlug: string;
  readonly userId: string;
  readonly membershipId: string;
  readonly principalType: 'staff';
  readonly requestId: string;
}

/** Background jobs act either as a named system job or on behalf of a membership (re-authorized at run time). */
export interface SystemContext {
  readonly tenantId: string;
  readonly principalType: 'system';
  readonly jobName: string;
  readonly requestId: string;
}

export type TenantContext = RequestContext | SystemContext;
