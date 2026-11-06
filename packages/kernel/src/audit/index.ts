import type { TenantContext } from '../context';
import type { Tx } from '../db';
import { newId } from '../ids';

/** Keys whose values never enter the audit log (PII / secrets). Audit stores references, not personal data. */
const REDACT = /(password|secret|token|email|phone|birth|iban|passport|tax_?id|bsn|address|name)$/i;

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[depth]';
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, REDACT.test(k) ? '[redacted]' : redact(v, depth + 1)]),
    );
  }
  return value;
}

export interface AuditEntry {
  action: string;
  targetType?: string;
  targetId?: string;
  securableId?: string;
  changes?: Record<string, unknown>;
}

/** Writes an audit event in the SAME transaction as the change: no change without its audit record. */
export async function writeAudit(tx: Tx, ctx: TenantContext, e: AuditEntry): Promise<string> {
  const id = newId();
  const user = ctx.principalType === 'staff';
  await tx.query(
    `INSERT INTO audit_events (tenant_id, id, actor_type, actor_membership_id, actor_label, action, target_type, target_id, securable_id, request_id, changes)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      ctx.tenantId,
      id,
      user ? 'user' : 'system',
      user ? ctx.membershipId : null,
      user ? null : `system:${ctx.jobName}`,
      e.action,
      e.targetType ?? null,
      e.targetId ?? null,
      e.securableId ?? null,
      ctx.requestId,
      JSON.stringify(redact(e.changes ?? {})),
    ],
  );
  return id;
}
