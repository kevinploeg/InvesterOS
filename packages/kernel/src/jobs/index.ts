import type pg from 'pg';
import type { RequestContext } from '../context';
import type { Tx } from '../db';
import { mapDbError } from '../db';
import { newId } from '../ids';
import type { Permission } from '../authz/permissions';

/**
 * Enqueues a job in the CURRENT request transaction. The database records the enqueuer from its own
 * context (policy: enqueued_by = app.current_membership()); the app cannot enqueue on behalf of others.
 * `permission` is re-checked by the database when the job executes.
 */
export async function enqueueJob(tx: Tx, ctx: RequestContext, kind: string, permission: Permission, payload: Record<string, unknown> = {}): Promise<string> {
  const id = newId();
  await tx.query(
    `INSERT INTO jobs (tenant_id, id, kind, permission, payload, enqueued_by) VALUES ($1, $2, $3, $4, $5, $6)`,
    [ctx.tenantId, id, kind, permission, JSON.stringify(payload), ctx.membershipId],
  );
  return id;
}

export type JobOutcome = 'done' | 'failed' | 'unavailable' | `refused:${string}`;

export interface JobRun {
  tenantId: string;
  membershipId: string;
  kind: string;
  payload: Record<string, unknown>;
}

/**
 * Executes one job (ios_worker pool). auth.begin_job re-validates the enqueuer NOW: membership and tenant
 * active, permission still held. A refusal is recorded and committed; the handler never runs.
 */
export async function runJob(workerPool: pg.Pool, jobId: string, handler: (tx: Tx, job: JobRun) => Promise<void>): Promise<JobOutcome> {
  const c = await workerPool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query<{ outcome: string; tenant_id: string; membership_id: string; kind: string; payload: Record<string, unknown> }>(
      'SELECT * FROM auth.begin_job($1)',
      [jobId],
    );
    const row = r.rows[0]!;
    if (row.outcome !== 'ok') {
      await c.query('COMMIT');
      return row.outcome as JobOutcome;
    }
    await c.query('SAVEPOINT job');
    let ok = true;
    try {
      await handler(c, { tenantId: row.tenant_id, membershipId: row.membership_id, kind: row.kind, payload: row.payload });
    } catch {
      ok = false;
      await c.query('ROLLBACK TO SAVEPOINT job');
    }
    await c.query('SELECT auth.complete_job($1, $2)', [jobId, ok]);
    await c.query('COMMIT');
    return ok ? 'done' : 'failed';
  } catch (err) {
    await c.query('ROLLBACK').catch(() => undefined);
    throw mapDbError(err);
  } finally {
    c.release();
  }
}
