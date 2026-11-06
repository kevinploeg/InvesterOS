import { inspect } from 'node:util';
import pg from 'pg';
import type { RequestContext, SystemContext } from '../context';
import { AuthenticationError, NotFoundError } from '../errors';
import { isUuid } from '../ids';

export type Tx = pg.PoolClient;
export type TxMode = 'read' | 'write';

export function createPool(connectionString: string, max = 10): pg.Pool {
  return new pg.Pool({ connectionString, max, idleTimeoutMillis: 30_000, application_name: 'investoros', statement_timeout: 15_000 });
}

/**
 * Holds a raw session token. It is passed to the database (auth.begin), never logged or serialised.
 */
export class SessionCredential {
  readonly #token: string;
  constructor(token: string) {
    this.#token = token;
  }
  /** Only for the kernel's DB calls and for setting the cookie. */
  reveal(): string {
    return this.#token;
  }
  toJSON(): string {
    return '[SessionCredential]';
  }
  toString(): string {
    return '[SessionCredential]';
  }
  [inspect.custom](): string {
    return '[SessionCredential]';
  }
}

/** Maps the database's access errors to HTTP semantics; everything else propagates unchanged. */
export function mapDbError(err: unknown): unknown {
  const code = (err as { code?: string }).code;
  if (code === 'IOS01') return new AuthenticationError('No valid session');
  if (code === 'IOS04') return new NotFoundError();
  return err;
}

async function inTx<T>(pool: pg.Pool, begin: (c: Tx) => Promise<void>, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await begin(client);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw mapDbError(err);
  } finally {
    client.release();
  }
}

interface BeginRow {
  session_id: string;
  user_id: string;
  tenant_id: string | null;
  tenant_slug: string | null;
  membership_id: string | null;
  active_tenant_slug: string | null;
}

/**
 * The ONLY way to touch tenant data. The database validates the session token and the membership
 * (auth.begin) and establishes the context itself; the application cannot assert an identity.
 * 'write' mode additionally serialises against concurrent revocations (see migration 0005).
 */
export function withTenantTx<T>(
  pool: pg.Pool,
  credential: SessionCredential,
  tenantSlug: string,
  mode: TxMode,
  fn: (tx: Tx, ctx: RequestContext) => Promise<T>,
  requestId = '',
): Promise<T> {
  let ctx: RequestContext | undefined;
  return inTx(
    pool,
    async (c) => {
      const r = await c.query<BeginRow>('SELECT * FROM auth.begin($1, $2, $3)', [credential.reveal(), tenantSlug, mode]);
      const row = r.rows[0]!;
      ctx = {
        tenantId: row.tenant_id!,
        tenantSlug: row.tenant_slug!,
        userId: row.user_id,
        membershipId: row.membership_id!,
        sessionId: row.session_id,
        principalType: 'staff',
        requestId,
      };
    },
    (tx) => fn(tx, ctx!),
  );
}

export interface UserContext {
  readonly userId: string;
  readonly sessionId: string;
  readonly activeTenantSlug: string | null;
}

/** User-level transaction without a tenant (tenant switcher, own memberships, logout). */
export function withUserTx<T>(pool: pg.Pool, credential: SessionCredential, fn: (tx: Tx, user: UserContext) => Promise<T>): Promise<T> {
  let user: UserContext | undefined;
  return inTx(
    pool,
    async (c) => {
      const r = await c.query<BeginRow>('SELECT * FROM auth.begin($1, NULL, $2)', [credential.reveal(), 'read']);
      const row = r.rows[0]!;
      user = { userId: row.user_id, sessionId: row.session_id, activeTenantSlug: row.active_tenant_slug };
    },
    (tx) => fn(tx, user!),
  );
}

/** Named system job (ios_worker only). Reaches only what system policies explicitly allow. */
export function withSystemTx<T>(workerPool: pg.Pool, ctx: SystemContext, fn: (tx: Tx) => Promise<T>): Promise<T> {
  if (!isUuid(ctx.tenantId)) throw new Error('withSystemTx: invalid tenantId');
  return inTx(workerPool, async (c) => {
    await c.query('SELECT auth.begin_system($1, $2)', [ctx.tenantId, ctx.jobName]);
  }, fn);
}

/** No request context (ios_auth pool: session creation after OIDC validation). */
export function withAuthTx<T>(authPool: pg.Pool, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return inTx(authPool, async () => undefined, fn);
}

/**
 * MVP data guard: refuse to run against any database that is not explicitly marked synthetic.
 * Real customer data is out of scope until the M5 go-live gate.
 */
export async function assertSyntheticDatabase(pool: pg.Pool): Promise<void> {
  const r = await pool.query<{ environment: string }>('SELECT environment FROM meta.synthetic_marker');
  if (r.rows[0]?.environment !== 'synthetic') {
    throw new Error('Refusing to start: database is not marked synthetic (meta.synthetic_marker). Synthetic data only.');
  }
}
