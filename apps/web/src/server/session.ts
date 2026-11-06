import 'server-only';
import { randomUUID } from 'node:crypto';
import { cookies } from 'next/headers';
import { notFound, redirect } from 'next/navigation';
import { getSession, resolveTenantContext, sessionCookieName, type Session } from '@investoros/kernel/auth';
import type { RequestContext } from '@investoros/kernel/context';
import { appPool, authConfig, ensureSynthetic } from './runtime';

export async function currentSession(): Promise<Session | null> {
  await ensureSynthetic();
  const token = (await cookies()).get(sessionCookieName(authConfig()))?.value;
  return getSession(appPool(), authConfig(), token);
}

/** Pages: redirect to login when unauthenticated. */
export async function requireSession(): Promise<Session> {
  const s = await currentSession();
  if (!s) redirect('/login');
  return s;
}

/** Pages under /t/[tenant]: the slug must match an active membership, else 404 (never 403). */
export async function requireTenantContext(slug: string): Promise<{ session: Session; ctx: RequestContext }> {
  const session = await requireSession();
  const ctx = await resolveTenantContext(appPool(), session, slug, randomUUID());
  if (!ctx) notFound();
  return { session, ctx };
}
