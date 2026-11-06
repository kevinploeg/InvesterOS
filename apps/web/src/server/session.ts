import 'server-only';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getSessionView, sessionCookieName, type SessionView } from '@investoros/kernel/auth';
import { SessionCredential } from '@investoros/kernel/db';
import { appPool, authConfig, ensureSynthetic } from './runtime';

/** The raw cookie wrapped so it cannot be logged or serialised by accident. */
export async function currentCredential(): Promise<SessionCredential | undefined> {
  const token = (await cookies()).get(sessionCookieName(authConfig()))?.value;
  return token ? new SessionCredential(token) : undefined;
}

/** Validated by the database (auth.begin). Null = no valid session. */
export async function currentSession(): Promise<SessionView | null> {
  await ensureSynthetic();
  return getSessionView(appPool(), await currentCredential());
}

/** Pages: redirect to login when unauthenticated. */
export async function requireCredential(): Promise<{ credential: SessionCredential; session: SessionView }> {
  const credential = await currentCredential();
  const session = await currentSession();
  if (!credential || !session) redirect('/login');
  return { credential, session };
}
