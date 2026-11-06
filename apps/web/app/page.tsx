import { redirect } from 'next/navigation';
import { currentSession } from '@/server/session';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const session = await currentSession();
  if (!session) redirect('/login');
  const active = session.memberships.find((m) => m.tenantSlug === session.activeTenantSlug) ?? session.memberships[0];
  if (!active) redirect('/login?error=no_membership');
  redirect(`/t/${active.tenantSlug}`);
}
