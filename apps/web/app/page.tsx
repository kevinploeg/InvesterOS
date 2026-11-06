import { redirect } from 'next/navigation';
import { listMemberships } from '@investoros/kernel/auth';
import { currentSession } from '@/server/session';
import { appPool } from '@/server/runtime';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const session = await currentSession();
  if (!session) redirect('/login');
  const memberships = await listMemberships(appPool(), session.userId);
  const active = memberships.find((m) => m.membershipId === session.activeMembershipId) ?? memberships[0];
  if (!active) redirect('/login?error=no_membership');
  redirect(`/t/${active.tenantSlug}`);
}
