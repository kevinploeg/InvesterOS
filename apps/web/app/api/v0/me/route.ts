import { NextResponse } from 'next/server';
import { listMemberships } from '@investoros/kernel/auth';
import { appPool } from '@/server/runtime';
import { currentSession } from '@/server/session';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  const session = await currentSession();
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
  const memberships = await listMemberships(appPool(), session.userId);
  return NextResponse.json(
    { userId: session.userId, memberships: memberships.map((m) => ({ tenant: m.tenantSlug, name: m.tenantName })) },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
