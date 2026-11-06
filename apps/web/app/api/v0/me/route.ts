import { NextResponse } from 'next/server';
import { currentSession } from '@/server/session';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  const session = await currentSession();
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
  return NextResponse.json(
    { userId: session.userId, memberships: session.memberships.map((m) => ({ tenant: m.tenantSlug, name: m.tenantName })) },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
