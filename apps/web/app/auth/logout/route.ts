import { NextResponse, type NextRequest } from 'next/server';
import { getSession, revokeSession, sessionCookieName } from '@investoros/kernel/auth';
import { appPool, authConfig } from '@/server/runtime';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<NextResponse> {
  const cfg = authConfig();
  // CSRF: state-changing request must come from our own origin.
  if (req.headers.get('origin') !== new URL(cfg.baseUrl).origin) {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 });
  }
  const token = req.cookies.get(sessionCookieName(cfg))?.value;
  const session = await getSession(appPool(), cfg, token);
  if (session) await revokeSession(appPool(), session);
  const res = NextResponse.redirect(new URL('/login', cfg.baseUrl), 303);
  res.cookies.delete(sessionCookieName(cfg));
  return res;
}
