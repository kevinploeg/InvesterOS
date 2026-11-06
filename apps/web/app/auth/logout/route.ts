import { NextResponse, type NextRequest } from 'next/server';
import { revokeSession, sessionCookieName } from '@investoros/kernel/auth';
import { SessionCredential } from '@investoros/kernel/db';
import { appPool, authConfig } from '@/server/runtime';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<NextResponse> {
  const cfg = authConfig();
  // CSRF: state-changing request must come from our own origin.
  if (req.headers.get('origin') !== new URL(cfg.baseUrl).origin) {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 });
  }
  const token = req.cookies.get(sessionCookieName(cfg))?.value;
  if (token) await revokeSession(appPool(), new SessionCredential(token)).catch(() => undefined); // already invalid = fine
  const res = NextResponse.redirect(new URL('/login', cfg.baseUrl), 303);
  res.cookies.delete(sessionCookieName(cfg));
  return res;
}
