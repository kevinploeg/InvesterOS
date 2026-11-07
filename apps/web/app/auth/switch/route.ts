import { NextResponse, type NextRequest } from 'next/server';
import { sessionCookieName, switchTenant } from '@investoros/kernel/auth';
import { SessionCredential } from '@investoros/kernel/db';
import { appPool, authConfig, ensureSynthetic } from '@/server/runtime';

export const dynamic = 'force-dynamic';

/**
 * Tenant switch = session rotation (M1-WP2, R5). The database revokes the current session and issues a new
 * one bound to the target tenant. Reached only via redirect from /t/[tenant] after that page has already
 * verified the membership; a forged request can at most rotate the victim's own session to a tenant they
 * already belong to (no data change).
 */
export async function GET(req: NextRequest): Promise<NextResponse> {
  await ensureSynthetic();
  const cfg = authConfig();
  const slug = req.nextUrl.searchParams.get('to') ?? '';
  const token = req.cookies.get(sessionCookieName(cfg))?.value;
  if (!token || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(slug)) return NextResponse.redirect(new URL('/login', cfg.baseUrl), 303);
  try {
    const next = await switchTenant(appPool(), new SessionCredential(token), slug);
    const res = NextResponse.redirect(new URL(`/t/${slug}`, cfg.baseUrl), 303);
    res.cookies.set(sessionCookieName(cfg), next.credential.reveal(), {
      httpOnly: true, secure: cfg.secureCookies, sameSite: 'lax', path: '/', expires: next.expiresAt,
    });
    res.headers.set('Cache-Control', 'no-store');
    return res;
  } catch (e) {
    if ((e as Error).name === 'NotFoundError') return new NextResponse('Not found', { status: 404 });
    return NextResponse.redirect(new URL('/login', cfg.baseUrl), 303);
  }
}
