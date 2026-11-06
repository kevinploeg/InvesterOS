import { NextResponse, type NextRequest } from 'next/server';
import { completeLogin, createSession, sessionCookieName, stateCookieName } from '@investoros/kernel/auth';
import { SessionCredential } from '@investoros/kernel/db';
import { authConfig, ensureSynthetic, sessionAuthPool } from '@/server/runtime';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest): Promise<NextResponse> {
  await ensureSynthetic();
  const cfg = authConfig();
  const to = (path: string) => NextResponse.redirect(new URL(path, cfg.baseUrl), 303);
  // Rebuild the callback URL on the configured base URL (never trust the Host header).
  const callback = new URL(`${cfg.redirectUri}${req.nextUrl.search}`);
  let res: NextResponse;
  try {
    const identity = await completeLogin(cfg, callback, req.cookies.get(stateCookieName(cfg))?.value);
    const previous = req.cookies.get(sessionCookieName(cfg))?.value;
    const session = await createSession(sessionAuthPool(), identity.issuer, identity.subject, previous ? new SessionCredential(previous) : undefined);
    if (!session) {
      res = to('/login?error=no_account');
    } else {
      res = to('/');
      res.cookies.set(sessionCookieName(cfg), session.credential.reveal(), {
        httpOnly: true, secure: cfg.secureCookies, sameSite: 'lax', path: '/', expires: session.expiresAt,
      });
    }
  } catch {
    res = to('/login?error=failed');
  }
  res.cookies.delete(stateCookieName(cfg));
  res.headers.set('Cache-Control', 'no-store');
  return res;
}
