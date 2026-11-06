import { NextResponse, type NextRequest } from 'next/server';
import { completeLogin, createSession, resolveIdentity, sessionCookieName, stateCookieName } from '@investoros/kernel/auth';
import { appPool, authConfig, ensureSynthetic } from '@/server/runtime';

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
    const userId = await resolveIdentity(appPool(), identity.issuer, identity.subject);
    if (!userId) {
      res = to('/login?error=no_account');
    } else {
      const previous = req.cookies.get(sessionCookieName(cfg))?.value;
      const { token, session } = await createSession(appPool(), cfg, userId, previous);
      res = to('/');
      res.cookies.set(sessionCookieName(cfg), token, {
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
