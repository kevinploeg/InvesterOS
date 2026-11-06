import { NextResponse } from 'next/server';
import { beginLogin, stateCookieName } from '@investoros/kernel/auth';
import { authConfig, ensureSynthetic } from '@/server/runtime';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  await ensureSynthetic();
  const cfg = authConfig();
  const { url, stateCookie } = await beginLogin(cfg);
  const res = NextResponse.redirect(url, 302);
  res.cookies.set(stateCookieName(cfg), stateCookie, {
    httpOnly: true, secure: cfg.secureCookies, sameSite: 'lax', path: '/', maxAge: 600,
  });
  res.headers.set('Cache-Control', 'no-store');
  return res;
}
