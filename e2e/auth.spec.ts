import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import type { SeedSummary } from '@investoros/testing';

const seed = (): SeedSummary => JSON.parse(readFileSync(join(__dirname, '.seed.json'), 'utf8'));

async function login(page: Page, subject: string): Promise<void> {
  await page.goto('/login');
  await page.getByTestId('login').click();
  await page.getByLabel('Subject').fill(subject); // mock IdP form
  await page.getByRole('button', { name: 'Sign in' }).click();
}

test.describe('unauthenticated access (M0-AC11)', () => {
  test('pages redirect to /login; API returns 401; health is up', async ({ page, request }) => {
    await page.goto('/');
    await expect(page).toHaveURL(/\/login$/);
    await page.goto('/t/noordzee-capital');
    await expect(page).toHaveURL(/\/login$/);
    expect((await request.get('/api/v0/me')).status()).toBe(401);
    expect((await request.get('/api/health')).status()).toBe(200);
  });

  test('a forged session cookie is rejected', async ({ context, request }) => {
    await context.addCookies([{ name: 'ios_session', value: 'A'.repeat(43), url: 'http://127.0.0.1:3000' }]);
    expect((await context.request.get('/api/v0/me')).status()).toBe(401);
    expect((await request.get('/api/v0/me', { headers: { cookie: `ios_session=${'B'.repeat(43)}` } })).status()).toBe(401);
  });
});

test.describe('login and tenant isolation in the UI', () => {
  test('a synthetic user logs in via OIDC and lands in their tenant; session cookie is hardened', async ({ page, context }) => {
    const u = seed().users[1]!; // admin of tenant 1
    await login(page, u.subject);
    await expect(page).toHaveURL(new RegExp(`/t/${u.tenants[0]!.slug}$`));
    await expect(page.getByTestId('signed-in-as')).toContainText(u.displayName);
    const cookie = (await context.cookies()).find((c) => c.name === 'ios_session')!;
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.sameSite).toBe('Lax');
    expect(cookie.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  test("another tenant's URL returns 404, indistinguishable from a non-existent tenant (M0-AC15)", async ({ page }) => {
    const s = seed();
    const u = s.users[1]!;
    await login(page, u.subject);
    const foreign = await page.goto(`/t/${s.tenants[1]!.slug}`);
    expect(foreign?.status()).toBe(404);
    const foreignBody = await page.locator('main').innerText();
    const missing = await page.goto('/t/does-not-exist');
    expect(missing?.status()).toBe(404);
    expect(await page.locator('main').innerText()).toBe(foreignBody);
  });

  test('a multi-tenant user can switch tenants (A8); switching rotates the session token (R5)', async ({ page, context, request }) => {
    const s = seed();
    const multi = s.users.find((u) => u.tenants.length > 1)!;
    await login(page, multi.subject);
    await expect(page.getByTestId('tenant-switcher')).toBeVisible();
    const before = (await context.cookies()).find((c) => c.name === 'ios_session')!.value;
    await page.getByRole('link', { name: s.tenants[2]!.name }).click();
    await expect(page).toHaveURL(new RegExp(`/t/${s.tenants[2]!.slug}$`));
    await expect(page.getByTestId('tenant-name')).toHaveText(s.tenants[2]!.name);
    const after = (await context.cookies()).find((c) => c.name === 'ios_session')!.value;
    expect(after).not.toBe(before);
    expect((await request.get('/api/v0/me', { headers: { cookie: `ios_session=${before}` } })).status()).toBe(401);
  });

  test('an identity unknown to InvestorOS is refused', async ({ page }) => {
    await login(page, 'mallory-not-provisioned');
    await expect(page).toHaveURL(/\/login\?error=no_account$/);
    await expect(page.locator('p[role=alert]')).toBeVisible();
  });

  test('logout revokes the session server-side: a replayed cookie no longer works', async ({ page, context, request }) => {
    await login(page, seed().users[2]!.subject);
    const token = (await context.cookies()).find((c) => c.name === 'ios_session')!.value;
    await page.getByTestId('logout').click();
    await expect(page).toHaveURL(/\/login$/);
    const replay = await request.get('/api/v0/me', { headers: { cookie: `ios_session=${token}` } });
    expect(replay.status()).toBe(401);
  });

  test('logout without a same-origin Origin header is refused (CSRF)', async ({ request }) => {
    const r = await request.post('/auth/logout', { headers: { origin: 'https://evil.example' }, maxRedirects: 0 });
    expect(r.status()).toBe(403);
  });

  test('a tampered OIDC callback fails safely', async ({ page }) => {
    await page.goto('/auth/callback?code=forged&state=forged');
    await expect(page).toHaveURL(/\/login\?error=failed$/);
  });
});

test.describe('platform', () => {
  test('security headers are present', async ({ request }) => {
    const h = (await request.get('/login')).headers();
    expect(h['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['strict-transport-security']).toContain('max-age=');
    expect(h['x-powered-by']).toBeUndefined();
  });

  test('UI is internationalised (Dutch via Accept-Language) and shows the synthetic-data banner', async ({ browser }) => {
    const ctx = await browser.newContext({ locale: 'nl-NL', extraHTTPHeaders: { 'accept-language': 'nl-NL,nl;q=0.9' } });
    const page = await ctx.newPage();
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Inloggen' })).toBeVisible();
    await expect(page.getByRole('note')).toContainText('synthetische');
    await ctx.close();
  });
});
