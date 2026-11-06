import { getTranslations } from 'next-intl/server';

export const dynamic = 'force-dynamic';

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const t = await getTranslations('login');
  const { error } = await searchParams;
  return (
    <main>
      <div className="card">
        <h1>{t('title')}</h1>
        {error === 'no_account' || error === 'no_membership' ? <p className="error" role="alert">{t('noAccount')}</p> : null}
        {error === 'failed' ? <p className="error" role="alert">{t('failed')}</p> : null}
        <a className="btn" href="/auth/login" data-testid="login">{t('button')}</a>
      </div>
    </main>
  );
}
