import type { ReactNode } from 'react';
import { NextIntlClientProvider } from 'next-intl';
import { getLocale, getTranslations } from 'next-intl/server';
import './globals.css';

export const metadata = { title: 'InvestorOS', robots: { index: false, follow: false } };

export default async function RootLayout({ children }: { children: ReactNode }) {
  const locale = await getLocale();
  const t = await getTranslations('common');
  return (
    <html lang={locale}>
      <body>
        <div className="synthetic-banner" role="note">{t('syntheticBanner')}</div>
        <NextIntlClientProvider>{children}</NextIntlClientProvider>
      </body>
    </html>
  );
}
