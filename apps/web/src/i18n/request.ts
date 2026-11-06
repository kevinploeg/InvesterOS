import { cookies, headers } from 'next/headers';
import { getRequestConfig } from 'next-intl/server';

export const LOCALES = ['en', 'nl'] as const;
export type Locale = (typeof LOCALES)[number];
const isLocale = (v: string | undefined): v is Locale => !!v && (LOCALES as readonly string[]).includes(v);

/** Locale: explicit cookie > Accept-Language > English. Translations for de/fr are added later. */
export default getRequestConfig(async () => {
  const fromCookie = (await cookies()).get('ios_locale')?.value;
  const accept = (await headers()).get('accept-language') ?? '';
  const fromHeader = accept.split(',').map((p) => p.split(';')[0]!.trim().slice(0, 2).toLowerCase()).find(isLocale);
  const locale: Locale = isLocale(fromCookie) ? fromCookie : (fromHeader ?? 'en');
  return { locale, messages: (await import(`../../messages/${locale}.json`)).default };
});
