import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { en } from './locales/en';
import { ps } from './locales/ps';
import { fa } from './locales/fa';

export type LanguageCode = 'en' | 'ps' | 'fa';

export const LANGUAGE_NAMES: Record<LanguageCode, string> = {
  en: 'English',
  ps: 'پښتو',
  fa: 'فارسی',
};

/** Pashto and Persian are RTL scripts. */
export function isRtl(code: string): boolean {
  return code === 'ps' || code === 'fa';
}

export const STORAGE_KEY = 'qrs.lang';

const saved = (): string => {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? 'en';
  } catch {
    return 'en';
  }
};

void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    ps: { translation: ps },
    fa: { translation: fa },
  },
  lng: saved(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
});

export function setLanguage(code: LanguageCode): void {
  void i18n.changeLanguage(code);
  document.documentElement.lang = code;
  try {
    localStorage.setItem(STORAGE_KEY, code);
  } catch {
    /* ignore */
  }
}

// Reflect the initial language on <html lang>.
document.documentElement.lang = saved();

export default i18n;
