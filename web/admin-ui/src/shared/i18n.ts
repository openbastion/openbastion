import i18n from "i18next";
import { initReactI18next, useTranslation } from "react-i18next";
import fr from "./i18n/locales/fr";
import en from "./i18n/locales/en";

// The two languages the Admin UI ships with. French is the default and the fallback: every key
// exists in both files, so a missing translation can only come from a forgotten key, never from
// an untranslated screen.
export const supportedLanguages = ["fr", "en"] as const;
export type Language = (typeof supportedLanguages)[number];

export const languageStorageKey = "openbastion.admin-ui.language.v1";

export function isLanguage(value: unknown): value is Language {
  return value === "fr" || value === "en";
}

// The language is a presentation choice of this browser, stored like the other operator
// preferences (ADR-0073): it never contains anything about the account or the session.
export function readLanguage(storage?: Pick<Storage, "getItem">): Language {
  try {
    const target = storage ?? (typeof window !== "undefined" ? window.localStorage : undefined);
    const stored = target?.getItem(languageStorageKey);
    return isLanguage(stored) ? stored : "fr";
  } catch {
    return "fr";
  }
}

export function writeLanguage(language: Language, storage?: Pick<Storage, "setItem">): boolean {
  try {
    const target = storage ?? (typeof window !== "undefined" ? window.localStorage : undefined);
    if (!target) return false;
    target.setItem(languageStorageKey, language);
    return true;
  } catch {
    return false;
  }
}

function applyDocumentLanguage(language: string): void {
  if (typeof document !== "undefined") document.documentElement.lang = language;
}

const initialLanguage = readLanguage();

// Resources are bundled, so the first render is already translated (`initAsync: false`): the
// login screen never flashes a key or a French label before switching language.
void i18n.use(initReactI18next).init({
  resources: { fr: { translation: fr }, en: { translation: en } },
  lng: initialLanguage,
  fallbackLng: "fr",
  supportedLngs: supportedLanguages,
  defaultNS: "translation",
  interpolation: { escapeValue: false },
  react: { useSuspense: false },
  initAsync: false,
});
applyDocumentLanguage(initialLanguage);
i18n.on("languageChanged", applyDocumentLanguage);

// Switching applies at once, without a reload: every mounted screen re-renders in the new
// language and the choice is remembered in this browser.
export function changeLanguage(language: Language): void {
  if (i18n.language === language) {
    writeLanguage(language);
    return;
  }
  void i18n.changeLanguage(language);
  writeLanguage(language);
}

// For the rare text built outside a component (a prompt, a message passed around): it reads the
// live instance, so it follows the language selected in the header.
export function translate(key: string, options?: Record<string, unknown>): string {
  return options ? (i18n.t(key, options) as string) : (i18n.t(key) as string);
}

export function currentLanguage(): Language {
  return isLanguage(i18n.language) ? i18n.language : "fr";
}

// Every component imports its translations through this module, which also runs the
// initialisation above: a screen rendered in a test has the same strings as in the browser.
export function useAppTranslation() {
  return useTranslation();
}
