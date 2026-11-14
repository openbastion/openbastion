import { changeLanguage, currentLanguage, Language, supportedLanguages, useAppTranslation } from "../i18n";

const names: Record<Language, string> = { fr: "Français", en: "English" };

// The language selector: a native select, so it is keyboard-usable and announced as a listbox
// without extra code. Changing it applies everywhere on the spot and is remembered per browser.
export function LanguageSwitcher({ className = "" }: { className?: string }) {
  // `useAppTranslation` subscribes to the i18n instance: a second selector (header and login page)
  // re-renders in step with the first, and the label follows the new language.
  const { t } = useAppTranslation();
  return (
    <label className={"language-switcher " + className}>
      <span className="language-switcher-label">{t("common.language.label")}</span>
      <select
        value={currentLanguage()}
        aria-label={t("common.language.label")}
        onChange={(event) => changeLanguage(event.target.value as Language)}
      >
        {supportedLanguages.map((code) => (
          <option key={code} value={code} lang={code}>
            {names[code]}
          </option>
        ))}
      </select>
    </label>
  );
}
