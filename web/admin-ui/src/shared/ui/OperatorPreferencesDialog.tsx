import { FormEvent, useEffect, useRef, useState } from "react";
import { AdminTab, DensityPreference, OperatorPreferences, ThemePreference } from "../operatorPreferences";
import { Button } from "./Button";
import { useAppTranslation } from "../i18n";

const destinations: AdminTab[] = ["overview", "accounts", "policies", "sessions", "audit", "security"];

export function OperatorPreferencesDialog({
  preferences,
  onSave,
  onClose,
}: {
  preferences: OperatorPreferences;
  onSave: (next: OperatorPreferences) => boolean;
  onClose: () => void;
}) {
  const { t } = useAppTranslation();
  const [draft, setDraft] = useState(preferences);
  const [storageError, setStorageError] = useState(false);
  const firstField = useRef<HTMLSelectElement>(null);

  useEffect(() => {
    firstField.current?.focus();
  }, []);

  function handleKeyDown(event: React.KeyboardEvent<HTMLElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== "Tab") return;
    const dialog = event.currentTarget;
    const focusable = Array.from(dialog.querySelectorAll<HTMLElement>('select:not([disabled]), input:not([disabled]), button:not([disabled])'));
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last?.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first?.focus();
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (onSave(draft)) onClose();
    else setStorageError(true);
  }

  return (
    <div className="preferences-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section
        className="preferences-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="operator-preferences-title"
        onKeyDown={handleKeyDown}
      >
        <header className="preferences-dialog-head">
          <div>
            <h2 id="operator-preferences-title">{t("preferences.title")}</h2>
            <p className="ob-hint">{t("preferences.intro")}</p>
          </div>
          <Button variant="icon" className="preferences-close" aria-label={t("preferences.close")} onClick={onClose}>×</Button>
        </header>
        <form onSubmit={submit}>
          <div className="preferences-fields">
            <label>
              {t("preferences.theme")}
              <select
                ref={firstField}
                value={draft.theme}
                onChange={(event) => setDraft((current) => ({ ...current, theme: event.target.value as ThemePreference }))}
              >
                <option value="system">{t("preferences.themeSystem")}</option>
                <option value="light">{t("preferences.themeLight")}</option>
                <option value="dark">{t("preferences.themeDark")}</option>
              </select>
            </label>
            <label>
              {t("preferences.density")}
              <select
                value={draft.density}
                onChange={(event) => setDraft((current) => ({ ...current, density: event.target.value as DensityPreference }))}
              >
                <option value="comfortable">{t("preferences.densityComfortable")}</option>
                <option value="compact">{t("preferences.densityCompact")}</option>
              </select>
            </label>
            <label>
              {t("preferences.defaultTab")}
              <select
                value={draft.defaultTab}
                onChange={(event) => setDraft((current) => ({ ...current, defaultTab: event.target.value as AdminTab }))}
              >
                {destinations.map((destination) => (
                  <option key={destination} value={destination}>{t(`preferences.destinations.${destination}`)}</option>
                ))}
              </select>
            </label>
            <label className="preferences-checkbox">
              <input
                type="checkbox"
                checked={draft.sidebarCollapsed}
                onChange={(event) => setDraft((current) => ({ ...current, sidebarCollapsed: event.target.checked }))}
              />
              {t("preferences.sidebarCollapsed")}
            </label>
          </div>
          <section className="shortcut-help" aria-labelledby="shortcut-help-title">
            <h3 id="shortcut-help-title">{t("preferences.shortcuts.title")}</h3>
            <dl>
              <div><dt>{t("preferences.shortcuts.palette")}</dt><dd><kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>K</kbd></dd></div>
              <div><dt>{t("preferences.shortcuts.section")}</dt><dd><kbd>Alt</kbd> + <kbd>{t("preferences.shortcuts.shiftKey")}</kbd> + <kbd>1–6</kbd></dd></div>
              <div><dt>{t("preferences.shortcuts.close")}</dt><dd><kbd>{t("preferences.shortcuts.escapeKey")}</kbd></dd></div>
            </dl>
            <p className="ob-hint">{t("preferences.shortcuts.hint")}</p>
          </section>
          {storageError ? <p className="preferences-storage-error" role="alert">{t("preferences.storageError")}</p> : null}
          <div className="ob-form-actions">
            <Button onClick={onClose}>{t("common.actions.cancel")}</Button>
            <Button type="submit" variant="primary">{t("preferences.save")}</Button>
          </div>
        </form>
      </section>
    </div>
  );
}
