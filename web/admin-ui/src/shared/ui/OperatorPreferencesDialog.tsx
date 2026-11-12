import { FormEvent, useEffect, useRef, useState } from "react";
import { AdminTab, DensityPreference, OperatorPreferences, ThemePreference } from "../operatorPreferences";
import { Button } from "./Button";

const destinations: { value: AdminTab; label: string }[] = [
  { value: "overview", label: "Vue générale" },
  { value: "accounts", label: "Comptes privilégiés" },
  { value: "policies", label: "Politiques" },
  { value: "sessions", label: "Sessions" },
  { value: "audit", label: "Enregistrements" },
  { value: "security", label: "Centre de sécurité" },
];

export function OperatorPreferencesDialog({
  preferences,
  onSave,
  onClose,
}: {
  preferences: OperatorPreferences;
  onSave: (next: OperatorPreferences) => boolean;
  onClose: () => void;
}) {
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
            <h2 id="operator-preferences-title">Préférences et raccourcis</h2>
            <p className="hint">Ces réglages sont conservés uniquement dans ce navigateur.</p>
          </div>
          <Button variant="icon" className="preferences-close" aria-label="Fermer les préférences" onClick={onClose}>×</Button>
        </header>
        <form onSubmit={submit}>
          <div className="preferences-fields">
            <label>
              Thème
              <select
                ref={firstField}
                value={draft.theme}
                onChange={(event) => setDraft((current) => ({ ...current, theme: event.target.value as ThemePreference }))}
              >
                <option value="system">Selon le système</option>
                <option value="light">Clair</option>
                <option value="dark">Sombre</option>
              </select>
            </label>
            <label>
              Densité de l'interface
              <select
                value={draft.density}
                onChange={(event) => setDraft((current) => ({ ...current, density: event.target.value as DensityPreference }))}
              >
                <option value="comfortable">Confortable</option>
                <option value="compact">Compacte</option>
              </select>
            </label>
            <label>
              Vue affichée à la connexion
              <select
                value={draft.defaultTab}
                onChange={(event) => setDraft((current) => ({ ...current, defaultTab: event.target.value as AdminTab }))}
              >
                {destinations.map((destination) => <option key={destination.value} value={destination.value}>{destination.label}</option>)}
              </select>
            </label>
            <label className="preferences-checkbox">
              <input
                type="checkbox"
                checked={draft.sidebarCollapsed}
                onChange={(event) => setDraft((current) => ({ ...current, sidebarCollapsed: event.target.checked }))}
              />
              Réduire la navigation latérale
            </label>
          </div>
          <section className="shortcut-help" aria-labelledby="shortcut-help-title">
            <h3 id="shortcut-help-title">Raccourcis clavier</h3>
            <dl>
              <div><dt>Ouvrir la palette de commandes</dt><dd><kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>K</kbd></dd></div>
              <div><dt>Accéder à une section (1 à 6)</dt><dd><kbd>Alt</kbd> + <kbd>Maj</kbd> + <kbd>1–6</kbd></dd></div>
              <div><dt>Fermer un panneau ou une palette</dt><dd><kbd>Échap</kbd></dd></div>
            </dl>
            <p className="hint">Les raccourcis de navigation sont ignorés lorsque le curseur se trouve dans un champ de saisie.</p>
          </section>
          {storageError ? <p className="preferences-storage-error" role="alert">Impossible d'enregistrer les préférences dans le stockage local de ce navigateur. Vérifiez ses paramètres de confidentialité et réessayez.</p> : null}
          <div className="form-actions">
            <Button onClick={onClose}>Annuler</Button>
            <Button type="submit" variant="primary">Enregistrer les préférences</Button>
          </div>
        </form>
      </section>
    </div>
  );
}
