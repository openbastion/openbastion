import { KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import type { Tab } from "../../app/AppShell";
import { useAppTranslation } from "../i18n";

type Command = {
  id: string;
  label: string;
  detail: string;
  keywords: string;
  run: () => void;
};

// A local command index only: it never enumerates resources or bypasses the Gateway.
export function CommandPalette({
  onClose,
  onNavigate,
  onFindSession,
}: {
  onClose: () => void;
  onNavigate: (tab: Tab) => void;
  onFindSession: (id: string) => void;
}) {
  const { t, i18n } = useAppTranslation();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  const commands = useMemo<Command[]>(() => {
    const destinations: { tab: Tab; label: string; detail: string; keywords: string }[] = (
      ["overview", "accounts", "policies", "sessions", "audit", "security"] as const
    ).map((tab) => ({
      tab,
      label: t(`palette.destinations.${tab}.label`),
      detail: t(`palette.destinations.${tab}.detail`),
      keywords: t(`palette.destinations.${tab}.keywords`),
    }));
    const normalized = query.trim().toLocaleLowerCase(i18n.language);
    const navigation: Command[] = destinations
      .filter((item) => !normalized || `${item.label} ${item.detail} ${item.keywords}`.toLocaleLowerCase(i18n.language).includes(normalized))
      .map((item) => ({
        id: item.tab,
        label: item.label,
        detail: item.detail,
        keywords: item.keywords,
        run: () => onNavigate(item.tab),
      }));
    if (query.trim()) {
      navigation.push({
        id: "find-session",
        label: t("palette.findSession.label", { query: query.trim() }),
        detail: t("palette.findSession.detail"),
        keywords: t("palette.findSession.keywords"),
        run: () => onFindSession(query.trim()),
      });
    }
    return navigation;
  }, [i18n.language, onFindSession, onNavigate, query, t]);

  useEffect(() => {
    input.current?.focus();
  }, []);

  useEffect(() => {
    setActive(0);
  }, [query]);

  function run(command: Command | undefined) {
    if (!command) return;
    command.run();
    onClose();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => Math.min(index + 1, commands.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => Math.max(index - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      run(commands[active]);
    } else if (event.key === "Tab") {
      const dialog = event.currentTarget;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>('input:not([disabled]), button:not([disabled])'));
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
  }

  return (
    <div className="command-palette-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section
        className="command-palette"
        role="dialog"
        aria-modal="true"
        aria-labelledby="command-palette-title"
        onKeyDown={handleKeyDown}
      >
        <h2 id="command-palette-title" className="visually-hidden">{t("palette.title")}</h2>
        <label className="visually-hidden" htmlFor="command-palette-query">{t("palette.queryLabel")}</label>
        <input
          ref={input}
          id="command-palette-query"
          type="search"
          role="combobox"
          aria-autocomplete="list"
          aria-expanded="true"
          aria-controls="command-palette-results"
          aria-activedescendant={commands[active] ? `command-${commands[active].id}` : undefined}
          autoComplete="off"
          spellCheck={false}
          placeholder={t("palette.placeholder")}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <div id="command-palette-results" className="command-palette-results" role="listbox" aria-label={t("palette.results")}>
          {commands.length ? commands.map((command, index) => (
            <button
              key={command.id}
              id={`command-${command.id}`}
              type="button"
              role="option"
              aria-selected={active === index}
              className="command-option"
              onMouseEnter={() => setActive(index)}
              onClick={() => run(command)}
            >
              <span>
                <strong>{command.label}</strong>
                <small>{command.detail}</small>
              </span>
              <span className="command-enter" aria-hidden="true">↵</span>
            </button>
          )) : <p className="command-empty">{t("palette.empty")}</p>}
        </div>
        <footer className="command-palette-footer">
          <span>{t("palette.footer.navigate")}</span>
          <span>{t("palette.footer.select")}</span>
          <span>{t("palette.footer.close")}</span>
          <button type="button" className="command-close" onClick={onClose}>{t("palette.footer.closeButton")}</button>
        </footer>
      </section>
    </div>
  );
}
