import { KeyboardEvent, ReactNode, useEffect, useRef, useState } from "react";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Label } from "../components/Label";

export interface AppCommand {
  id: string;
  label: string;
  detail: string;
  run: () => void;
}

export interface AppCommandPaletteProps {
  /** Already filtered by the application, which owns the index and the search rules. */
  commands: AppCommand[];
  query: string;
  onQueryChange: (query: string) => void;
  onClose: () => void;
  labels: {
    title: string;
    query: string;
    placeholder: string;
    results: string;
    empty: string;
    navigateHint: string;
    selectHint: string;
    closeHint: string;
    closeButton: string;
  };
  /** Decorative icon at the end of each option. */
  optionIcon?: ReactNode;
}

/** A modal command palette: combobox + listbox, arrow keys, Enter runs, Escape and backdrop close. */
export function AppCommandPalette({ commands, query, onQueryChange, onClose, labels, optionIcon }: AppCommandPaletteProps) {
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => { input.current?.focus(); }, []);
  useEffect(() => { setActive(0); }, [query]);

  function run(command: AppCommand | undefined) {
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
      const focusable = Array.from(event.currentTarget.querySelectorAll<HTMLElement>("input:not([disabled]), button:not([disabled])"));
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
      <section className="command-palette" role="dialog" aria-modal="true" aria-labelledby="command-palette-title" onKeyDown={handleKeyDown}>
        <h2 id="command-palette-title" className="visually-hidden">{labels.title}</h2>
        <Label className="visually-hidden" htmlFor="command-palette-query">{labels.query}</Label>
        <Input
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
          placeholder={labels.placeholder}
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
        />
        <div id="command-palette-results" className="command-palette-results" role="listbox" aria-label={labels.results}>
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
              {optionIcon}
            </button>
          )) : <p className="command-empty">{labels.empty}</p>}
        </div>
        <footer className="command-palette-footer">
          <span>{labels.navigateHint}</span>
          <span>{labels.selectHint}</span>
          <span>{labels.closeHint}</span>
          <Button variant="ghost" className="command-close" onClick={onClose}>{labels.closeButton}</Button>
        </footer>
      </section>
    </div>
  );
}
