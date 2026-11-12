import { KeyboardEvent, useEffect, useRef, useState } from "react";

// Explicit confirmation for privileged or destructive actions. The caller owns the API request;
// this component only guards the gesture and keeps focus inside the alert dialog.
export function ConfirmDialog({
  title,
  description,
  confirmLabel,
  danger = true,
  error,
  onConfirm,
  onCancel,
}: {
  title: string;
  description: string;
  confirmLabel: string;
  danger?: boolean;
  error?: string;
  onConfirm: () => Promise<boolean>;
  onCancel: () => void;
}) {
  const cancel = useRef<HTMLButtonElement>(null);
  const confirm = useRef<HTMLButtonElement>(null);
  const trigger = useRef<HTMLElement | null>(document.activeElement instanceof HTMLElement ? document.activeElement : null);
  const busy = useRef(false);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    cancel.current?.focus();
    return () => {
      if (trigger.current?.isConnected) trigger.current.focus();
      else document.querySelector<HTMLElement>("[data-confirm-focus-fallback]")?.focus();
    };
  }, []);

  async function submit() {
    if (busy.current) return;
    busy.current = true;
    setWorking(true);
    try {
      if (await onConfirm()) onCancel();
    } finally {
      busy.current = false;
      setWorking(false);
    }
  }

  function keys(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape" && !working) {
      event.preventDefault();
      onCancel();
    } else if (event.key === "Tab") {
      if (event.shiftKey && document.activeElement === cancel.current) {
        event.preventDefault();
        confirm.current?.focus();
      } else if (!event.shiftKey && document.activeElement === confirm.current) {
        event.preventDefault();
        cancel.current?.focus();
      }
    }
  }

  return (
    <div className="confirm-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !working) onCancel(); }}>
      <div className="confirm-dialog" role="alertdialog" aria-modal="true" aria-busy={working} aria-labelledby="confirm-title" aria-describedby="confirm-description" onKeyDown={keys}>
        <h2 id="confirm-title">{title}</h2>
        <p id="confirm-description">{description}</p>
        {error ? <p className="notice error" role="alert">{error}</p> : null}
        <div className="form-actions">
          <button ref={cancel} type="button" disabled={working} onClick={onCancel}>Annuler</button>
          <button ref={confirm} type="button" className={danger ? "danger" : "primary"} disabled={working} onClick={() => void submit()}>
            {working ? "Traitement…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
