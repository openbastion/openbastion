import { FormEvent, ReactNode } from "react";
import { Notice } from "../Notice";

// The card every write action is typed into: a titled, labelled form, its fields, the outcome of
// the last submit, then its one action. What the form sends stays the screen's business.
export function FormCard({
  label,
  title,
  hint,
  submitLabel,
  onSubmit,
  error,
  ok,
  children,
}: {
  label: string;
  title?: string;
  hint?: ReactNode;
  submitLabel: string;
  onSubmit: (e: FormEvent) => void;
  error?: unknown;
  ok?: string;
  children: ReactNode;
}) {
  return (
    <form onSubmit={onSubmit} aria-label={label} className="card form-card">
      {title ? <h3>{title}</h3> : null}
      {hint ? <p className="hint">{hint}</p> : null}
      <div className="fields">{children}</div>
      <Notice error={error} ok={ok} />
      <div className="form-actions">
        <button type="submit" className="primary">
          {submitLabel}
        </button>
      </div>
    </form>
  );
}
