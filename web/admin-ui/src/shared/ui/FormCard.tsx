import { FormEvent, ReactNode } from "react";
import { Notice } from "../Notice";
import { Button } from "./Button";

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
    <form onSubmit={onSubmit} aria-label={label} className="ob-surface ob-form-card">
      {title ? <h3>{title}</h3> : null}
      {hint ? <p className="ob-hint">{hint}</p> : null}
      <div className="ob-form-fields">{children}</div>
      <Notice error={error} ok={ok} />
      <div className="ob-form-actions">
        <Button type="submit" variant="primary">
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
