import { FormEvent, ReactNode } from "react";
import { Form } from "@openbastion/ui";
import { Notice } from "../Notice";
import { Button } from "./Button";

// The card every write action is typed into: a titled, labelled form, its fields, the outcome of
// the last submit, then its actions. What the form sends stays the screen's business.
//
// While `submitting` is true the form says it is busy and its submit button is disabled and says
// so (`submittingLabel`): a second click must not send a second request. `noValidate` hands
// required-field errors to the screen, which shows them under each field instead of the
// browser's bubble; `footer` and `secondaryAction` sit next to the submit button.
export function FormCard({
  label,
  title,
  hint,
  submitLabel,
  submittingLabel,
  submitting = false,
  noValidate = false,
  footer,
  secondaryAction,
  onSubmit,
  error,
  ok,
  children,
}: {
  label: string;
  title?: string;
  hint?: ReactNode;
  submitLabel: string;
  submittingLabel?: string;
  submitting?: boolean;
  noValidate?: boolean;
  footer?: ReactNode;
  secondaryAction?: ReactNode;
  onSubmit: (e: FormEvent) => void;
  error?: unknown;
  ok?: string;
  children: ReactNode;
}) {
  return (
    <Form onSubmit={onSubmit} aria-label={label} aria-busy={submitting || undefined} noValidate={noValidate} className="ob-surface ob-form-card">
      {title ? <h3>{title}</h3> : null}
      {hint ? <p className="ob-hint">{hint}</p> : null}
      <div className="ob-form-fields">{children}</div>
      <Notice error={error} ok={ok} />
      {footer}
      <div className="ob-form-actions">
        {secondaryAction}
        <Button type="submit" variant="primary" disabled={submitting}>
          {submitting && submittingLabel ? submittingLabel : submitLabel}
        </Button>
      </div>
    </Form>
  );
}
