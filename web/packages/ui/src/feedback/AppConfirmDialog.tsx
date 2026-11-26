import { useEffect, useRef, useState } from "react";
import { AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogTitle } from "../components/AlertDialog";
import { Alert } from "../components/Alert";
import { Button } from "../components/Button";

export type AppConfirmDialogProps = {
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel: string;
  workingLabel: string;
  danger?: boolean;
  error?: string;
  // The caller owns the request; true closes the dialog, false keeps it open (with `error`).
  onConfirm: () => Promise<boolean>;
  onCancel: () => void;
};

// Explicit confirmation of a privileged or destructive action. Mounted when needed. Focus starts on
// Cancel (never on the destructive control), Escape and the overlay cancel unless a request is in
// flight, and a second click cannot send the request twice.
export function AppConfirmDialog({
  title,
  description,
  confirmLabel,
  cancelLabel,
  workingLabel,
  danger = true,
  error,
  onConfirm,
  onCancel,
}: AppConfirmDialogProps) {
  const [working, setWorking] = useState(false);
  const busy = useRef(false);
  // The dialog is unmounted by its caller, so Radix has no trigger to return to (its alert dialog
  // sends focus to the removed Cancel button): the element that had focus is restored here, or the
  // page's focus fallback (the heading marked `data-confirm-focus-fallback`) when it is gone.
  const trigger = useRef<HTMLElement | null>(document.activeElement instanceof HTMLElement ? document.activeElement : null);
  useEffect(() => () => {
    if (trigger.current?.isConnected) trigger.current.focus();
    else document.querySelector<HTMLElement>("[data-confirm-focus-fallback]")?.focus();
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

  return (
    <AlertDialog open onOpenChange={(open) => { if (!open && !working) onCancel(); }}>
      <AlertDialogContent aria-busy={working}>
        <AlertDialogTitle>{title}</AlertDialogTitle>
        <AlertDialogDescription>{description}</AlertDialogDescription>
        {error ? <Alert tone="danger">{error}</Alert> : null}
        <div className="ob-form-actions">
          <AlertDialogCancel><Button disabled={working} onClick={onCancel}>{cancelLabel}</Button></AlertDialogCancel>
          <Button variant={danger ? "danger" : "primary"} disabled={working} onClick={() => void submit()}>
            {working ? workingLabel : confirmLabel}
          </Button>
        </div>
      </AlertDialogContent>
    </AlertDialog>
  );
}
