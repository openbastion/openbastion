import { ReactNode } from "react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@openbastion/ui";

// The design system's modal: a dialog opened over the current screen, with its title and an
// optional description announced to assistive technology. Screens own the open state and the
// content; this component only carries the shared overlay behaviour.
export function Modal({
  open,
  onOpenChange,
  title,
  description,
  className,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={className}>
        <DialogTitle>{title}</DialogTitle>
        {description ? <DialogDescription>{description}</DialogDescription> : null}
        {children}
      </DialogContent>
    </Dialog>
  );
}
