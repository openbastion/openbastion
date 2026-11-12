import { forwardRef, type HTMLAttributes, type ReactElement, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-dialog";
import { cn } from "../lib/cn";

export type DialogProps = { open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; modal?: boolean; children: ReactNode };
export function Dialog({ open, defaultOpen, onOpenChange, modal = true, children }: DialogProps) {
  return <Primitive.Root open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} modal={modal}>{children}</Primitive.Root>;
}
export type DialogTriggerProps = { children: ReactElement };
export function DialogTrigger({ children }: DialogTriggerProps) {
  return <Primitive.Trigger asChild>{children}</Primitive.Trigger>;
}
export type DialogCloseProps = { children: ReactElement };
export function DialogClose({ children }: DialogCloseProps) {
  return <Primitive.Close asChild>{children}</Primitive.Close>;
}
export type DialogContentProps = HTMLAttributes<HTMLDivElement> & { overlayClassName?: string; onOpenAutoFocus?: (event: Event) => void; onCloseAutoFocus?: (event: Event) => void };
export const DialogContent = forwardRef<HTMLDivElement, DialogContentProps>(function DialogContent({ className, overlayClassName, children, ...props }, ref) {
  return (
    <Primitive.Portal>
      <Primitive.Overlay className={cn("ob-overlay", overlayClassName)} />
      <Primitive.Content {...props} ref={ref} className={cn("ob-dialog-content", className)}>{children}</Primitive.Content>
    </Primitive.Portal>
  );
});
DialogContent.displayName = "DialogContent";
export type DialogTitleProps = HTMLAttributes<HTMLHeadingElement>;
export const DialogTitle = forwardRef<HTMLHeadingElement, DialogTitleProps>(function DialogTitle({ className, ...props }, ref) {
  return <Primitive.Title {...props} ref={ref} className={cn("ob-dialog-title", className)} />;
});
DialogTitle.displayName = "DialogTitle";
export type DialogDescriptionProps = HTMLAttributes<HTMLParagraphElement>;
export const DialogDescription = forwardRef<HTMLParagraphElement, DialogDescriptionProps>(function DialogDescription({ className, ...props }, ref) {
  return <Primitive.Description {...props} ref={ref} className={cn("ob-dialog-description", className)} />;
});
DialogDescription.displayName = "DialogDescription";
