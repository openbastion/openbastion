import { forwardRef, type HTMLAttributes, type ReactElement, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-alert-dialog";
import { cn } from "../lib/cn";

export type AlertDialogProps = { open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; children: ReactNode };
export function AlertDialog({ open, defaultOpen, onOpenChange, children }: AlertDialogProps) {
  return <Primitive.Root open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>{children}</Primitive.Root>;
}
export type AlertDialogTriggerProps = { children: ReactElement };
export function AlertDialogTrigger({ children }: AlertDialogTriggerProps) { return <Primitive.Trigger asChild>{children}</Primitive.Trigger>; }
export type AlertDialogContentProps = HTMLAttributes<HTMLDivElement> & { overlayClassName?: string };
export const AlertDialogContent = forwardRef<HTMLDivElement, AlertDialogContentProps>(function AlertDialogContent({ className, overlayClassName, children, ...props }, ref) {
  return <Primitive.Portal><Primitive.Overlay className={cn("ob-overlay", overlayClassName)} /><Primitive.Content {...props} ref={ref} className={cn("ob-dialog-content", "ob-alert-dialog-content", className)}>{children}</Primitive.Content></Primitive.Portal>;
});
AlertDialogContent.displayName = "AlertDialogContent";
export type AlertDialogTitleProps = HTMLAttributes<HTMLHeadingElement>;
export const AlertDialogTitle = forwardRef<HTMLHeadingElement, AlertDialogTitleProps>(function AlertDialogTitle({ className, ...props }, ref) { return <Primitive.Title {...props} ref={ref} className={cn("ob-dialog-title", className)} />; });
AlertDialogTitle.displayName = "AlertDialogTitle";
export type AlertDialogDescriptionProps = HTMLAttributes<HTMLParagraphElement>;
export const AlertDialogDescription = forwardRef<HTMLParagraphElement, AlertDialogDescriptionProps>(function AlertDialogDescription({ className, ...props }, ref) { return <Primitive.Description {...props} ref={ref} className={cn("ob-dialog-description", className)} />; });
AlertDialogDescription.displayName = "AlertDialogDescription";
export type AlertDialogActionProps = { children: ReactElement };
export function AlertDialogAction({ children }: AlertDialogActionProps) { return <Primitive.Action asChild>{children}</Primitive.Action>; }
export type AlertDialogCancelProps = { children: ReactElement };
export function AlertDialogCancel({ children }: AlertDialogCancelProps) { return <Primitive.Cancel asChild>{children}</Primitive.Cancel>; }
