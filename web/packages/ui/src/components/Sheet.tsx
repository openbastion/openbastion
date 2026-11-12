import type { HTMLAttributes, ReactElement, ReactNode } from "react";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "./Dialog";

export type SheetProps = { open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; children: ReactNode };
export function Sheet({ open, defaultOpen, onOpenChange, children }: SheetProps) { return <Dialog open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>{children}</Dialog>; }
export type SheetTriggerProps = { children: ReactElement };
export function SheetTrigger({ children }: SheetTriggerProps) { return <DialogTrigger>{children}</DialogTrigger>; }
export type SheetCloseProps = { children: ReactElement };
export function SheetClose({ children }: SheetCloseProps) { return <DialogClose>{children}</DialogClose>; }
export type SheetContentProps = HTMLAttributes<HTMLDivElement> & { side?: "left" | "right" | "top" | "bottom" };
export function SheetContent({ side = "right", className, ...props }: SheetContentProps) { return <DialogContent {...props} data-side={side} className={className ? `ob-sheet-content ${className}` : "ob-sheet-content"} />; }
export { DialogTitle as SheetTitle, DialogDescription as SheetDescription };
