import type { HTMLAttributes, ReactElement, ReactNode } from "react";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "./Dialog";

export type DrawerProps = { open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; children: ReactNode };
export function Drawer({ open, defaultOpen, onOpenChange, children }: DrawerProps) { return <Dialog open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>{children}</Dialog>; }
export type DrawerTriggerProps = { children: ReactElement };
export function DrawerTrigger({ children }: DrawerTriggerProps) { return <DialogTrigger>{children}</DialogTrigger>; }
export type DrawerCloseProps = { children: ReactElement };
export function DrawerClose({ children }: DrawerCloseProps) { return <DialogClose>{children}</DialogClose>; }
export type DrawerContentProps = HTMLAttributes<HTMLDivElement>;
export function DrawerContent({ className, ...props }: DrawerContentProps) { return <DialogContent {...props} className={className ? `ob-drawer-content ${className}` : "ob-drawer-content"} />; }
export { DialogTitle as DrawerTitle, DialogDescription as DrawerDescription };
