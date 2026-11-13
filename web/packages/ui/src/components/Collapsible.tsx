import type { ReactElement, ReactNode } from "react";
import * as Primitive from "@radix-ui/react-collapsible";
import { cn } from "../lib/cn";

export type CollapsibleProps = { open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; disabled?: boolean; children: ReactNode; className?: string };
export function Collapsible({ open, defaultOpen, onOpenChange, disabled, children, className }: CollapsibleProps) { return <Primitive.Root open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} disabled={disabled} className={cn("ob-collapsible", className)}>{children}</Primitive.Root>; }
export type CollapsibleTriggerProps = { children: ReactElement };
export function CollapsibleTrigger({ children }: CollapsibleTriggerProps) { return <Primitive.Trigger asChild>{children}</Primitive.Trigger>; }
export type CollapsibleContentProps = React.HTMLAttributes<HTMLDivElement>;
export function CollapsibleContent({ className, ...props }: CollapsibleContentProps) { return <Primitive.Content {...props} className={cn("ob-collapsible-content", className)} />; }
