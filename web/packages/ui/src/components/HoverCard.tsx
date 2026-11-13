import { forwardRef, type HTMLAttributes, type ReactElement, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-hover-card";
import { cn } from "../lib/cn";

export type HoverCardProps = { children: ReactNode; open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; openDelay?: number; closeDelay?: number };
export function HoverCard({ children, open, defaultOpen, onOpenChange, openDelay = 500, closeDelay = 300 }: HoverCardProps) { return <Primitive.Root open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} openDelay={openDelay} closeDelay={closeDelay}>{children}</Primitive.Root>; }
export type HoverCardTriggerProps = { children: ReactElement };
export function HoverCardTrigger({ children }: HoverCardTriggerProps) { return <Primitive.Trigger asChild>{children}</Primitive.Trigger>; }
export type HoverCardContentProps = HTMLAttributes<HTMLDivElement> & { sideOffset?: number; align?: "start" | "center" | "end" };
export const HoverCardContent = forwardRef<HTMLDivElement, HoverCardContentProps>(function HoverCardContent({ className, sideOffset = 6, align = "center", ...props }, ref) { return <Primitive.Portal><Primitive.Content {...props} ref={ref} sideOffset={sideOffset} align={align} className={cn("ob-popover-content", className)} /></Primitive.Portal>; });
HoverCardContent.displayName = "HoverCardContent";
