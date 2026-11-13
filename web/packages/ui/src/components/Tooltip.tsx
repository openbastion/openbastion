import { forwardRef, type HTMLAttributes, type ReactElement, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-tooltip";
import { cn } from "../lib/cn";

export type TooltipProviderProps = { children: ReactNode; delayDuration?: number; skipDelayDuration?: number; disableHoverableContent?: boolean };
export function TooltipProvider({ children, delayDuration = 500, skipDelayDuration = 300, disableHoverableContent = false }: TooltipProviderProps) { return <Primitive.Provider delayDuration={delayDuration} skipDelayDuration={skipDelayDuration} disableHoverableContent={disableHoverableContent}>{children}</Primitive.Provider>; }
export type TooltipProps = { children: ReactNode; open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; delayDuration?: number };
export function Tooltip({ children, open, defaultOpen, onOpenChange, delayDuration }: TooltipProps) { return <Primitive.Root open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} delayDuration={delayDuration}>{children}</Primitive.Root>; }
export type TooltipTriggerProps = { children: ReactElement };
export function TooltipTrigger({ children }: TooltipTriggerProps) { return <Primitive.Trigger asChild>{children}</Primitive.Trigger>; }
export type TooltipContentProps = HTMLAttributes<HTMLDivElement> & { sideOffset?: number };
export const TooltipContent = forwardRef<HTMLDivElement, TooltipContentProps>(function TooltipContent({ className, sideOffset = 5, ...props }, ref) { return <Primitive.Portal><Primitive.Content {...props} ref={ref} sideOffset={sideOffset} className={cn("ob-tooltip-content", className)} /></Primitive.Portal>; });
TooltipContent.displayName = "TooltipContent";
