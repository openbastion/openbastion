import { forwardRef, type HTMLAttributes, type ReactElement, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-popover";
import { cn } from "../lib/cn";

export type PopoverProps = { open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; modal?: boolean; children: ReactNode };
export function Popover({ open, defaultOpen, onOpenChange, modal = false, children }: PopoverProps) { return <Primitive.Root open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} modal={modal}>{children}</Primitive.Root>; }
export type PopoverTriggerProps = { children: ReactElement };
export function PopoverTrigger({ children }: PopoverTriggerProps) { return <Primitive.Trigger asChild>{children}</Primitive.Trigger>; }
export type PopoverAnchorProps = HTMLAttributes<HTMLDivElement>;
export const PopoverAnchor = forwardRef<HTMLDivElement, PopoverAnchorProps>(function PopoverAnchor({ className, ...props }, ref) { return <Primitive.Anchor {...props} ref={ref} className={className} />; });
PopoverAnchor.displayName = "PopoverAnchor";
export type PopoverContentProps = HTMLAttributes<HTMLDivElement> & { sideOffset?: number; align?: "start" | "center" | "end" };
export const PopoverContent = forwardRef<HTMLDivElement, PopoverContentProps>(function PopoverContent({ className, sideOffset = 6, align = "center", ...props }, ref) { return <Primitive.Portal><Primitive.Content {...props} ref={ref} sideOffset={sideOffset} align={align} className={cn("ob-popover-content", className)} /></Primitive.Portal>; });
PopoverContent.displayName = "PopoverContent";
export type PopoverCloseProps = { children: ReactElement };
export function PopoverClose({ children }: PopoverCloseProps) { return <Primitive.Close asChild>{children}</Primitive.Close>; }
