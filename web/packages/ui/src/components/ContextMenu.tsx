import { forwardRef, type HTMLAttributes, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-context-menu";
import { cn } from "../lib/cn";

export type ContextMenuProps = { children: ReactNode; onOpenChange?: (open: boolean) => void };
export function ContextMenu({ children, onOpenChange }: ContextMenuProps) { return <Primitive.Root onOpenChange={onOpenChange}>{children}</Primitive.Root>; }
export type ContextMenuTriggerProps = HTMLAttributes<HTMLDivElement>;
export const ContextMenuTrigger = forwardRef<HTMLDivElement, ContextMenuTriggerProps>(function ContextMenuTrigger({ className, ...props }, ref) { return <Primitive.Trigger {...props} ref={ref} className={cn("ob-context-menu-trigger", className)} />; });
ContextMenuTrigger.displayName = "ContextMenuTrigger";
export type ContextMenuContentProps = HTMLAttributes<HTMLDivElement> & { sideOffset?: number };
export const ContextMenuContent = forwardRef<HTMLDivElement, ContextMenuContentProps>(function ContextMenuContent({ className, sideOffset = 4, ...props }, ref) { return <Primitive.Portal><Primitive.Content {...props} ref={ref} sideOffset={sideOffset} className={cn("ob-menu-content", className)} /></Primitive.Portal>; });
ContextMenuContent.displayName = "ContextMenuContent";
export type ContextMenuItemProps = HTMLAttributes<HTMLDivElement> & { disabled?: boolean; onSelect?: () => void };
export const ContextMenuItem = forwardRef<HTMLDivElement, ContextMenuItemProps>(function ContextMenuItem({ className, ...props }, ref) { return <Primitive.Item {...props} ref={ref} className={cn("ob-menu-item", className)} />; });
ContextMenuItem.displayName = "ContextMenuItem";
export type ContextMenuSeparatorProps = HTMLAttributes<HTMLDivElement>;
export const ContextMenuSeparator = forwardRef<HTMLDivElement, ContextMenuSeparatorProps>(function ContextMenuSeparator({ className, ...props }, ref) { return <Primitive.Separator {...props} ref={ref} className={cn("ob-menu-separator", className)} />; });
ContextMenuSeparator.displayName = "ContextMenuSeparator";
export type ContextMenuLabelProps = HTMLAttributes<HTMLDivElement>;
export const ContextMenuLabel = forwardRef<HTMLDivElement, ContextMenuLabelProps>(function ContextMenuLabel({ className, ...props }, ref) { return <Primitive.Label {...props} ref={ref} className={cn("ob-menu-label", className)} />; });
ContextMenuLabel.displayName = "ContextMenuLabel";
