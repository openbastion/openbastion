import { forwardRef, type HTMLAttributes, type ReactElement, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-dropdown-menu";
import { cn } from "../lib/cn";

export type DropdownMenuProps = { open?: boolean; defaultOpen?: boolean; onOpenChange?: (open: boolean) => void; modal?: boolean; children: ReactNode };
export function DropdownMenu({ open, defaultOpen, onOpenChange, modal = true, children }: DropdownMenuProps) { return <Primitive.Root open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} modal={modal}>{children}</Primitive.Root>; }
export type DropdownMenuTriggerProps = { children: ReactElement };
export function DropdownMenuTrigger({ children }: DropdownMenuTriggerProps) { return <Primitive.Trigger asChild>{children}</Primitive.Trigger>; }
export type DropdownMenuContentProps = HTMLAttributes<HTMLDivElement> & { sideOffset?: number; align?: "start" | "center" | "end" };
export const DropdownMenuContent = forwardRef<HTMLDivElement, DropdownMenuContentProps>(function DropdownMenuContent({ className, sideOffset = 4, align = "end", ...props }, ref) { return <Primitive.Portal><Primitive.Content {...props} ref={ref} sideOffset={sideOffset} align={align} className={cn("ob-menu-content", className)} /></Primitive.Portal>; });
DropdownMenuContent.displayName = "DropdownMenuContent";
export type DropdownMenuItemProps = HTMLAttributes<HTMLDivElement> & { disabled?: boolean; onSelect?: () => void; inset?: boolean };
export const DropdownMenuItem = forwardRef<HTMLDivElement, DropdownMenuItemProps>(function DropdownMenuItem({ className, disabled, onSelect, inset, ...props }, ref) { return <Primitive.Item {...props} ref={ref} disabled={disabled} onSelect={onSelect} data-inset={inset || undefined} className={cn("ob-menu-item", className)} />; });
DropdownMenuItem.displayName = "DropdownMenuItem";
export type DropdownMenuCheckboxItemProps = Omit<DropdownMenuItemProps, "onSelect"> & { checked: boolean | "indeterminate"; onCheckedChange?: (checked: boolean) => void };
export const DropdownMenuCheckboxItem = forwardRef<HTMLDivElement, DropdownMenuCheckboxItemProps>(function DropdownMenuCheckboxItem({ className, checked, onCheckedChange, ...props }, ref) { return <Primitive.CheckboxItem {...props} ref={ref} checked={checked} onCheckedChange={onCheckedChange} className={cn("ob-menu-item", className)} />; });
DropdownMenuCheckboxItem.displayName = "DropdownMenuCheckboxItem";
export type DropdownMenuLabelProps = HTMLAttributes<HTMLDivElement> & { inset?: boolean };
export const DropdownMenuLabel = forwardRef<HTMLDivElement, DropdownMenuLabelProps>(function DropdownMenuLabel({ className, inset, ...props }, ref) { return <Primitive.Label {...props} ref={ref} data-inset={inset || undefined} className={cn("ob-menu-label", className)} />; });
DropdownMenuLabel.displayName = "DropdownMenuLabel";
export type DropdownMenuSeparatorProps = HTMLAttributes<HTMLDivElement>;
export const DropdownMenuSeparator = forwardRef<HTMLDivElement, DropdownMenuSeparatorProps>(function DropdownMenuSeparator({ className, ...props }, ref) { return <Primitive.Separator {...props} ref={ref} className={cn("ob-menu-separator", className)} />; });
DropdownMenuSeparator.displayName = "DropdownMenuSeparator";
export type DropdownMenuRadioGroupProps = { value?: string; onValueChange?: (value: string) => void; children: ReactNode };
export function DropdownMenuRadioGroup({ value, onValueChange, children }: DropdownMenuRadioGroupProps) { return <Primitive.RadioGroup value={value} onValueChange={onValueChange}>{children}</Primitive.RadioGroup>; }
export type DropdownMenuRadioItemProps = Omit<DropdownMenuItemProps, "onSelect"> & { value: string };
export const DropdownMenuRadioItem = forwardRef<HTMLDivElement, DropdownMenuRadioItemProps>(function DropdownMenuRadioItem({ className, ...props }, ref) { return <Primitive.RadioItem {...props} ref={ref} className={cn("ob-menu-item", className)} />; });
DropdownMenuRadioItem.displayName = "DropdownMenuRadioItem";
