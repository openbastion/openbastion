import { forwardRef, type HTMLAttributes, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-menubar";
import { cn } from "../lib/cn";

export type MenubarProps = { children: ReactNode; loop?: boolean; dir?: "ltr" | "rtl"; className?: string };
export function Menubar({ children, className, ...props }: MenubarProps) { return <Primitive.Root {...props} className={cn("ob-menubar", className)}>{children}</Primitive.Root>; }
export type MenubarMenuProps = { children: ReactNode };
export function MenubarMenu({ children }: MenubarMenuProps) { return <Primitive.Menu>{children}</Primitive.Menu>; }
export type MenubarTriggerProps = { children: ReactNode; className?: string; disabled?: boolean };
export function MenubarTrigger({ children, className, ...props }: MenubarTriggerProps) { return <Primitive.Trigger {...props} className={cn("ob-menubar-trigger", className)}>{children}</Primitive.Trigger>; }
export type MenubarContentProps = HTMLAttributes<HTMLDivElement> & { align?: "start" | "center" | "end"; sideOffset?: number };
export const MenubarContent = forwardRef<HTMLDivElement, MenubarContentProps>(function MenubarContent({ className, ...props }, ref) { return <Primitive.Portal><Primitive.Content {...props} ref={ref} className={cn("ob-menu-content", className)} /></Primitive.Portal>; });
MenubarContent.displayName = "MenubarContent";
export type MenubarItemProps = HTMLAttributes<HTMLDivElement> & { disabled?: boolean; onSelect?: () => void };
export const MenubarItem = forwardRef<HTMLDivElement, MenubarItemProps>(function MenubarItem({ className, ...props }, ref) { return <Primitive.Item {...props} ref={ref} className={cn("ob-menu-item", className)} />; });
MenubarItem.displayName = "MenubarItem";
export type MenubarSeparatorProps = HTMLAttributes<HTMLDivElement>;
export const MenubarSeparator = forwardRef<HTMLDivElement, MenubarSeparatorProps>(function MenubarSeparator({ className, ...props }, ref) { return <Primitive.Separator {...props} ref={ref} className={cn("ob-menu-separator", className)} />; });
MenubarSeparator.displayName = "MenubarSeparator";
