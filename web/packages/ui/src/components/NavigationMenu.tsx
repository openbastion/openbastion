import { forwardRef, type AnchorHTMLAttributes, type HTMLAttributes, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-navigation-menu";
import { cn } from "../lib/cn";

export type NavigationMenuProps = { children: ReactNode; value?: string; defaultValue?: string; onValueChange?: (value: string) => void; dir?: "ltr" | "rtl"; orientation?: "horizontal" | "vertical"; delayDuration?: number; skipDelayDuration?: number; className?: string };
export function NavigationMenu({ children, className, ...props }: NavigationMenuProps) { return <Primitive.Root {...props} className={cn("ob-navigation-menu", className)}>{children}</Primitive.Root>; }
export type NavigationMenuListProps = HTMLAttributes<HTMLUListElement>;
export const NavigationMenuList = forwardRef<HTMLUListElement, NavigationMenuListProps>(function NavigationMenuList({ className, ...props }, ref) { return <Primitive.List {...props} ref={ref} className={cn("ob-navigation-menu-list", className)} />; });
NavigationMenuList.displayName = "NavigationMenuList";
export type NavigationMenuItemProps = HTMLAttributes<HTMLLIElement> & { value?: string };
export const NavigationMenuItem = forwardRef<HTMLLIElement, NavigationMenuItemProps>(function NavigationMenuItem({ className, ...props }, ref) { return <Primitive.Item {...props} ref={ref} className={cn("ob-navigation-menu-item", className)} />; });
NavigationMenuItem.displayName = "NavigationMenuItem";
export type NavigationMenuTriggerProps = HTMLAttributes<HTMLButtonElement>;
export const NavigationMenuTrigger = forwardRef<HTMLButtonElement, NavigationMenuTriggerProps>(function NavigationMenuTrigger({ className, ...props }, ref) { return <Primitive.Trigger {...props} ref={ref} className={cn("ob-navigation-menu-trigger", className)} />; });
NavigationMenuTrigger.displayName = "NavigationMenuTrigger";
export type NavigationMenuContentProps = HTMLAttributes<HTMLDivElement>;
export const NavigationMenuContent = forwardRef<HTMLDivElement, NavigationMenuContentProps>(function NavigationMenuContent({ className, ...props }, ref) { return <Primitive.Content {...props} ref={ref} className={cn("ob-navigation-menu-content", className)} />; });
NavigationMenuContent.displayName = "NavigationMenuContent";
export type NavigationMenuLinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "onSelect"> & { active?: boolean; onSelect?: () => void };
export const NavigationMenuLink = forwardRef<HTMLAnchorElement, NavigationMenuLinkProps>(function NavigationMenuLink({ className, onSelect, ...props }, ref) { return <Primitive.Link {...props} ref={ref} onSelect={onSelect ? () => onSelect() : undefined} className={cn("ob-navigation-menu-link", className)} />; });
NavigationMenuLink.displayName = "NavigationMenuLink";
export function NavigationMenuViewport({ className }: { className?: string }) { return <div className={cn("ob-navigation-menu-viewport", className)}><Primitive.Viewport /></div>; }
