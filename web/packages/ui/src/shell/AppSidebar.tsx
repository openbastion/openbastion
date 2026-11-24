import { forwardRef, type ReactNode } from "react";
import { Sidebar } from "../components/Sidebar";
import { cn } from "../lib/cn";

export type AppSidebarProps = {
  id?: string;
  label?: string;
  collapsed?: boolean;
  // On a narrow viewport the sidebar is a modal dialog; the shell owns the backdrop and the
  // focus trap (incrément 4), the sidebar only exposes the right roles.
  mobileOpen?: boolean;
  // The brand block (AppSidebarBrand) and the workspace/context selector (incrément 4).
  brand?: ReactNode;
  context?: ReactNode;
  // The navigation itself (AppNavigation).
  children: ReactNode;
  footer?: ReactNode;
  userMenu?: ReactNode;
  className?: string;
};

// The sidebar landmark, built on the Sidebar primitive. Slots only: the brand, the context
// selector, the navigation, the console state and the user menu are supplied by the caller.
export const AppSidebar = forwardRef<HTMLElement, AppSidebarProps>(function AppSidebar(
  {
    id = "admin-navigation",
    label = "Navigation principale",
    collapsed = false,
    mobileOpen = false,
    brand,
    context,
    children,
    footer,
    userMenu,
    className,
  },
  ref,
) {
  return (
    <Sidebar
      ref={ref}
      id={id}
      label={label}
      collapsed={collapsed}
      role={mobileOpen ? "dialog" : undefined}
      aria-modal={mobileOpen ? "true" : undefined}
      className={cn("app-sidebar", className)}
    >
      {brand}
      {context}
      {children}
      {footer}
      {userMenu}
    </Sidebar>
  );
});
AppSidebar.displayName = "AppSidebar";
