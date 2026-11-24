import { type ReactNode } from "react";
import { cn } from "../lib/cn";
import { AppContent } from "./AppContent";

export type AppShellProps = {
  sidebar: ReactNode;
  header?: ReactNode;
  // A notice every screen must see, kept outside the screen (see AppContent).
  banner?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  collapsed?: boolean;
  mobileOpen?: boolean;
  onMobileClose?: () => void;
  // The "skip to content" link, in the application's language.
  skipLink?: ReactNode;
  mainId?: string;
  className?: string;
};

// The workspace grid: the sidebar landmark, the scrolling content column and the footer. It
// renders structure only — no router, no translation, no application state (ADR-0137 §8). The
// application owns every interaction and passes the slots already wired.
export function AppShell({
  sidebar,
  header,
  banner,
  footer,
  children,
  collapsed = false,
  mobileOpen = false,
  onMobileClose,
  skipLink,
  mainId = "main-content",
  className,
}: AppShellProps) {
  return (
    <>
      {skipLink}
      <div
        className={cn(
          "app-workspace",
          collapsed && "sidebar-collapsed",
          mobileOpen && "mobile-navigation-open",
          className,
        )}
      >
        {mobileOpen ? (
          <button
            type="button"
            className="navigation-backdrop"
            aria-hidden="true"
            tabIndex={-1}
            onClick={onMobileClose}
          />
        ) : null}
        {sidebar}
        <AppContent header={header} banner={banner} id={mainId} inert={mobileOpen}>
          {children}
        </AppContent>
        {footer}
      </div>
    </>
  );
}
