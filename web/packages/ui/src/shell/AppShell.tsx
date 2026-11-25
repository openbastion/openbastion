import { type ReactNode, type Ref } from "react";
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
  // The focusable main landmark, for an application that moves the focus there after a navigation.
  mainRef?: Ref<HTMLElement>;
  // Replaces the default backdrop when the application mounts its own modal behaviour
  // (AppMobileNavigation renders the backdrop itself, and must stay mounted while closed).
  mobileBehavior?: ReactNode;
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
  mainRef,
  mobileBehavior,
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
        {mobileBehavior ?? (mobileOpen ? (
          <button
            type="button"
            className="navigation-backdrop"
            aria-hidden="true"
            tabIndex={-1}
            onClick={onMobileClose}
          />
        ) : null)}
        {sidebar}
        <AppContent ref={mainRef} header={header} banner={banner} id={mainId} inert={mobileOpen}>
          {children}
        </AppContent>
        {footer}
      </div>
    </>
  );
}
