import { forwardRef, type ReactNode } from "react";
import { cn } from "../lib/cn";

export type AppContentProps = {
  header?: ReactNode;
  // A notice every screen must see (for example capabilities that could not be read). Kept
  // outside the screen so a page cannot hide it.
  banner?: ReactNode;
  children: ReactNode;
  id?: string;
  inert?: boolean;
  className?: string;
};

// The scrolling column of the shell: the header, then the single main landmark every screen
// renders into. The main element is focusable programmatically (-1) so navigation can move the
// focus there without adding a tab stop.
export const AppContent = forwardRef<HTMLElement, AppContentProps>(function AppContent(
  { header, banner, children, id = "main-content", inert = false, className },
  ref,
) {
  return (
    <div className={cn("app-content", className)}>
      {header}
      <main ref={ref} id={id} className="app-main" tabIndex={-1} inert={inert}>
        {banner}
        {children}
      </main>
    </div>
  );
});
AppContent.displayName = "AppContent";
