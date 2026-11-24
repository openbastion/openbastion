import { type ReactNode } from "react";
import { cn } from "../lib/cn";

export type AppHeaderProps = {
  breadcrumbs?: ReactNode;
  // The command/search trigger. The header only places it: opening a palette is an interaction
  // the application owns (ADR-0137 §8, incrément 4).
  search?: ReactNode;
  // Contents of the trailing action cluster (environment badge, notifications, help, mobile
  // navigation toggle), in the order the application chooses.
  actions?: ReactNode;
  children?: ReactNode;
  inert?: boolean;
  className?: string;
};

export function AppHeader({ breadcrumbs, search, actions, children, inert = false, className }: AppHeaderProps) {
  return (
    <header className={cn("app-header", className)} inert={inert}>
      {breadcrumbs}
      {search}
      {actions ? <div className="header-actions">{actions}</div> : null}
      {children}
    </header>
  );
}
