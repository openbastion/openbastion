import { type ReactNode } from "react";
import { cn } from "../lib/cn";

export type AppPageHeadProps = {
  title: string;
  subtitle?: ReactNode;
  hints?: ReactNode[];
  // The disclosure summary when more than one hint is given. The shell has no translation
  // layer: the application passes the label it wants.
  hintsLabel?: string;
  actions?: ReactNode;
};

export function AppPageHead({ title, subtitle, hints = [], hintsLabel = "Consignations", actions }: AppPageHeadProps) {
  return (
    <header className="ob-page-header">
      <div className="page-heading">
        <h2 tabIndex={-1} data-confirm-focus-fallback>{title}</h2>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </div>
      {subtitle ? <p className="ob-page-subtitle">{subtitle}</p> : null}
      {hints.length > 1 ? (
        <details className="page-hints">
          <summary>{hintsLabel}</summary>
          {hints.map((hint, index) => (
            <p className="ob-hint" key={index}>{hint}</p>
          ))}
        </details>
      ) : (
        hints.map((hint, index) => (
          <p className="ob-hint" key={index}>{hint}</p>
        ))
      )}
    </header>
  );
}

export type AppPageProps = AppPageHeadProps & {
  children?: ReactNode;
  className?: string;
};

// The frame of a signed-in screen: one heading, the actions that belong to it, the hints an
// operator must know before acting, then the screen itself.
export function AppPage({ children, className, ...head }: AppPageProps) {
  return (
    <section className={cn("ob-page", className)}>
      <AppPageHead {...head} />
      {children}
    </section>
  );
}
