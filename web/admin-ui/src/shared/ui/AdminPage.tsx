import { ReactNode } from "react";
import { useAppTranslation } from "../i18n";

// The frame of every signed-in screen (@openbastion/design-tokens/styles.css: `.page`, `.page-head`, `.hint`). Hints
// are what an operator must know before acting on the screen, never a tour of it.
export function AdminPage({
  title,
  subtitle,
  hints = [],
  actions,
  children,
}: {
  title: string;
  // The reference screens put one sentence under the title: what the screen is, in the product's
  // own words. It replaces nothing else — the hints below stay what an operator must know.
  subtitle?: ReactNode;
  hints?: ReactNode[];
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section className="ob-page">
      <PageHead title={title} subtitle={subtitle} hints={hints} actions={actions} />
      {children}
    </section>
  );
}

// A screen with several consignations keeps them one gesture away instead of pushing the data it
// exists to show below the fold: one hint stays visible, three become a disclosure.
export function PageHead({
  title,
  subtitle,
  hints = [],
  actions,
}: {
  title: string;
  subtitle?: ReactNode;
  hints?: ReactNode[];
  actions?: ReactNode;
}) {
  const { t } = useAppTranslation();
  return (
    <header className="ob-page-header">
      <div className="page-heading">
        <h2 tabIndex={-1} data-confirm-focus-fallback>{title}</h2>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </div>
      {subtitle ? <p className="ob-page-subtitle">{subtitle}</p> : null}
      {hints.length > 1 ? (
        <details className="page-hints">
          <summary>{t("common.hints", { count: hints.length })}</summary>
          {hints.map((hint, i) => (
            <p className="ob-hint" key={i}>
              {hint}
            </p>
          ))}
        </details>
      ) : (
        hints.map((hint, i) => (
          <p className="ob-hint" key={i}>
            {hint}
          </p>
        ))
      )}
    </header>
  );
}
