import { ReactNode } from "react";

// The frame of every signed-in screen (src/app/styles.css: `.page`, `.page-head`, `.hint`). Hints
// are what an operator must know before acting on the screen, never a tour of it.
export function AdminPage({
  title,
  hints = [],
  actions,
  children,
}: {
  title: string;
  hints?: ReactNode[];
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section className="ob-page">
      <PageHead title={title} hints={hints} actions={actions} />
      {children}
    </section>
  );
}

// A screen with several consignations keeps them one gesture away instead of pushing the data it
// exists to show below the fold: one hint stays visible, three become a disclosure.
export function PageHead({
  title,
  hints = [],
  actions,
}: {
  title: string;
  hints?: ReactNode[];
  actions?: ReactNode;
}) {
  return (
    <header className="ob-page-header">
      <div className="page-heading">
        <h2 tabIndex={-1} data-confirm-focus-fallback>{title}</h2>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </div>
      {hints.length > 1 ? (
        <details className="page-hints">
          <summary>À savoir avant d’agir ({hints.length})</summary>
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
