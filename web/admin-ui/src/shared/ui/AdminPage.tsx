import { ReactNode } from "react";

// The frame of every signed-in screen (src/app/styles.css: `.page`, `.page-head`, `.hint`). Hints
// are what an operator must know before acting on the screen, never a tour of it.
export function AdminPage({ title, hints = [], children }: { title: string; hints?: ReactNode[]; children?: ReactNode }) {
  return (
    <section className="page">
      <PageHead title={title} hints={hints} />
      {children}
    </section>
  );
}

export function PageHead({ title, hints = [] }: { title: string; hints?: ReactNode[] }) {
  return (
    <div className="page-head">
      <h2 tabIndex={-1} data-confirm-focus-fallback>{title}</h2>
      {hints.map((hint, i) => (
        <p className="hint" key={i}>
          {hint}
        </p>
      ))}
    </div>
  );
}
