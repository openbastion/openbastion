import { ReactNode } from "react";

// The cards of the reference screens that pair a capability list with a side panel
// (docs/ui/reference-screens/openbastion-parametres*.svg, openbastion-infrastructure.svg):
// one 12px rounded surface, a title, one sentence saying what it covers, then its rows.
export function ReferenceCard({
  title,
  subtitle,
  badge,
  footer,
  tone = "surface",
  className,
  // The reference has one card without a visible title (the note in Sécurité): keep its name for
  // assistive technology without adding a heading the mockup does not show.
  hideTitle = false,
  children,
}: {
  title: string;
  subtitle?: ReactNode;
  badge?: ReactNode;
  footer?: ReactNode;
  tone?: "surface" | "chrome" | "accent";
  className?: string;
  hideTitle?: boolean;
  children?: ReactNode;
}) {
  return (
    <section className={`reference-card reference-card--${tone}` + (className ? ` ${className}` : "")} aria-label={title}>
      <header className="reference-card-head">
        <div className="reference-card-heading">
          <h3 className={hideTitle ? "ob-visually-hidden" : undefined}>{title}</h3>
          {subtitle ? <p className="reference-card-subtitle">{subtitle}</p> : null}
        </div>
        {badge}
      </header>
      {children ? <div className="reference-card-rows">{children}</div> : null}
      {footer ? <p className="reference-card-foot">{footer}</p> : null}
    </section>
  );
}

// A row of a reference card: a round mark, a title, one line of detail, and the state on the
// right. Every capability list of the settings and infrastructure screens has this shape.
export function ReferenceRow({
  mark,
  title,
  description,
  badge,
  children,
}: {
  mark?: ReactNode;
  title: string;
  description?: ReactNode;
  badge?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="reference-row">
      {mark ? <span className="reference-row-mark" aria-hidden="true">{mark}</span> : null}
      <div className="reference-row-copy">
        <p className="reference-row-title">{title}</p>
        {description ? <p className="reference-row-description">{description}</p> : null}
        {children}
      </div>
      {badge}
    </div>
  );
}

// The state pill of those rows (PAR RÔLE, SUPPORTÉ, INTÉGRÉ, ACTIF, REQUIS, LIVRÉ, DISPONIBLE).
// `quiet` is for a state the public API cannot confirm: the pill keeps its place, the label says
// what is unknown instead of claiming a capability.
export function ReferenceState({
  tone = "accent",
  children,
}: {
  tone?: "accent" | "success" | "quiet" | "chrome";
  children: ReactNode;
}) {
  return <span className={`reference-state reference-state--${tone}`}>{children}</span>;
}

// A label/value pair of the side panels (Votre instance, État de sécurité, Architecture des
// échanges). The value is an em dash when no public contract produces it.
export function ReferenceFacts({ stacked = false, className, children }: { stacked?: boolean; className?: string; children: ReactNode }) {
  return <dl className={"reference-facts" + (stacked ? " reference-facts--stacked" : "") + (className ? ` ${className}` : "")}>{children}</dl>;
}

export function ReferenceFact({ label, value, unavailable }: { label: string; value: ReactNode; unavailable?: boolean }) {
  return (
    <div className="reference-fact">
      <dt>{label}</dt>
      <dd className={unavailable ? "is-unavailable" : undefined}>{value}</dd>
    </div>
  );
}

// A switch drawn in its reference position. Nothing here is a control: the value it shows is
// declared at deployment, so the screen exposes no state to toggle (no public write route).
export function ReferenceSwitch({ checked, label }: { checked: boolean; label: string }) {
  return (
    <span className="reference-switch" data-checked={checked ? "true" : "false"} role="img" aria-label={label}>
      <span className="reference-switch-knob" aria-hidden="true" />
    </span>
  );
}
