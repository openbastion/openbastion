import { ReactNode } from "react";
import { useAppTranslation } from "../i18n";

// The indicator card of the reference screens (Accès privilégiés, Audit & conformité): a label,
// one figure and one line saying what the figure covers. A figure the public API cannot produce
// is shown as an em dash with the reason, never as a plausible number.
export function ReferenceMetric({
  label,
  value,
  detail,
  loading = false,
  tone = "default",
  size = "default",
}: {
  label: string;
  value?: number | string;
  detail: ReactNode;
  loading?: boolean;
  tone?: "default" | "accent";
  size?: "default" | "compact";
}) {
  const { t } = useAppTranslation();
  const missing = !loading && (value === undefined || value === "");
  return (
    <article className={`reference-metric reference-metric--${size}` + (tone === "accent" ? " reference-metric--accent" : "")}>
      <p className="reference-metric-label">{label}</p>
      {loading ? (
        <p className="reference-metric-value" role="status">…</p>
      ) : (
        <p className={"reference-metric-value" + (missing ? " is-unavailable" : "")}>{missing ? "—" : value}</p>
      )}
      <p className="reference-metric-detail" title={missing ? t("common.noApiContract") : undefined}>{detail}</p>
    </article>
  );
}
