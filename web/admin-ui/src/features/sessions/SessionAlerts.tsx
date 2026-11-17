import { Badge } from "../../shared/ui/Badge";
import { useAppTranslation } from "../../shared/i18n";

// Deliberately no API call: the public Gateway contract has no session-alert resource or
// acknowledgement lifecycle. Audit events are evidence, not an alert queue or anomaly verdict.
export function SessionAlerts() {
  const { t } = useAppTranslation();
  return (
    <section className="session-alerts-unavailable ob-surface" aria-labelledby="session-alerts-title">
      <div className="ob-section-heading">
        <h3 id="session-alerts-title">{t("sessions.alerts.title")}</h3>
        <Badge tone="warning">{t("sessions.alerts.badge")}</Badge>
      </div>
      <p>{t("sessions.alerts.description")}</p>
      <p className="ob-hint">{t("sessions.alerts.auditNote")}</p>
    </section>
  );
}
