import { Badge } from "../../shared/ui/Badge";
import { useAppTranslation } from "../../shared/i18n";

// Deliberately no API call: the public Gateway contract has no session-alert resource or
// acknowledgement lifecycle. Audit events are evidence, not an alert queue or anomaly verdict.
// The panel keeps the reference screen's place (docs/ui/reference-screens/openbastion-sessions-alertes.svg)
// and states the missing contract instead of inventing a queue, counters or handling actions.
export function SessionAlerts() {
  const { t } = useAppTranslation();
  return (
    <section className="ob-surface reference-panel session-alerts" aria-labelledby="session-alerts-title">
      <div className="reference-panel-heading">
        <div>
          <h3 id="session-alerts-title">{t("sessions.alerts.recentTitle")}</h3>
          <p>{t("sessions.alerts.description")}</p>
        </div>
        <Badge tone="warning" className="reference-pill">{t("sessions.alerts.badge")}</Badge>
      </div>
      <div className="reference-unavailable">
        <h3>{t("sessions.alerts.fileUnavailable")}</h3>
        <p className="ob-hint">{t("sessions.alerts.auditNote")}</p>
      </div>
    </section>
  );
}
