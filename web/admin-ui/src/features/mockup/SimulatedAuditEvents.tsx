import { useAppTranslation } from "../../shared/i18n";
import { simulatedAuditEvents } from "./simulatedData";
import { SimulatedBadge } from "./SimulatedBadge";

// Structured audit events as the mockup shows them: event type, UTC timestamp, actor · target ·
// result, details. The public API has no audit read route (ADR-0142).
export function SimulatedAuditEvents() {
  const { t } = useAppTranslation();
  return (
    <section className="simulated-panel" aria-labelledby="simulated-audit-title">
      <header className="simulated-panel-heading">
        <h3 id="simulated-audit-title">{t("simulated.audit.title")}</h3>
        <SimulatedBadge />
      </header>
      <p className="simulated-panel-note">{t("simulated.audit.note")}</p>
      <ul className="simulated-event-list">
        {simulatedAuditEvents.map((event) => (
          <li key={event.id} className="simulated-event">
            <div className="simulated-event-top">
              <code>{event.eventType}</code>
              <time dateTime={event.timestamp}>{event.timestamp}</time>
            </div>
            <p>
              {t("simulated.audit.actor")}: {event.actor} · {t("simulated.audit.target")}: {event.target} · {t("simulated.audit.outcome")}: {t(`simulated.audit.outcomes.${event.outcome}`)}
            </p>
            <p className="simulated-event-details">{JSON.stringify(event.details)}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
