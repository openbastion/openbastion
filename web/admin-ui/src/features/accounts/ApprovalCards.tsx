import { Button } from "../../shared/ui/Button";
import { Session } from "../../shared/api";
import { useAppTranslation } from "../../shared/i18n";

// "Il y a 12 min": a request waits for a person, so the age of the request is what matters, not
// the absolute timestamp. A date the browser cannot parse is shown as is.
export function relativeTime(value: string | undefined, locale: string, now: number): string {
  if (!value) return "—";
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return "—";
  const minutes = Math.round((time - now) / 60_000);
  const format = new Intl.RelativeTimeFormat(locale, { numeric: "auto", style: "short" });
  if (Math.abs(minutes) < 60) return format.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return format.format(hours, "hour");
  return format.format(Math.round(hours / 24), "day");
}

// The pending approval requests this caller may decide, as the reference screen shows them: who
// asks, for which account, why, and how long the request has been waiting. Deciding happens on
// the Sessions screen, where the Broker's approve and reject routes live.
export function ApprovalCards({ sessions, onOpen }: { sessions: Session[]; onOpen: () => void }) {
  const { t, i18n } = useAppTranslation();
  const now = Date.now();
  return (
    <ul className="approval-cards">
      {sessions.map((session) => (
        <li key={session.id}>
          <article className="approval-card">
            <header>
              <strong>{session.requestedBy}</strong>
              <span className="approval-card-time">
                {relativeTime(session.createdAt, i18n.language, now)}
              </span>
            </header>
            <code className="approval-card-account">{session.privilegedAccountId}</code>
            <p className="approval-card-reason">{session.justification || t("accounts.approvals.noReason")}</p>
            <Button variant="ghost" className="reference-link" onClick={onOpen}>
              {t("accounts.approvals.open")} <span aria-hidden="true">→</span>
            </Button>
          </article>
        </li>
      ))}
    </ul>
  );
}
