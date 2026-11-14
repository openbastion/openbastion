import { Page, Session } from "../../shared/api";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Badge } from "../../shared/ui/Badge";
import { Button } from "../../shared/ui/Button";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { useAppTranslation } from "../../shared/i18n";

// The requests waiting for this user's decision — break-glass (ADR-0012) and approval (ADR-0067).
// The screen owns the call and the notice; the table only says which request each button names.
export function PendingRequests({
  pending,
  loading = false,
  onApprove,
  onReject,
}: {
  pending?: Page<Session>;
  loading?: boolean;
  onApprove: (s: Session) => void;
  onReject: (s: Session) => void;
}) {
  const { t } = useAppTranslation();
  return (
    <section className="ob-surface ob-panel pending-requests" aria-labelledby="pending-requests-title">
      <div className="ob-section-heading">
        <h3 id="pending-requests-title">{t("sessions.pending.title")}</h3>
      </div>
      {loading ? <p className="ob-empty-state" role="status">{t("sessions.pending.loading")}</p> : null}
      {!loading && pending && pending.items.length === 0 ? <p className="ob-empty-state">{t("sessions.pending.empty")}</p> : null}
      {!loading && pending && pending.items.length > 0 ? (
        <div className="ob-table-wrap">
          <table className="ob-data-table">
            <caption className="ob-visually-hidden">{t("sessions.pending.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("sessions.columns.session")}</th>
                <th scope="col">{t("sessions.columns.type")}</th>
                <th scope="col">{t("sessions.columns.requester")}</th>
                <th scope="col">{t("sessions.columns.account")}</th>
                <th scope="col">{t("sessions.columns.justification")}</th>
                <th scope="col">{t("sessions.columns.ticket")}</th>
                <th scope="col">{t("sessions.columns.expires")}</th>
                <th scope="col">{t("sessions.columns.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {pending.items.map((s) => (
                <tr key={s.id}>
                  <td>
                    <code>{s.id}</code>
                  </td>
                  <td>
                    <div className="request-kind">
                      <StatusBadge status={s.status} />
                      {s.breakGlass ? <Badge tone="warning">{t("sessions.pending.emergency")}</Badge> : <Badge>{t("sessions.pending.approval")}</Badge>}
                    </div>
                  </td>
                  <td>{s.requestedBy}</td>
                  <td>{s.privilegedAccountId}</td>
                  <td>{s.justification}</td>
                  <td>{s.ticket ? <code>{s.ticket}</code> : "—"}</td>
                  <td>{s.expiresAt}</td>
                  <td className="ob-table-actions">
                    <div>
                      <Button aria-label={t("sessions.pending.approveAria", { id: s.id })} onClick={() => onApprove(s)}>
                        {t("sessions.pending.approve")}
                      </Button>
                      <Button variant="danger" aria-label={t("sessions.pending.rejectAria", { id: s.id })} onClick={() => onReject(s)}>
                        {t("sessions.pending.reject")}
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {!loading && pending?.truncated ? <InlineNotice tone="warning">{t("sessions.pending.truncated")}</InlineNotice> : null}
    </section>
  );
}
