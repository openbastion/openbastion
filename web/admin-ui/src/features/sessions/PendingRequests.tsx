import { useMemo, useState } from "react";
import { Page, Session } from "../../shared/api";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Badge } from "../../shared/ui/Badge";
import { Button } from "../../shared/ui/Button";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { useAppTranslation } from "../../shared/i18n";
import { Input, Label } from "@openbastion/ui";

// The requests waiting for this user's decision — break-glass (ADR-0012) and approval (ADR-0067).
// Search is deliberately local to the bounded page returned by the Broker; the table never
// claims to search requests the caller cannot decide or records outside that page.
export function PendingRequests({
  pending,
  loading = false,
  onApprove,
  onReject,
  currentUserId,
}: {
  pending?: Page<Session>;
  loading?: boolean;
  currentUserId?: string;
  onApprove: (s: Session) => void;
  onReject: (s: Session) => void;
}) {
  const { t, i18n } = useAppTranslation();
  const [query, setQuery] = useState("");
  const visibleItems = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase(i18n.language);
    if (!needle) return pending?.items ?? [];
    return (pending?.items ?? []).filter((session) =>
      [session.id, session.requestedBy, session.privilegedAccountId, session.justification, session.ticket ?? ""]
        .some((value) => value.toLocaleLowerCase(i18n.language).includes(needle)),
    );
  }, [i18n.language, pending, query]);
  const dateTime = (value?: string) => value
    ? new Intl.DateTimeFormat(i18n.language, { dateStyle: "short", timeStyle: "short" }).format(new Date(value))
    : "—";

  return (
    <section className="ob-surface ob-panel pending-requests" aria-labelledby="pending-requests-title">
      <div className="ob-section-heading">
        <h3 id="pending-requests-title">{t("sessions.pending.title")}</h3>
      </div>
      {loading ? <p className="ob-empty-state" role="status">{t("sessions.pending.loading")}</p> : null}
      {!loading && pending && pending.items.length === 0 ? <p className="ob-empty-state">{t("sessions.pending.empty")}</p> : null}
      {!loading && pending && pending.items.length > 0 ? (
        <>
          <div className="reference-table-toolbar">
            <Label className="reference-search">
              <Input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                aria-label={t("sessions.pending.searchAria")}
                placeholder={t("sessions.pending.searchPlaceholder")}
              />
            </Label>
            <p className="reference-table-range" aria-live="polite">
              {t("sessions.pending.scope", { shown: visibleItems.length, total: pending.items.length })}
            </p>
          </div>
          {visibleItems.length === 0 ? <p className="ob-empty-state">{t("sessions.pending.noMatch")}</p> : null}
          {visibleItems.length > 0 ? (
            <div className="ob-table-wrap">
              <table className="ob-data-table">
                <caption className="ob-visually-hidden">{t("sessions.pending.caption")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("sessions.columns.session")}</th>
                    <th scope="col">{t("sessions.columns.type")}</th>
                    <th scope="col">{t("sessions.columns.requester")}</th>
                    <th scope="col">{t("sessions.columns.account")}</th>
                    <th scope="col">{t("sessions.columns.started")}</th>
                    <th scope="col">{t("sessions.columns.justification")}</th>
                    <th scope="col">{t("sessions.columns.ticket")}</th>
                    <th scope="col">{t("sessions.columns.expires")}</th>
                    <th scope="col">{t("sessions.columns.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleItems.map((session) => {
                    const ownRequest = Boolean(currentUserId && session.requestedBy === currentUserId);
                    return (
                      <tr key={session.id}>
                        <td><code>{session.id}</code></td>
                        <td>
                          <div className="request-kind">
                            <StatusBadge status={session.status} />
                            {session.breakGlass
                              ? <Badge tone="warning">{t("sessions.pending.emergency")}</Badge>
                              : <Badge>{t("sessions.pending.approval")}</Badge>}
                          </div>
                        </td>
                        <td>{session.requestedBy}</td>
                        <td>{session.privilegedAccountId}</td>
                        <td>{dateTime(session.createdAt)}</td>
                        <td>{session.justification}</td>
                        <td>{session.ticket ? <code>{session.ticket}</code> : "—"}</td>
                        <td>{dateTime(session.expiresAt)}</td>
                        <td className="ob-table-actions">
                          {ownRequest ? <InlineNotice tone="warning">{t("sessions.pending.ownRequest")}</InlineNotice> : (
                            <div>
                              <Button aria-label={t("sessions.pending.approveAria", { id: session.id })} onClick={() => onApprove(session)}>
                                {t("sessions.pending.approve")}
                              </Button>
                              <Button variant="danger" aria-label={t("sessions.pending.rejectAria", { id: session.id })} onClick={() => onReject(session)}>
                                {t("sessions.pending.reject")}
                              </Button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </>
      ) : null}
      {!loading && pending?.truncated ? <InlineNotice tone="warning">{t("sessions.pending.truncated")}</InlineNotice> : null}
    </section>
  );
}
