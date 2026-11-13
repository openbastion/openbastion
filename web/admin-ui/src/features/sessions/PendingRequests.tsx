import { Page, Session } from "../../shared/api";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Badge } from "../../shared/ui/Badge";
import { Button } from "../../shared/ui/Button";
import { InlineNotice } from "../../shared/ui/InlineNotice";

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
  return (
    <section className="ob-surface ob-panel pending-requests" aria-labelledby="pending-requests-title">
      <div className="ob-section-heading">
        <h3 id="pending-requests-title">Demandes à décider</h3>
      </div>
      {loading ? <p className="ob-empty-state" role="status">Chargement des demandes en attente…</p> : null}
      {!loading && pending && pending.items.length === 0 ? <p className="ob-empty-state">Aucune demande en attente.</p> : null}
      {!loading && pending && pending.items.length > 0 ? (
        <div className="ob-table-wrap">
          <table className="ob-data-table">
            <caption className="ob-visually-hidden">Demandes de sessions privilégiées en attente de décision</caption>
            <thead>
              <tr>
                <th scope="col">Session</th>
                <th scope="col">Type</th>
                <th scope="col">Demandeur</th>
                <th scope="col">Compte</th>
                <th scope="col">Justification</th>
                <th scope="col">Ticket</th>
                <th scope="col">Échéance</th>
                <th scope="col">Actions</th>
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
                      {s.breakGlass ? <Badge tone="warning">Urgence</Badge> : <Badge>Approbation</Badge>}
                    </div>
                  </td>
                  <td>{s.requestedBy}</td>
                  <td>{s.privilegedAccountId}</td>
                  <td>{s.justification}</td>
                  <td>{s.ticket ? <code>{s.ticket}</code> : "—"}</td>
                  <td>{s.expiresAt}</td>
                  <td className="ob-table-actions">
                    <div>
                      <Button aria-label={`Approuver la session ${s.id}`} onClick={() => onApprove(s)}>
                        Approuver
                      </Button>
                      <Button variant="danger" aria-label={`Refuser la session ${s.id}`} onClick={() => onReject(s)}>
                        Refuser
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {!loading && pending?.truncated ? <InlineNotice tone="warning">D'autres demandes attendent : décidez celles-ci d'abord.</InlineNotice> : null}
    </section>
  );
}
