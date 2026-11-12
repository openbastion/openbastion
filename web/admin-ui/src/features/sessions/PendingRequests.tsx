import { Page, Session } from "../../shared/api";
import { StatusBadge } from "../../shared/ui/StatusBadge";

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
    <div className="card">
      <div className="card-head">
        <h3>Demandes à décider</h3>
      </div>
      {loading ? <p className="empty" role="status">Chargement des demandes en attente…</p> : null}
      {!loading && pending && pending.items.length === 0 ? <p className="empty">Aucune demande en attente.</p> : null}
      {!loading && pending && pending.items.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Session</th>
                <th>Type</th>
                <th>Demandeur</th>
                <th>Compte</th>
                <th>Justification</th>
                <th>Ticket</th>
                <th>Échéance</th>
                <th />
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
                      {s.breakGlass ? <span className="badge warn">Urgence</span> : <span className="badge">Approbation</span>}
                    </div>
                  </td>
                  <td>{s.requestedBy}</td>
                  <td>{s.privilegedAccountId}</td>
                  <td>{s.justification}</td>
                  <td>{s.ticket ? <code>{s.ticket}</code> : "—"}</td>
                  <td>{s.expiresAt}</td>
                  <td className="actions">
                    <button type="button" aria-label={`Approuver la session ${s.id}`} onClick={() => onApprove(s)}>
                      Approuver
                    </button>
                    <button type="button" className="danger" aria-label={`Refuser la session ${s.id}`} onClick={() => onReject(s)}>
                      Refuser
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {!loading && pending?.truncated ? <p className="card-foot hint">D'autres demandes attendent : décidez celles-ci d'abord.</p> : null}
    </div>
  );
}
