import { Page, Session } from "../../shared/api";

// The requests waiting for this user's decision — break-glass (ADR-0012) and approval (ADR-0067).
// The screen owns the call and the notice; the table only says which request each button names.
export function PendingRequests({
  pending,
  onApprove,
  onReject,
}: {
  pending?: Page<Session>;
  onApprove: (s: Session) => void;
  onReject: (s: Session) => void;
}) {
  return (
    <div className="card">
      <div className="card-head">
        <h3>Demandes à décider</h3>
      </div>
      {pending && pending.items.length === 0 ? <p className="empty">Aucune demande en attente.</p> : null}
      {pending && pending.items.length > 0 ? (
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
                  <td>{s.breakGlass ? <span className="badge warn">urgence</span> : <span className="badge">approbation</span>}</td>
                  <td>{s.requestedBy}</td>
                  <td>{s.privilegedAccountId}</td>
                  <td>{s.justification}</td>
                  <td>{s.ticket ? <code>{s.ticket}</code> : "—"}</td>
                  <td>{s.expiresAt}</td>
                  <td className="actions">
                    <button type="button" onClick={() => onApprove(s)}>
                      Approuver
                    </button>
                    <button type="button" className="danger" onClick={() => onReject(s)}>
                      Refuser
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {pending?.truncated ? <p className="card-foot hint">D'autres demandes attendent : décidez celles-ci d'abord.</p> : null}
    </div>
  );
}
