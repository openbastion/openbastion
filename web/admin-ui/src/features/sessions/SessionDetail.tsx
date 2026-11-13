import { Session } from "../../shared/api";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Button } from "../../shared/ui/Button";

// The attached screen of the session being looked at: each connection is another attach, and the
// key restarts the viewer on the new one.
export interface AttachedScreen {
  sessionId: string;
  attach: string;
  key: number;
}

// One session, as its identifier returns it: what it is, what it carries, and what its status
// allows — opening the screen of a graphical session (ADR-0071), or terminating it.
export function SessionDetail({
  session,
  onOpenScreen,
  onTerminate,
}: {
  session: Session;
  onOpenScreen: (sessionId: string) => void;
  onTerminate: (session: Session) => void;
}) {
  return (
    <>
      <dl className="ob-detail-list" aria-label="Détails de la session">
        <dt>Statut</dt>
        <dd>
          <StatusBadge status={session.status} />
        </dd>
        <dt>Protocole</dt>
        <dd>{session.protocol}</dd>
        <dt>Demandeur</dt>
        <dd>{session.requestedBy}</dd>
        <dt>Compte</dt>
        <dd>{session.privilegedAccountId}</dd>
        <dt>Justification</dt>
        <dd>{session.justification}</dd>
        <dt>Fin</dt>
        <dd>{session.expiresAt}</dd>
        {session.ticket ? (
          <>
            <dt>Ticket</dt>
            <dd>
              <code>{session.ticket}</code>
            </dd>
          </>
        ) : null}
        {session.decidedAt ? (
          <>
            <dt>Décision le</dt>
            <dd><time dateTime={session.decidedAt}>{new Date(session.decidedAt).toLocaleString("fr-FR")}</time></dd>
          </>
        ) : null}
        {session.approvalRequired ? (
          <>
            <dt>Approbation</dt>
            <dd>{session.decidedBy ? `décidée par ${session.decidedBy}` : "en attente"}</dd>
          </>
        ) : null}
        {session.breakGlass ? (
          <>
            <dt>Urgence</dt>
            <dd>oui{session.decidedBy ? `, décidée par ${session.decidedBy}` : ""}</dd>
          </>
        ) : null}
      </dl>
      {session.status === "active" ? (
        <div className="ob-form-actions">
          {session.protocol === "vnc" || session.protocol === "rdp" ? (
            <Button variant="primary" onClick={() => onOpenScreen(session.id)}>
              Ouvrir l'écran
            </Button>
          ) : null}
          <Button variant="danger" onClick={() => onTerminate(session)}>
            Mettre fin
          </Button>
        </div>
      ) : null}
    </>
  );
}
