import { Session } from "../../shared/api";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Button } from "../../shared/ui/Button";
import { useAppTranslation } from "../../shared/i18n";

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
  const { t, i18n } = useAppTranslation();
  return (
    <>
      <dl className="ob-detail-list" aria-label={t("sessions.detail.aria")}>
        <dt>{t("sessions.columns.status")}</dt>
        <dd>
          <StatusBadge status={session.status} />
        </dd>
        <dt>{t("sessions.columns.protocol")}</dt>
        <dd>{session.protocol}</dd>
        <dt>{t("sessions.columns.requester")}</dt>
        <dd>{session.requestedBy}</dd>
        <dt>{t("sessions.columns.account")}</dt>
        <dd>{session.privilegedAccountId}</dd>
        <dt>{t("sessions.columns.justification")}</dt>
        <dd>{session.justification}</dd>
        <dt>{t("sessions.detail.end")}</dt>
        <dd>{session.expiresAt}</dd>
        {session.ticket ? (
          <>
            <dt>{t("sessions.columns.ticket")}</dt>
            <dd>
              <code>{session.ticket}</code>
            </dd>
          </>
        ) : null}
        {session.decidedAt ? (
          <>
            <dt>{t("sessions.detail.decidedAt")}</dt>
            <dd><time dateTime={session.decidedAt}>{new Date(session.decidedAt).toLocaleString(i18n.language)}</time></dd>
          </>
        ) : null}
        {session.approvalRequired ? (
          <>
            <dt>{t("sessions.detail.approval")}</dt>
            <dd>{session.decidedBy ? t("sessions.detail.decidedBy", { who: session.decidedBy }) : t("sessions.detail.pending")}</dd>
          </>
        ) : null}
        {session.breakGlass ? (
          <>
            <dt>{t("sessions.detail.emergency")}</dt>
            <dd>{session.decidedBy ? t("sessions.detail.emergencyDecidedBy", { who: session.decidedBy }) : t("sessions.detail.emergencyYes")}</dd>
          </>
        ) : null}
      </dl>
      {session.status === "active" ? (
        <div className="ob-form-actions">
          {session.protocol === "vnc" || session.protocol === "rdp" ? (
            <Button variant="primary" onClick={() => onOpenScreen(session.id)}>
              {t("sessions.detail.openScreen")}
            </Button>
          ) : null}
          <Button variant="danger" onClick={() => onTerminate(session)}>
            {t("sessions.detail.terminate")}
          </Button>
        </div>
      ) : null}
    </>
  );
}
