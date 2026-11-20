import { useState } from "react";
import { FormField, Select } from "@openbastion/ui";
import { ScreenChannel, ScreenChoice, ScreenColorDepth, Session } from "../../shared/api";
import { Button } from "../../shared/ui/Button";
import { useAppTranslation } from "../../shared/i18n";
import { SecretInjection } from "./SecretInjection";
import { GatedButton } from "../../shared/ui/GatedButton";
import { useSignedIn } from "../../shared/session";

// The attached screen of the session being looked at: each connection is another attach, and the
// key restarts the viewer on the new one.
export interface AttachedScreen {
  sessionId: string;
  attach: string;
  key: number;
  // The screen it was opened with (ADR-0132), asked again on a reconnection.
  choice?: ScreenChoice;
}

// One session, as its identifier returns it: what it is, what it carries, and what its status
// allows — opening a graphical screen (ADR-0071), typing the session-bound Vault secret (ADR-0097),
// or terminating the session.
export function SessionDetail({
  session,
  onOpenScreen,
  onTerminate,
}: {
  session: Session;
  onOpenScreen: (sessionId: string, choice?: ScreenChoice) => void;
  onTerminate: (session: Session) => void;
}) {
  const { t, i18n } = useAppTranslation();
  const { who } = useSignedIn();
  // The Broker gives the screen to the requester only (POST /connect), and lets the requester end
  // their own session without a policy (ADR-0017); anyone else needs session-terminate.
  const isRequester = Boolean(who?.sub) && who?.sub === session.requestedBy;
  const unknownCaller = !who?.sub;
  // The operator's screen choice for an RDP session (ADR-0132). The page does not know the
  // account's profile — an operator may not read the account — so "Account default" sends nothing
  // and the Broker refuses, with 403, a choice the profile does not allow.
  const [channel, setChannel] = useState<ScreenChannel | "">("");
  const [colorDepth, setColorDepth] = useState<ScreenColorDepth | 0>(0);
  const mayOpen = isRequester || unknownCaller;
  return (
    <>
      <dl className="ob-detail-list" aria-label={t("sessions.detail.aria")}>
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
        <>
          <SecretInjection session={session} />
          {session.protocol === "rdp" && mayOpen ? (
            <fieldset className="screen-choice" aria-describedby={`screen-choice-hint-${session.id}`}>
              <legend>{t("screen.choice.label")}</legend>
              <FormField id={`screen-choice-channel-${session.id}`} label={t("screen.choice.channel")}>
                <Select value={channel} onChange={(e) => setChannel(e.target.value as ScreenChannel | "")}>
                  <option value="">{t("screen.choice.accountDefault")}</option>
                  <option value="graphics">{t("screen.channel.graphics")}</option>
                  <option value="bitmap">{t("screen.channel.bitmap")}</option>
                </Select>
              </FormField>
              <FormField id={`screen-choice-depth-${session.id}`} label={t("screen.choice.colorDepth")}>
                <Select value={String(colorDepth)} onChange={(e) => setColorDepth(Number(e.target.value) as ScreenColorDepth | 0)}>
                  <option value="0">{t("screen.choice.accountDefault")}</option>
                  <option value="16">{t("screen.depth.d16")}</option>
                  <option value="32">{t("screen.depth.d32")}</option>
                </Select>
              </FormField>
              <p className="ob-hint" id={`screen-choice-hint-${session.id}`}>{t("screen.choice.hint")}</p>
            </fieldset>
          ) : null}
          <div className="ob-form-actions">
            {session.protocol === "vnc" || session.protocol === "rdp" ? (
              <span title={mayOpen ? undefined : t("sessions.detail.screenRequesterOnly")}>
                <Button
                  variant="primary"
                  disabled={!mayOpen}
                  onClick={() => onOpenScreen(session.id, session.protocol === "rdp" ? screenChoice(channel, colorDepth) : undefined)}
                >
                  {t("sessions.detail.openScreen")}
                </Button>
              </span>
            ) : null}
            <GatedButton capability="sessions.terminate" extraAllowed={isRequester} variant="danger" onClick={() => onTerminate(session)}>
              {t("sessions.detail.terminate")}
            </GatedButton>
          </div>
        </>
      ) : null}
    </>
  );
}

// The choice as the Gateway takes it: only what was chosen, nothing for "Account default".
export function screenChoice(channel: ScreenChannel | "", colorDepth: ScreenColorDepth | 0): ScreenChoice | undefined {
  const choice: ScreenChoice = {};
  if (channel) choice.channel = channel;
  if (colorDepth) choice.colorDepth = colorDepth;
  return choice.channel || choice.colorDepth ? choice : undefined;
}
